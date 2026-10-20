// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/quic-go"
)

// RingMember owns protocol I/O and reports its resource failure independently
// of pool admission. BindPool runs before the member is established or exposed.
type RingMember interface {
	BindPool(*netproxy.PoolState, netproxy.ResourceRef, func())
	ConnectQUIC(context.Context, netproxy.Dialer, DialFunc) (*quic.Conn, error)
	FailureCause() error
	Close() error
}

// ClientRing allocates only from ready members. Connect is the sole owner of
// physical establishment and replenishment; allocations never create clients.
type ClientRing[C RingMember] struct {
	mu        sync.Mutex
	connectMu sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	ring      *list.List
	current   *list.Element
	newClient func(capabilityCallback func(streamType quic.StreamType, n int64)) C
	reserved  int64
	closed    bool
	state     *netproxy.PoolState
}

type clientRingNode[C RingMember] struct {
	cli C
	// capability tracks only bidirectional stream credit, independently of authentication and UDP streams.
	capability atomic.Int64
	resource   netproxy.ResourceRef
}

func NewClientRing[C RingMember](newClient func(capabilityCallback func(streamType quic.StreamType, n int64)) C, reserved int64) *ClientRing[C] {
	ctx, cancel := context.WithCancel(context.Background())
	return &ClientRing[C]{
		ctx: ctx, cancel: cancel,
		ring:      list.New(),
		newClient: newClient,
		reserved:  reserved,
		state:     netproxy.NewPoolState(netproxy.LayerQUIC),
	}
}

// Allocate cancels protocol I/O when the pool closes and rejects a late
// handoff from a terminated member. The caller releases any returned resource
// on error. Only new bidirectional streams need stream reservations.
func (r *ClientRing[C]) Allocate(ctx context.Context, reserveStreams bool, allocate func(context.Context, C) error) error {
	if r.ctx.Err() != nil {
		return ErrClientClosed
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	defer cancel()
	if !r.state.Snapshot().Accepting {
		return netproxy.ErrNotConnected
	}
	return r.tryNext(func(node *clientRingNode[C]) error {
		if capacity := node.capability.Load(); reserveStreams && capacity != -1 && capacity <= r.reserved {
			return ErrHoldOn
		}
		return allocate(ctx, node.cli)
	})
}

// tryNext only allocates from established members. Physical connection work
// belongs to Connect, including expansion after an admission-capacity failure.
func (r *ClientRing[C]) tryNext(f func(*clientRingNode[C]) error) error {
	// Only selection touches the ring. Opening a stream may block on peer IO,
	// and must not serialize unrelated allocations or session cleanup.
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrClientClosed
	}
	type candidate struct {
		elem *list.Element
		node *clientRingNode[C]
	}
	candidates := make([]candidate, 0, r.ring.Len())
	elem := r.current
	for range r.ring.Len() {
		if elem == nil {
			elem = r.ring.Front()
		}
		candidates = append(candidates, candidate{elem, elem.Value.(*clientRingNode[C])})
		elem = elem.Next()
	}
	r.mu.Unlock()
	for _, candidate := range candidates {
		if !r.state.IsReady(candidate.node.resource) {
			continue
		}
		err := f(candidate.node)
		if err == nil {
			r.mu.Lock()
			defer r.mu.Unlock()
			// Close or a member failure may finish while allocation is outside
			// the lock. Reject that handoff; the caller releases its new stream.
			if r.closed {
				return ErrClientClosed
			}
			if cause := candidate.node.cli.FailureCause(); cause != nil {
				return cause
			}
			if candidate.elem.Value == candidate.node {
				r.current = candidate.elem
			}
			return nil
		}
		if !IsCapacityError(err) && !errors.Is(err, ErrClientClosed) {
			return err
		}
	}
	if r.ctx.Err() != nil {
		return ErrClientClosed
	}
	r.state.RequestCapacity(nil)
	return netproxy.WrapFailure(ErrHoldOn, netproxy.Failure{Scope: netproxy.ScopeOperation, Layer: netproxy.LayerQUIC, Phase: netproxy.OpOpenStream, Reason: netproxy.ReasonCapacity})
}

func (r *ClientRing[C]) insertAfterCurrent(node *clientRingNode[C]) (elem *list.Element) {
	node.resource = r.state.NewResource()
	if r.current == nil {
		elem = r.ring.PushBack(node)
		r.current = elem
	} else {
		elem = r.ring.InsertAfter(node, r.current)
	}
	node.cli.BindPool(r.state, node.resource, func() {
		r.passiveRemove(elem)
	})
	return elem
}

func (r *ClientRing[C]) passiveRemove(elem *list.Element) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if elem.Value == nil {
		// Removed.
		return
	}
	r.state.Remove(elem.Value.(*clientRingNode[C]).resource)
	elem.Value = nil
	if r.current == elem {
		r.current = elem.Next()
	}
	r.ring.Remove(elem)
}

func (r *ClientRing[C]) Close() error {
	r.cancel() // Interrupt handshakes and in-flight allocations.
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.cancel()
	r.state.Close()
	var clients []C
	for elem := r.ring.Front(); elem != nil; elem = elem.Next() {
		if elem.Value != nil {
			clients = append(clients, elem.Value.(*clientRingNode[C]).cli)
			elem.Value = nil
		}
	}
	r.ring.Init()
	r.current = nil
	r.mu.Unlock()
	var err error
	for _, client := range clients {
		err = errors.Join(err, client.Close())
	}
	return err
}

func (r *ClientRing[C]) Snapshot() netproxy.StateEvent { return r.state.Snapshot() }
func (r *ClientRing[C]) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return r.state.WatchState(ctx)
}

// Connect establishes or replenishes members under the daemon's recovery
// scheduler. The ring lock is released during handshakes so healthy members
// remain available while a replacement is connecting.
func (r *ClientRing[C]) Connect(ctx context.Context, dialer netproxy.Dialer, dialFn DialFunc) (err error) {
	r.connectMu.Lock()
	defer r.connectMu.Unlock()
	connectCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	defer cancel()
	for {
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return ErrClientClosed
		}
		snapshot := r.state.Snapshot()
		if snapshot.Accepting && !snapshot.RecoveryRequired {
			r.mu.Unlock()
			return nil
		}
		node := &clientRingNode[C]{}
		node.capability.Store(-1)
		node.cli = r.newClient(func(streamType quic.StreamType, n int64) {
			if streamType == quic.StreamTypeBidi {
				node.capability.Store(n)
			}
		})
		elem := r.insertAfterCurrent(node)
		r.current = elem
		r.state.BeginConnect()
		r.mu.Unlock()
		_, err = node.cli.ConnectQUIC(connectCtx, dialer, dialFn)
		if err != nil {
			r.passiveRemove(elem)
			_ = node.cli.Close()
		}
		r.state.EndConnect(err)
		if err != nil {
			return err
		}
	}
}
