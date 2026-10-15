package tuic

import (
	"container/list"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
)

type clientRing struct {
	mu        sync.Mutex
	connectMu sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	ring      *list.List
	current   *list.Element
	newClient func(capabilityCallback func(n int64)) *clientImpl
	reserved  int64
	closed    bool
	state     *common.QUICPoolState
}

type clientRingNode struct {
	cli *clientImpl
	// capability is updated by the QUIC callback and read atomically.
	capability int64
}

func newClientRing(newClient func(capabilityCallback func(n int64)) *clientImpl, reserved int64) *clientRing {
	ctx, cancel := context.WithCancel(context.Background())
	return &clientRing{
		ctx: ctx, cancel: cancel,
		ring:      list.New(),
		newClient: newClient,
		reserved:  reserved,
		state:     common.NewQUICPoolState(),
	}
}

func (r *clientRing) DialContext(ctx context.Context, metadata *protocol.Metadata) (conn net.Conn, err error) {
	if r.ctx.Err() != nil {
		return nil, common.ErrClientClosed
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	defer cancel()
	if r.state.Snapshot().State != netproxy.SessionConnected {
		return nil, netproxy.ErrNotConnected
	}
	err = r.tryNext(func(node *clientRingNode) error {
		cap := atomic.LoadInt64(&node.capability)
		if cap != -1 && cap <= r.reserved {
			return common.ErrHoldOn
		}
		conn, err = node.cli.DialContext(ctx, metadata)
		return err
	})
	if err != nil && conn != nil {
		_ = conn.Close()
		conn = nil
	}
	return conn, err
}

func (r *clientRing) ListenPacket(ctx context.Context, metadata *protocol.Metadata) (conn net.PacketConn, err error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	defer cancel()
	if r.state.Snapshot().State != netproxy.SessionConnected {
		return nil, netproxy.ErrNotConnected
	}
	err = r.tryNext(func(node *clientRingNode) error {
		cap := atomic.LoadInt64(&node.capability)
		if cap != -1 && cap <= r.reserved {
			return common.ErrHoldOn
		}
		conn, err = node.cli.ListenPacket(ctx, metadata)
		return err
	})
	if err != nil && conn != nil {
		_ = conn.Close()
		conn = nil
	}
	return conn, err
}

// tryNext only allocates from established members. Physical connection work
// belongs to Connect, including expansion after an admission-capacity failure.
func (r *clientRing) tryNext(f func(*clientRingNode) error) error {
	// Only selection touches the ring. Opening a stream may block on peer IO,
	// and must not serialize unrelated allocations or session cleanup.
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return common.ErrClientClosed
	}
	type candidate struct {
		elem *list.Element
		node *clientRingNode
	}
	candidates := make([]candidate, 0, r.ring.Len())
	elem := r.current
	for range r.ring.Len() {
		if elem == nil {
			elem = r.ring.Front()
		}
		candidates = append(candidates, candidate{elem, elem.Value.(*clientRingNode)})
		elem = elem.Next()
	}
	r.mu.Unlock()
	for _, candidate := range candidates {
		if !r.state.IsReady(candidate.node.cli.resource) {
			continue
		}
		err := f(candidate.node)
		if err == nil {
			r.mu.Lock()
			defer r.mu.Unlock()
			// Close or a member failure may finish while allocation is outside
			// the lock. Reject that handoff; the caller releases its new stream.
			if r.closed {
				return common.ErrClientClosed
			}
			if cause := candidate.node.cli.lease.Cause(); cause != nil {
				return cause
			}
			if candidate.elem.Value == candidate.node {
				r.current = candidate.elem
			}
			return nil
		}
		if !common.IsCapacityError(err) && !errors.Is(err, common.ErrClientClosed) {
			return err
		}
	}
	if r.ctx.Err() != nil {
		return common.ErrClientClosed
	}
	r.state.RequestCapacity()
	return netproxy.WrapFailure(common.ErrHoldOn, netproxy.Failure{Scope: netproxy.ScopeOperation, Layer: netproxy.LayerQUIC, Phase: netproxy.OpOpenStream, Reason: netproxy.ReasonCapacity})
}

func (r *clientRing) _insertAfterCurrent(node *clientRingNode) (elem *list.Element) {
	node.cli.resource = r.state.NewResource()
	node.cli.poolState = r.state
	if r.current == nil {
		elem = r.ring.PushBack(node)
		r.current = elem
	} else {
		elem = r.ring.InsertAfter(node, r.current)
	}
	node.cli.setOnClose(func() {
		r.passiveRemove(elem)
	})
	return elem
}

func (r *clientRing) passiveRemove(elem *list.Element) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if elem.Value == nil {
		// Removed.
		return
	}
	r.state.Remove(elem.Value.(*clientRingNode).cli.resource)
	elem.Value = nil
	if r.current == elem {
		r.current = elem.Next()
	}
	r.ring.Remove(elem)
}

func (r *clientRing) Close() error {
	r.cancel() // Interrupt handshakes and in-flight allocations.
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.cancel()
	r.state.Close()
	var clients []*clientImpl
	for elem := r.ring.Front(); elem != nil; elem = elem.Next() {
		if elem.Value != nil {
			clients = append(clients, elem.Value.(*clientRingNode).cli)
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

func (r *clientRing) Snapshot() netproxy.StateEvent { return r.state.Snapshot() }
func (r *clientRing) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return r.state.WatchState(ctx)
}

// Connect establishes or replenishes members under the daemon's recovery
// scheduler. The ring lock is released during handshakes so healthy members
// remain available while a replacement is connecting.
func (r *clientRing) Connect(ctx context.Context, dialer netproxy.Dialer, dialFn common.DialFunc) (err error) {
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
			return common.ErrClientClosed
		}
		snapshot := r.state.Snapshot()
		if snapshot.Accepting && !snapshot.RecoveryRequired {
			r.mu.Unlock()
			return nil
		}
		node := &clientRingNode{capability: -1}
		node.cli = r.newClient(func(n int64) { atomic.StoreInt64(&node.capability, n) })
		elem := r._insertAfterCurrent(node)
		r.current = elem
		r.state.BeginConnect()
		r.mu.Unlock()
		_, err = node.cli.getQuicConn(connectCtx, dialer, dialFn)
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
