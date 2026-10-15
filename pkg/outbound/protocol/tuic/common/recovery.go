package common

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/quic-go"
)

// IsCapacityError describes admission pressure, not a failed QUIC connection.
func IsCapacityError(err error) bool {
	var limit quic.StreamLimitReachedError
	return errors.As(err, &limit) || errors.Is(err, ErrTooManyOpenStreams) || errors.Is(err, ErrHoldOn)
}

// WrapQUICError keeps the original error and the exact resource that produced it.
// A stream reset must never invalidate its parent connection.
func WrapQUICError(err error, ref netproxy.ResourceRef, lease *netproxy.Lease, op netproxy.Operation, fail func(error)) error {
	if err == nil || err == io.EOF && op == netproxy.OpRead {
		return err
	}
	var causes []error
	for _, failure := range netproxy.Failures(err) {
		cause := failure.Cause
		failure.Resource, failure.Phase = ref, op
		if failure.Layer == netproxy.LayerUnknown {
			failure.Layer = netproxy.LayerQUIC
		}
		if lease != nil {
			failure.Stream = lease.Stream()
		}
		// These admission sentinels belong to this pool, beyond QUIC's typed limit.
		if errors.Is(cause, ErrTooManyOpenStreams) || errors.Is(cause, ErrHoldOn) {
			failure.Scope, failure.Reason = netproxy.ScopeOperation, netproxy.ReasonCapacity
		}
		if failure.Origin == netproxy.OriginLocalProtocol && lease != nil && !lease.Valid() {
			if cleanup := netproxy.ClassifyFailure(lease.Cause()); cleanup.Origin == netproxy.OriginLocalCleanup {
				failure.Origin, failure.Reason = netproxy.OriginLocalCleanup, netproxy.ReasonClosed
			}
		}
		wrapped := netproxy.WrapFailure(cause, failure)
		if failure.Scope == netproxy.ScopeSharedResource {
			if fail != nil {
				fail(wrapped)
			}
		} else if failure.Scope == netproxy.ScopeStream && lease != nil {
			lease.Invalidate(wrapped)
		}
		causes = append(causes, wrapped)
	}
	if len(causes) == 1 {
		return causes[0]
	}
	return errors.Join(causes...)
}

// QUICPoolState aggregates independently owned connections. Its stable pool
// identity is distinct from each member identity carried by failure.Cause.
type QUICPoolState struct {
	mu         sync.Mutex
	state      *netproxy.StateBroadcaster
	ref        netproxy.ResourceRef
	members    map[netproxy.ResourceRef]bool
	connecting int
	desired    int
	episode    uint64
	cause      error
	closed     bool
}

func NewQUICPoolState() *QUICPoolState {
	p := &QUICPoolState{state: netproxy.NewStateBroadcaster(netproxy.SessionDisconnected), ref: netproxy.NewResourceRef(), members: make(map[netproxy.ResourceRef]bool), desired: 1}
	p.publish()
	return p
}
func (p *QUICPoolState) NewResource() netproxy.ResourceRef {
	p.mu.Lock()
	defer p.mu.Unlock()
	ref := netproxy.NewResourceRef()
	ref.OwnerID = p.ref.OwnerID
	if !p.closed {
		p.members[ref] = false
	}
	return ref
}
func (p *QUICPoolState) Snapshot() netproxy.StateEvent { return p.state.Snapshot() }
func (p *QUICPoolState) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return p.state.WatchState(ctx)
}
func (p *QUICPoolState) ready() int {
	ready := 0
	for _, usable := range p.members {
		if usable {
			ready++
		}
	}
	return ready
}
func (p *QUICPoolState) publish() {
	ready := p.ready()
	state, phase := netproxy.SessionDisconnected, "queued"
	if p.closed {
		state, phase = netproxy.SessionClosed, "stopped"
	} else if ready > 0 {
		state, phase = netproxy.SessionConnected, "ready"
	} else if p.connecting > 0 {
		state = netproxy.SessionConnecting
	}
	required := !p.closed && ready < p.desired
	if !p.closed && p.connecting > 0 {
		phase = "connecting"
	} else if required {
		phase = "queued"
	}
	p.state.Publish(netproxy.StateEvent{State: state, Cause: p.cause, Resource: p.ref, EpisodeID: p.episode,
		Layer: netproxy.LayerQUIC, Accepting: ready > 0 && !p.closed, UsableCapacity: ready,
		RecoveryRequired: required, RecoveryPhase: phase, RecoveryExecutor: netproxy.RecoveryDaemon})
}
func (p *QUICPoolState) IsReady(ref netproxy.ResourceRef) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closed && p.members[ref]
}

// RequestCapacity coalesces simultaneous admission failures into one extra
// member request. It never starts a timer or bypasses the background executor.
func (p *QUICPoolState) RequestCapacity() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	ready := p.ready()
	if p.desired > ready {
		return
	}
	p.desired = ready + 1
	p.publish()
}
func (p *QUICPoolState) Ready(ref netproxy.ResourceRef) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if usable, ok := p.members[ref]; !ok || usable || p.closed {
		return
	}
	p.members[ref] = true
	ready := p.ready()
	if ready >= p.desired {
		p.desired = ready
		p.cause = nil
	}
	p.publish()
}
func (p *QUICPoolState) Failed(ref netproxy.ResourceRef, cause error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if usable, ok := p.members[ref]; !ok || !usable || p.closed {
		return
	}
	p.members[ref] = false
	p.episode++
	p.cause = netproxy.WrapFailure(cause, netproxy.Failure{Resource: ref, Scope: netproxy.ScopeSharedResource})
	p.publish()
}
func (p *QUICPoolState) Remove(ref netproxy.ResourceRef) {
	p.mu.Lock()
	defer p.mu.Unlock()
	usable := p.members[ref]
	delete(p.members, ref)
	if usable && !p.closed {
		p.publish()
	}
}
func (p *QUICPoolState) BeginConnect() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.connecting++
	p.publish()
}
func (p *QUICPoolState) EndConnect(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.connecting--
	if err != nil {
		p.cause = err
	}
	p.publish()
}
func (p *QUICPoolState) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.publish()
}
