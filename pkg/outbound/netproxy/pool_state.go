// SPDX-License-Identifier: AGPL-3.0-only

package netproxy

import (
	"context"
	"sync"
)

// PoolState aggregates independently owned connections. Its stable pool
// identity is distinct from each member identity carried by failure.Cause.
type PoolState struct {
	layer      FailureLayer
	stateless  bool
	mu         sync.Mutex
	state      *StateBroadcaster
	ref        ResourceRef
	members    map[ResourceRef]bool
	connecting int
	desired    int
	episode    uint64
	cause      error
	closed     bool
}

func NewPoolState(layer FailureLayer) *PoolState {
	p := &PoolState{layer: layer, state: NewStateBroadcaster(SessionDisconnected), ref: NewResourceRef(), members: make(map[ResourceRef]bool), desired: 1}
	p.publish()
	return p
}
func (p *PoolState) NewResource() ResourceRef {
	p.mu.Lock()
	defer p.mu.Unlock()
	ref := NewResourceRef()
	ref.OwnerID = p.ref.OwnerID
	if !p.closed {
		p.members[ref] = false
	}
	return ref
}
func (p *PoolState) Snapshot() StateEvent { return p.state.Snapshot() }
func (p *PoolState) WatchState(ctx context.Context) <-chan StateEvent {
	return p.state.WatchState(ctx)
}
func (p *PoolState) ready() int {
	ready := 0
	for _, usable := range p.members {
		if usable {
			ready++
		}
	}
	return ready
}
func (p *PoolState) publish() { p.publishPhase("") }

func (p *PoolState) publishPhase(override string) {
	ready := p.ready()
	state, phase := SessionDisconnected, "queued"
	if p.closed {
		state, phase = SessionClosed, "stopped"
	} else if p.stateless || ready > 0 {
		state, phase = SessionConnected, "ready"
	} else if p.connecting > 0 {
		state = SessionConnecting
	}
	required := !p.closed && !p.stateless && ready < p.desired
	if !p.closed && p.connecting > 0 {
		phase = "connecting"
	} else if required {
		phase = "queued"
	}
	if p.stateless && !p.closed {
		phase = "stateless"
	}
	if override != "" && !p.closed {
		phase = override
	}
	p.state.Publish(StateEvent{State: state, Cause: p.cause, Resource: p.ref, EpisodeID: p.episode,
		Layer: p.layer, Accepting: (p.stateless || ready > 0) && !p.closed, UsableCapacity: ready,
		RecoveryRequired: required, RecoveryPhase: phase, RecoveryExecutor: RecoveryDaemon})
}
func (p *PoolState) IsReady(ref ResourceRef) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closed && p.members[ref]
}

// RequestCapacity coalesces simultaneous admission failures into one extra
// member request. It never starts a timer or bypasses the background executor.
func (p *PoolState) RequestCapacity(cause error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.stateless {
		return
	}
	ready := p.ready()
	if p.desired > ready {
		return
	}
	p.desired = ready + 1
	if cause != nil {
		p.cause = cause
		p.publishPhase("capacity_wait")
	} else {
		p.publish()
	}
}
func (p *PoolState) Ready(ref ResourceRef) {
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
func (p *PoolState) Failed(ref ResourceRef, cause error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if usable, ok := p.members[ref]; !ok || !usable || p.closed {
		return
	}
	p.members[ref] = false
	p.episode++
	p.cause = WrapFailure(cause, Failure{Resource: ref, Scope: ScopeSharedResource})
	p.publish()
}
func (p *PoolState) Remove(ref ResourceRef) {
	p.mu.Lock()
	defer p.mu.Unlock()
	usable := p.members[ref]
	delete(p.members, ref)
	if usable && !p.closed {
		p.publish()
	}
}
func (p *PoolState) BeginConnect() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.connecting++
	p.publish()
	return true
}
func (p *PoolState) EndConnect(err error) {
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
func (p *PoolState) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.publish()
}

// Stateless marks successful negotiation of a protocol with no shared resource.
// The protocol implementation continues to own every individual connection.
func (p *PoolState) Stateless(layer FailureLayer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.stateless, p.layer, p.cause = true, layer, nil
	p.publish()
}

// Unavailable records a protocol-owned drain or terminal transition. A graceful
// drain may be followed by a distinct fatal error; local cleanup is not an accident.
func (p *PoolState) Unavailable(ref ResourceRef, cause error, phase string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ready, exists := p.members[ref]
	if !exists || p.closed {
		return
	}
	local := ClassifyFailure(cause).Origin == OriginLocalCleanup
	if !ready && local {
		return
	}
	p.members[ref] = false
	if cause != nil && !local {
		p.episode++
	}
	if cause != nil {
		p.cause = cause
	}
	if p.ready() >= p.desired {
		p.cause = nil
	}
	p.publishPhase(phase)
}

// RefineFailure enriches the current resource's failure without opening a new
// episode or allowing late errors to overwrite a replacement's healthy state.
func (p *PoolState) RefineFailure(ref ResourceRef, cause error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.stateless || p.ready() >= p.desired || ClassifyFailure(p.cause).Resource != ref {
		return
	}
	p.cause = cause
	p.publish()
}
