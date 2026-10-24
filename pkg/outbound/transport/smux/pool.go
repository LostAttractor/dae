package smux

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

const (
	// expandStreams is the number of user streams every connected session
	// carries before the pool asks for another session (sing-box documents
	// the same min_streams value).
	expandStreams = 4
	// idleTimeout retires extra sessions without user streams for this long.
	idleTimeout = 60 * time.Second
)

// smuxSlot is one bounded pool position. Its lifecycle exists only while the
// slot is active. Slot 0 is the path's base session and is never retired.
type smuxSlot struct {
	lifecycle  *netproxy.SingleSession[*smuxResource]
	connecting int
	// streams counts streams handed out by the pool, including opens in flight;
	// users counts the user streams among them, which alone grow the pool.
	streams, users int
	// lastUsed is the last time user traffic, not connectivity checks, needed
	// this slot.
	lastUsed       time.Time
	state          netproxy.StateEvent
	failedResource netproxy.ResourceRef
}

type smuxPool struct {
	slots        []*smuxSlot
	newLifecycle func() *netproxy.SingleSession[*smuxResource]
	state        *netproxy.PoolState
	episode      uint64

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	cursor    int
	idle      *time.Timer
	idleAt    time.Time
	watchers  sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

func newSmuxPool(owner *Smux, maxConnections int) *smuxPool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &smuxPool{
		state:  netproxy.NewPoolState(netproxy.LayerSMUX),
		ctx:    ctx,
		cancel: cancel,
		slots:  make([]*smuxSlot, maxConnections),
		newLifecycle: func() *netproxy.SingleSession[*smuxResource] {
			return netproxy.NewSingleSession(netproxy.SingleSessionConfig[*smuxResource]{
				Layer: netproxy.LayerSMUX, RecoveryExecutor: netproxy.RecoveryDaemon,
				Establish:   owner.establish,
				IsConnected: smuxResourceConnected,
				Observe:     owner.observe,
				Close: func(resource *smuxResource) error {
					err := resource.session.Close()
					if errors.Is(err, io.ErrClosedPipe) {
						return nil
					}
					return err
				},
			})
		},
	}
	for i := range p.slots {
		p.slots[i] = new(smuxSlot)
	}
	return p
}

func smuxResourceConnected(resource *smuxResource) bool {
	return !resource.monitor.broken.Load() && !resource.session.IsClosed()
}

func (p *smuxPool) Snapshot() netproxy.StateEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.syncStatesLocked()
	p.publishStateLocked(nil)
	return p.state.Snapshot()
}

func (p *smuxPool) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return p.state.WatchState(ctx)
}

func (p *smuxPool) activateLocked(slot *smuxSlot) {
	lifecycle := p.newLifecycle()
	slot.lifecycle = lifecycle
	slot.lastUsed = time.Now()
	slot.state = lifecycle.Snapshot()
	slot.failedResource = netproxy.ResourceRef{}
	events := lifecycle.WatchState(p.ctx)
	p.watchers.Go(func() {
		// A retired lifecycle's events are ignored until its Close ends them.
		for event := range events {
			p.mu.Lock()
			if p.ctx.Err() == nil && slot.lifecycle == lifecycle && event.Seq > slot.state.Seq {
				p.observeSlotLocked(slot, event)
				p.publishStateLocked(event.Cause)
			}
			p.mu.Unlock()
		}
	})
	p.scheduleIdleLocked(slot)
}

// retireLocked closes an extra slot's session without counting a failure.
func (p *smuxPool) retireLocked(slot *smuxSlot) {
	lifecycle := slot.lifecycle
	*slot = smuxSlot{}
	p.watchers.Go(func() { _ = lifecycle.Close() })
}

// idleLocked reports an active extra slot that no stream or Connect uses.
func (p *smuxPool) idleLocked(slot *smuxSlot) bool {
	return p.ctx.Err() == nil && slot != p.slots[0] && slot.lifecycle != nil && slot.streams == 0 && slot.connecting == 0
}

func (p *smuxPool) scheduleIdleLocked(slot *smuxSlot) {
	if !p.idleLocked(slot) {
		return
	}
	at := slot.lastUsed.Add(idleTimeout)
	if !p.idleAt.IsZero() && !at.Before(p.idleAt) {
		return
	}
	p.idleAt = at
	if p.idle == nil {
		p.idle = time.AfterFunc(time.Until(at), p.retireIdle)
		return
	}
	p.idle.Reset(time.Until(at))
}

func (p *smuxPool) retireIdle() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.idleAt = time.Time{}
	retired := false
	for _, slot := range p.slots {
		if !p.idleLocked(slot) {
			continue
		}
		if time.Since(slot.lastUsed) < idleTimeout {
			p.scheduleIdleLocked(slot)
			continue
		}
		if p.soleConnectedLocked(slot) {
			// Keep the path's only usable session while slot 0 is refilled.
			slot.lastUsed = time.Now()
			p.scheduleIdleLocked(slot)
			continue
		}
		p.retireLocked(slot)
		retired = true
	}
	if retired {
		p.publishStateLocked(nil)
	}
}

// soleConnectedLocked reports whether slot is the pool's only connected slot.
func (p *smuxPool) soleConnectedLocked(slot *smuxSlot) bool {
	for _, other := range p.slots {
		if _, connected := p.connectedHandleLocked(other); connected != (other == slot) {
			return false
		}
	}
	return true
}

// observeSlotLocked applies a newer lifecycle event. An idle extra slot whose
// established session fails is retired rather than refilled.
func (p *smuxPool) observeSlotLocked(slot *smuxSlot, event netproxy.StateEvent) {
	if event.Seq <= slot.state.Seq {
		return
	}
	lost := slot.state.State == netproxy.SessionConnected && event.State != netproxy.SessionConnected
	p.observeSlotFailureLocked(slot, event)
	slot.state = event
	if lost && p.idleLocked(slot) {
		p.retireLocked(slot)
	}
}

// Each slot activation remembers one generation watermark; metadata events and
// late errors from replaced resources cannot create another pool episode.
func (p *smuxPool) observeSlotFailureLocked(slot *smuxSlot, event netproxy.StateEvent) {
	if event.Resource.Generation == 0 {
		return
	}
	previous := slot.failedResource
	if previous.OwnerID == event.Resource.OwnerID && previous.ResourceID == event.Resource.ResourceID && previous.Generation >= event.Resource.Generation {
		return
	}
	for _, failure := range netproxy.Failures(event.Cause) {
		if failure.Scope == netproxy.ScopeSharedResource && failure.Origin != netproxy.OriginLocalCleanup {
			slot.failedResource = event.Resource
			p.episode++
			return
		}
	}
}

func (p *smuxPool) syncStatesLocked() {
	for _, slot := range p.slots {
		if slot.lifecycle != nil {
			p.observeSlotLocked(slot, slot.lifecycle.Snapshot())
		}
	}
}

func (p *smuxPool) publishStateLocked(cause error) {
	if p.ctx.Err() != nil {
		return
	}
	capacity := netproxy.PoolCapacity{EpisodeID: p.episode, Cause: cause}
	for _, slot := range p.slots {
		if slot.lifecycle == nil {
			continue
		}
		capacity.DesiredCapacity++
		if _, alive := p.connectedHandleLocked(slot); alive {
			capacity.UsableCapacity++
		} else if slot.connecting > 0 || slot.state.State == netproxy.SessionConnecting {
			capacity.Connecting++
		} else if capacity.Cause == nil {
			capacity.Cause = slot.state.Cause
		}
	}
	p.state.ObserveCapacity(capacity)
}

func (p *smuxPool) connectedHandleLocked(slot *smuxSlot) (*netproxy.SingleSessionHandle[*smuxResource], bool) {
	if slot.lifecycle == nil {
		return nil, false
	}
	handle, err := slot.lifecycle.CurrentHandle()
	if err != nil || !smuxResourceConnected(handle.Resource()) {
		return nil, false
	}
	return handle, true
}

func (p *smuxPool) connectedSlotLocked() *smuxSlot {
	for _, slot := range p.slots {
		if _, connected := p.connectedHandleLocked(slot); connected {
			return slot
		}
	}
	return nil
}

func (p *smuxPool) connectionSlotLocked() *smuxSlot {
	for _, slot := range p.slots {
		if slot.connecting > 0 {
			return slot
		}
	}
	for _, slot := range p.slots {
		if _, alive := p.connectedHandleLocked(slot); slot.lifecycle != nil && !alive {
			return slot
		}
	}
	return p.slots[0]
}

func (p *smuxPool) Connect(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	if p.ctx.Err() != nil {
		p.mu.Unlock()
		return net.ErrClosed
	}
	p.syncStatesLocked()
	p.publishStateLocked(nil)
	if p.connectedSlotLocked() != nil && !p.state.Snapshot().RecoveryRequired {
		p.mu.Unlock()
		return nil
	}
	slot := p.connectionSlotLocked()
	if slot.lifecycle == nil {
		p.activateLocked(slot)
	}
	lifecycle := slot.lifecycle
	slot.connecting++
	p.publishStateLocked(nil)
	p.mu.Unlock()

	err := lifecycle.Connect(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	slot.connecting--
	if p.ctx.Err() != nil {
		return net.ErrClosed
	}
	p.observeSlotLocked(slot, lifecycle.Snapshot())
	p.scheduleIdleLocked(slot)
	p.publishStateLocked(err)
	return err
}

// reserve only allocates established resources. Expansion is an owner fact
// consumed by the external recovery coordinator; data-plane callers never dial
// or wait behind a failed slot's reconnect/backoff.
func (p *smuxPool) reserve(ctx context.Context, excluded map[*smuxSlot]struct{}, user bool) (*smuxSlot, *netproxy.SingleSessionHandle[*smuxResource], error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx.Err() != nil {
		return nil, nil, net.ErrClosed
	}
	// Sync first: syncing may retire an idle slot, never the chosen one.
	p.syncStatesLocked()
	var best *smuxSlot
	var bestHandle *netproxy.SingleSessionHandle[*smuxResource]
	ready, loaded := true, true
	start := p.cursor
	p.cursor = (start + 1) % len(p.slots)
	for offset := range len(p.slots) {
		slot := p.slots[(start+offset)%len(p.slots)]
		if slot.lifecycle == nil {
			continue
		}
		handle, connected := p.connectedHandleLocked(slot)
		if !connected {
			ready = false
			continue
		}
		if _, skip := excluded[slot]; skip {
			continue
		}
		loaded = loaded && slot.users >= expandStreams
		if best == nil || slot.streams < best.streams {
			best, bestHandle = slot, handle
		}
	}
	if user && best != nil && loaded {
		p.expandLocked(ready)
	}
	p.publishStateLocked(nil)
	if best == nil {
		return nil, nil, netproxy.WrapFailure(netproxy.ErrNotConnected, netproxy.Failure{Layer: netproxy.LayerSMUX, Scope: netproxy.ScopeOperation, Reason: netproxy.ReasonCapacity, Phase: netproxy.OpOpenStream})
	}
	best.streams++
	if user {
		best.users++
	}
	return best, bestHandle, nil
}

// expandLocked asks for one more session. Requests coalesce: while an active
// slot is unconnected, the outstanding request is only kept wanted.
func (p *smuxPool) expandLocked(ready bool) {
	for _, slot := range p.slots {
		if slot.lifecycle == nil {
			if ready {
				p.activateLocked(slot)
				return
			}
			continue
		}
		if _, connected := p.connectedHandleLocked(slot); !connected {
			slot.lastUsed = time.Now()
		}
	}
}

func (p *smuxPool) release(slot *smuxSlot, user bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	slot.streams--
	if user {
		slot.users--
		slot.lastUsed = time.Now()
	}
	if !p.idleLocked(slot) {
		return
	}
	if _, connected := p.connectedHandleLocked(slot); !connected {
		// Its session failed while carrying streams; do not refill it idle.
		// A failure its lifecycle has not reported yet retires the slot on
		// arrival instead, so the failure still opens an episode.
		p.observeSlotLocked(slot, slot.lifecycle.Snapshot())
		if slot.lifecycle != nil && slot.state.State != netproxy.SessionConnected {
			p.retireLocked(slot)
		}
		p.publishStateLocked(nil)
		return
	}
	p.scheduleIdleLocked(slot)
}

func (p *smuxPool) OpenStream(ctx context.Context) (net.Conn, error) {
	// Connectivity checks use existing sessions but never grow the pool.
	user := !netproxy.IsConnectivityCheck(ctx)
	excluded := make(map[*smuxSlot]struct{}, len(p.slots))
	var openErr error
	for len(excluded) < len(p.slots) {
		slot, handle, err := p.reserve(ctx, excluded, user)
		if err != nil {
			return nil, errors.Join(openErr, err)
		}
		release := sync.OnceFunc(func() { p.release(slot, user) })
		session := handle.Resource().session
		lease := handle.NewStreamLease()
		stream, err := openStream(ctx, session)
		if err == nil && lease.Valid() {
			return &leasedStream{Stream: stream, handle: handle, lease: lease, release: release}, nil
		}
		if err == nil {
			_ = stream.Close()
			err = netproxy.ErrNotConnected
		}
		lease.Invalidate(err)
		fact := netproxy.ClassifyFailure(err)
		fact.Resource, fact.Stream, fact.Layer, fact.Phase = handle.Ref(), lease.Stream(), netproxy.LayerSMUX, netproxy.OpOpenStream
		if cause := handle.Resource().monitor.cause(); cause != nil || session.IsClosed() {
			if cause != nil {
				err = cause
			}
			fact.Scope = netproxy.ScopeSharedResource
			handle.Abort(netproxy.WrapFailure(err, fact))
		} else if fact.Scope == netproxy.ScopeUnknown {
			fact.Scope = netproxy.ScopeStream
		}
		release()
		err = netproxy.WrapFailure(err, fact)
		openErr = errors.Join(openErr, err)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		excluded[slot] = struct{}{}
	}
	return nil, openErr
}

func (p *smuxPool) Close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.cancel()
		p.state.Close()
		if p.idle != nil {
			p.idle.Stop()
		}
		lifecycles := make([]*netproxy.SingleSession[*smuxResource], 0, len(p.slots))
		for _, slot := range p.slots {
			if slot.lifecycle != nil {
				lifecycles = append(lifecycles, slot.lifecycle)
			}
		}
		p.mu.Unlock()
		for i := len(lifecycles) - 1; i >= 0; i-- {
			p.closeErr = errors.Join(p.closeErr, lifecycles[i].Close())
		}
		p.watchers.Wait()
	})
	return p.closeErr
}
