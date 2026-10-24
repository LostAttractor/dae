package singmux

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

// sessionSlot is one bounded pool position. Its lifecycle exists only while the
// slot is active. Slot 0 is the path's base session and is never retired.
type sessionSlot struct {
	lifecycle  *netproxy.SingleSession[*sessionResource]
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

type sessionPool struct {
	layer        netproxy.FailureLayer
	slots        []*sessionSlot
	newLifecycle func() *netproxy.SingleSession[*sessionResource]
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

func newSessionPool(owner *Mux, maxConnections int) *sessionPool {
	ctx, cancel := context.WithCancel(context.Background())
	layer := owner.Protocol.layer()
	p := &sessionPool{
		layer:  layer,
		state:  netproxy.NewPoolState(layer),
		ctx:    ctx,
		cancel: cancel,
		slots:  make([]*sessionSlot, maxConnections),
		newLifecycle: func() *netproxy.SingleSession[*sessionResource] {
			return netproxy.NewSingleSession(netproxy.SingleSessionConfig[*sessionResource]{
				Layer: layer, RecoveryExecutor: netproxy.RecoveryDaemon,
				Establish:   owner.establish,
				IsConnected: (*sessionResource).connected,
				Observe:     owner.observe,
				Close: func(resource *sessionResource) error {
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
		p.slots[i] = new(sessionSlot)
	}
	return p
}

func (p *sessionPool) Snapshot() netproxy.StateEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.syncStatesLocked()
	p.publishStateLocked(nil)
	return p.state.Snapshot()
}

func (p *sessionPool) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return p.state.WatchState(ctx)
}

func (p *sessionPool) activateLocked(slot *sessionSlot) {
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
func (p *sessionPool) retireLocked(slot *sessionSlot) {
	lifecycle := slot.lifecycle
	*slot = sessionSlot{}
	p.watchers.Go(func() { _ = lifecycle.Close() })
}

// idleLocked reports an active extra slot that no stream or Connect uses.
func (p *sessionPool) idleLocked(slot *sessionSlot) bool {
	return p.ctx.Err() == nil && slot != p.slots[0] && slot.lifecycle != nil && slot.streams == 0 && slot.connecting == 0
}

func (p *sessionPool) scheduleIdleLocked(slot *sessionSlot) {
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

func (p *sessionPool) retireIdle() {
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
func (p *sessionPool) soleConnectedLocked(slot *sessionSlot) bool {
	for _, other := range p.slots {
		if _, connected := p.connectedHandleLocked(other); connected != (other == slot) {
			return false
		}
	}
	return true
}

// observeSlotLocked applies a newer lifecycle event. An idle extra slot whose
// established session fails is retired rather than refilled.
func (p *sessionPool) observeSlotLocked(slot *sessionSlot, event netproxy.StateEvent) {
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
func (p *sessionPool) observeSlotFailureLocked(slot *sessionSlot, event netproxy.StateEvent) {
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

func (p *sessionPool) syncStatesLocked() {
	for _, slot := range p.slots {
		if slot.lifecycle != nil {
			p.observeSlotLocked(slot, slot.lifecycle.Snapshot())
		}
	}
}

func (p *sessionPool) publishStateLocked(cause error) {
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

func (p *sessionPool) connectedHandleLocked(slot *sessionSlot) (*netproxy.SingleSessionHandle[*sessionResource], bool) {
	if slot.lifecycle == nil {
		return nil, false
	}
	handle, err := slot.lifecycle.CurrentHandle()
	if err != nil || !handle.Resource().connected() {
		return nil, false
	}
	return handle, true
}

func (p *sessionPool) connectedSlotLocked() *sessionSlot {
	for _, slot := range p.slots {
		if _, connected := p.connectedHandleLocked(slot); connected {
			return slot
		}
	}
	return nil
}

func (p *sessionPool) connectionSlotLocked() *sessionSlot {
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

func (p *sessionPool) Connect(ctx context.Context) error {
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
func (p *sessionPool) reserve(ctx context.Context, excluded map[*sessionSlot]struct{}, user bool) (*sessionSlot, *netproxy.SingleSessionHandle[*sessionResource], error) {
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
	var best *sessionSlot
	var bestHandle *netproxy.SingleSessionHandle[*sessionResource]
	ready, loaded, bestSaturated := true, true, false
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
		// A saturated session is loaded whatever it carries: new streams
		// there could not grow their receive windows.
		saturated := handle.Resource().session.saturated()
		loaded = loaded && (saturated || slot.users >= expandStreams)
		if best == nil || bestSaturated && !saturated || bestSaturated == saturated && slot.streams < best.streams {
			best, bestHandle, bestSaturated = slot, handle, saturated
		}
	}
	if user && best != nil && loaded {
		p.expandLocked(ready)
	}
	p.publishStateLocked(nil)
	if best == nil {
		return nil, nil, netproxy.WrapFailure(netproxy.ErrNotConnected, netproxy.Failure{Layer: p.layer, Scope: netproxy.ScopeOperation, Reason: netproxy.ReasonCapacity, Phase: netproxy.OpOpenStream})
	}
	best.streams++
	if user {
		best.users++
	}
	return best, bestHandle, nil
}

// expandLocked asks for one more session. Requests coalesce: while an active
// slot is unconnected, the outstanding request is only kept wanted.
func (p *sessionPool) expandLocked(ready bool) {
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

func (p *sessionPool) release(slot *sessionSlot, user bool) {
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

func (p *sessionPool) OpenStream(ctx context.Context) (net.Conn, error) {
	// Connectivity checks use existing sessions but never grow the pool.
	user := !netproxy.IsConnectivityCheck(ctx)
	excluded := make(map[*sessionSlot]struct{}, len(p.slots))
	var openErr error
	for len(excluded) < len(p.slots) {
		slot, handle, err := p.reserve(ctx, excluded, user)
		if err != nil {
			return nil, errors.Join(openErr, err)
		}
		release := sync.OnceFunc(func() { p.release(slot, user) })
		session := handle.Resource().session
		lease := handle.NewStreamLease()
		stream, err := session.OpenStream(ctx)
		if err == nil && lease.Valid() {
			return &leasedStream{Conn: stream, layer: p.layer, handle: handle, lease: lease, release: release}, nil
		}
		if err == nil {
			_ = stream.Close()
			err = netproxy.ErrNotConnected
		}
		lease.Invalidate(err)
		fact := netproxy.ClassifyFailure(err)
		fact.Resource, fact.Stream, fact.Layer, fact.Phase = handle.Ref(), lease.Stream(), p.layer, netproxy.OpOpenStream
		if cause := handle.Resource().cause(); cause != nil || session.IsClosed() {
			if cause != nil {
				err = cause
			}
			fact.Scope = netproxy.ScopeSharedResource
			handle.Abort(netproxy.WrapFailure(err, fact))
		} else if idsExhausted(err) {
			// Replace the session; it would fail every later open.
			fact.Scope, fact.Origin, fact.Reason = netproxy.ScopeSharedResource, netproxy.OriginLocalProtocol, netproxy.ReasonCapacity
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

func (p *sessionPool) Close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.cancel()
		p.state.Close()
		if p.idle != nil {
			p.idle.Stop()
		}
		lifecycles := make([]*netproxy.SingleSession[*sessionResource], 0, len(p.slots))
		for _, slot := range p.slots {
			if slot.lifecycle != nil {
				lifecycles = append(lifecycles, slot.lifecycle)
			}
		}
		p.mu.Unlock()
		// In parallel: a session may write its queued frames for a while.
		errs := make([]error, len(lifecycles))
		var closing sync.WaitGroup
		for i, lifecycle := range lifecycles {
			closing.Go(func() { errs[i] = lifecycle.Close() })
		}
		closing.Wait()
		p.closeErr = errors.Join(errs...)
		p.watchers.Wait()
	})
	return p.closeErr
}
