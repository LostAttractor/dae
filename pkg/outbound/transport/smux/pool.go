package smux

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/xtaci/smux"
)

type smuxSlot struct {
	lifecycle      *netproxy.SingleSession[*smuxResource]
	activated      bool
	connecting     int
	pending        int
	state          netproxy.StateEvent
	failedResource netproxy.ResourceRef
}

type smuxPool struct {
	slots   []*smuxSlot
	state   *netproxy.PoolState
	episode uint64

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	cursor    int
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
	}
	for i := range p.slots {
		p.slots[i] = &smuxSlot{lifecycle: netproxy.NewSingleSession(netproxy.SingleSessionConfig[*smuxResource]{
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
		})}
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
	if slot.activated {
		return
	}
	slot.activated = true
	slot.state = slot.lifecycle.Snapshot()
	events := slot.lifecycle.WatchState(p.ctx)
	p.watchers.Go(func() {
		for event := range events {
			p.mu.Lock()
			if p.ctx.Err() != nil {
				p.mu.Unlock()
				return
			}
			if event.Seq > slot.state.Seq {
				p.observeSlotFailureLocked(slot, event)
				slot.state = event
				p.publishStateLocked(event.Cause)
			}
			p.mu.Unlock()
		}
	})
}

func (p *smuxPool) syncSlotStateLocked(slot *smuxSlot) {
	event := slot.lifecycle.Snapshot()
	if event.Seq > slot.state.Seq {
		p.observeSlotFailureLocked(slot, event)
		slot.state = event
	}
}

// Each fixed slot remembers one generation watermark; metadata events and
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
		if slot.activated {
			p.syncSlotStateLocked(slot)
		}
	}
}

func (p *smuxPool) publishStateLocked(cause error) {
	if p.ctx.Err() != nil {
		return
	}
	capacity := netproxy.PoolCapacity{EpisodeID: p.episode, Cause: cause}
	for _, slot := range p.slots {
		if !slot.activated {
			continue
		}
		capacity.DesiredCapacity++
		if _, alive := p.connectedResourceLocked(slot); alive {
			capacity.UsableCapacity++
		} else if slot.connecting > 0 || slot.state.State == netproxy.SessionConnecting {
			capacity.Connecting++
		} else if capacity.Cause == nil {
			capacity.Cause = slot.state.Cause
		}
	}
	p.state.ObserveCapacity(capacity)
}

func (p *smuxPool) connectedResourceLocked(slot *smuxSlot) (*smuxResource, bool) {
	resource, err := slot.lifecycle.Current()
	if err != nil || !smuxResourceConnected(resource) {
		return nil, false
	}
	return resource, true
}

func (p *smuxPool) connectedSlotLocked() *smuxSlot {
	for _, slot := range p.slots {
		if slot.activated {
			if _, connected := p.connectedResourceLocked(slot); !connected {
				continue
			}
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
		if slot.activated {
			if _, alive := p.connectedResourceLocked(slot); !alive {
				return slot
			}
		}
	}
	for _, slot := range p.slots {
		if !slot.activated {
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
	if p.connectedSlotLocked() != nil {
		p.syncStatesLocked()
		p.publishStateLocked(nil)
		if !p.state.Snapshot().RecoveryRequired {
			p.mu.Unlock()
			return nil
		}
	}
	p.syncStatesLocked()
	p.publishStateLocked(nil)
	slot := p.connectionSlotLocked()
	p.activateLocked(slot)
	slot.connecting++
	p.publishStateLocked(nil)
	p.mu.Unlock()

	err := slot.lifecycle.Connect(ctx)
	p.mu.Lock()
	slot.connecting--
	p.syncSlotStateLocked(slot)
	closed := p.ctx.Err() != nil
	p.publishStateLocked(err)
	p.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	return err
}

// reserve only allocates established resources. Expansion is an owner fact
// consumed by the external recovery coordinator; data-plane callers never dial
// or wait behind a failed slot's reconnect/backoff.
func (p *smuxPool) reserve(ctx context.Context, excluded map[*smuxSlot]struct{}, allowExpand bool) (*smuxSlot, *smux.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx.Err() != nil {
		return nil, nil, net.ErrClosed
	}
	var best *smuxSlot
	var resource *smuxResource
	bestLoad := 0
	start := p.cursor
	p.cursor = (start + 1) % len(p.slots)
	for offset := range len(p.slots) {
		slot := p.slots[(start+offset)%len(p.slots)]
		if _, skip := excluded[slot]; skip || !slot.activated {
			continue
		}
		candidate, alive := p.connectedResourceLocked(slot)
		if !alive {
			continue
		}
		load := candidate.session.NumStreams() + slot.pending
		if best == nil || load < bestLoad {
			best, resource, bestLoad = slot, candidate, load
		}
	}
	if allowExpand && best != nil && bestLoad > 0 {
		for _, slot := range p.slots {
			if !slot.activated {
				p.activateLocked(slot)
				break
			}
		}
	}
	p.syncStatesLocked()
	p.publishStateLocked(nil)
	if best == nil {
		return nil, nil, netproxy.WrapFailure(netproxy.ErrNotConnected, netproxy.Failure{Layer: netproxy.LayerSMUX, Scope: netproxy.ScopeOperation, Reason: netproxy.ReasonCapacity, Phase: netproxy.OpOpenStream})
	}
	best.pending++
	return best, resource.session, nil
}

func (p *smuxPool) release(slot *smuxSlot) {
	p.mu.Lock()
	if slot.pending > 0 {
		slot.pending--
	}
	p.mu.Unlock()
}

func (p *smuxPool) OpenStream(ctx context.Context) (net.Conn, error) {
	excluded := make(map[*smuxSlot]struct{}, len(p.slots))
	var openErr error
	for len(excluded) < len(p.slots) {
		slot, session, err := p.reserve(ctx, excluded, true)
		if err != nil {
			return nil, errors.Join(openErr, err)
		}
		handle, handleErr := slot.lifecycle.CurrentHandle()
		if handleErr != nil || handle.Resource().session != session {
			p.release(slot)
			excluded[slot] = struct{}{}
			continue
		}
		lease := handle.NewStreamLease()
		stream, err := openStream(ctx, session, func() { p.release(slot) })
		if err == nil && lease.Valid() {
			return &leasedStream{Stream: stream, handle: handle, lease: lease}, nil
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
		p.mu.Unlock()
		for i := len(p.slots) - 1; i >= 0; i-- {
			p.closeErr = errors.Join(p.closeErr, p.slots[i].lifecycle.Close())
		}
		p.watchers.Wait()
	})
	return p.closeErr
}
