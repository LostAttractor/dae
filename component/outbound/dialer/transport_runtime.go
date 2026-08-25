package dialer

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

type transportRuntime struct {
	owned   *netproxy.Runtime
	session netproxy.Session

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu         sync.RWMutex
	notifyMu   sync.Mutex
	state      netproxy.StateEvent
	views      map[*Dialer]struct{}
	connecting bool
	connectSem chan struct{}

	retireOnce sync.Once
}

func newTransportRuntime(owned *netproxy.Runtime) *transportRuntime {
	ctx, cancel := context.WithCancel(context.Background())
	r := &transportRuntime{
		owned:      owned,
		ctx:        ctx,
		cancel:     cancel,
		views:      make(map[*Dialer]struct{}),
		state:      netproxy.StateEvent{State: netproxy.SessionConnected},
		connectSem: make(chan struct{}, 1),
	}
	if session, ok := owned.Session(); ok {
		r.session = session
		r.state = session.Snapshot()
		r.wg.Add(1)
		go r.watchSession()
	}
	return r
}

func (r *transportRuntime) watchSession() {
	defer r.wg.Done()
	events := r.session.WatchState(r.ctx)
	for event := range events {
		r.publish(event)
	}
	if r.ctx.Err() == nil {
		last := r.session.Snapshot()
		if last.State == netproxy.SessionClosed {
			r.publish(last)
		} else {
			r.publish(netproxy.StateEvent{
				Seq:   r.stateSnapshot().Seq + 1,
				State: netproxy.SessionDisconnected,
				Cause: errors.New("session state stream closed unexpectedly"),
			})
		}
	}
}

func (r *transportRuntime) publish(event netproxy.StateEvent) {
	r.notifyMu.Lock()
	defer r.notifyMu.Unlock()
	r.mu.Lock()
	if r.ctx.Err() != nil {
		r.mu.Unlock()
		return
	}
	if r.session != nil && event.Seq <= r.state.Seq {
		r.mu.Unlock()
		return
	}
	r.state = event
	requestCheck := !r.connecting && event.State != netproxy.SessionClosed
	views := make([]*Dialer, 0, len(r.views))
	for view := range r.views {
		views = append(views, view)
	}
	r.mu.Unlock()
	for _, view := range views {
		view.handleSessionState(event, requestCheck)
	}
}

func (r *transportRuntime) register(view *Dialer) {
	r.notifyMu.Lock()
	defer r.notifyMu.Unlock()
	r.mu.Lock()
	r.views[view] = struct{}{}
	r.mu.Unlock()
	if r.session != nil {
		view.handleSessionState(r.stateSnapshot(), false)
	}
}

func (r *transportRuntime) unregister(view *Dialer) {
	r.notifyMu.Lock()
	defer r.notifyMu.Unlock()
	r.mu.Lock()
	delete(r.views, view)
	r.mu.Unlock()
}

func (r *transportRuntime) stateSnapshot() netproxy.StateEvent {
	r.mu.RLock()
	cached := r.state
	r.mu.RUnlock()
	if r.session == nil {
		return cached
	}
	live := r.session.Snapshot()
	if live.Seq >= cached.Seq {
		return live
	}
	return cached
}

func (r *transportRuntime) connected() bool {
	return r.accepting() && (r.session == nil || r.stateSnapshot().State == netproxy.SessionConnected)
}

func (r *transportRuntime) sessionSnapshot() (netproxy.StateEvent, bool) {
	if r.session == nil {
		return netproxy.StateEvent{}, false
	}
	return r.stateSnapshot(), true
}

func (r *transportRuntime) sessionSeq() uint64 {
	if r.session == nil {
		return 0
	}
	return r.stateSnapshot().Seq
}

func (r *transportRuntime) matchesSession(seq uint64) bool {
	return r.session == nil || r.stateSnapshot().Seq == seq
}

func (r *transportRuntime) connect(ctx context.Context, requester *Dialer) error {
	if !r.accepting() {
		return net.ErrClosed
	}
	if r.session == nil {
		return nil
	}
	select {
	case r.connectSem <- struct{}{}:
		defer func() { <-r.connectSem }()
	case <-ctx.Done():
		return ctx.Err()
	case <-r.ctx.Done():
		return net.ErrClosed
	}
	if !r.accepting() {
		return net.ErrClosed
	}
	if r.connected() {
		return nil
	}
	r.mu.Lock()
	r.connecting = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.connecting = false
		r.mu.Unlock()
	}()
	err := r.session.Connect(ctx)
	r.publish(r.session.Snapshot())
	r.mu.Lock()
	connected := r.state.State == netproxy.SessionConnected
	views := make([]*Dialer, 0, len(r.views))
	if connected {
		for view := range r.views {
			if view != requester {
				views = append(views, view)
			}
		}
	}
	r.mu.Unlock()
	for _, view := range views {
		view.NotifyCheck()
	}
	return err
}

func (r *transportRuntime) accepting() bool {
	return r.ctx.Err() == nil
}

func (r *transportRuntime) retire() {
	r.retireOnce.Do(func() {
		owned := r.owned
		owned.Retire()
		go func() {
			if err := owned.Wait(context.Background()); err != nil {
				log.Warnf("Failed to release outbound runtime: %v", err)
			}
		}()
		r.cancel()
		r.wg.Wait()
		r.mu.Lock()
		clear(r.views)
		r.mu.Unlock()
	})
}
