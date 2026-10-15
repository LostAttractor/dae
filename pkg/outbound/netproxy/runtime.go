package netproxy

import (
	"context"
	"net"
	"sync"
)

// Runtime owns one fully constructed outbound chain. Retire rejects new work
// and releases the chain after all operations and returned connections drain.
type Runtime struct {
	layer        Layer
	dialer       Dialer
	session      Session
	sessionGroup *SessionGroup

	mu        sync.Mutex
	refs      int
	retired   bool
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

type runtimeSession struct {
	Session
	runtime *Runtime
}

type runtimeDialer struct{ runtime *Runtime }

func (s *runtimeSession) Connect(ctx context.Context) error {
	r := s.runtime
	if !r.acquire() {
		return net.ErrClosed
	}
	defer r.release()
	if err := s.Session.Connect(ctx); err != nil {
		return err
	}
	if !r.accepting() {
		return net.ErrClosed
	}
	return nil
}

func (d *runtimeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	r := d.runtime
	if !r.acquire() {
		return nil, net.ErrClosed
	}
	conn, err := r.layer.Data.DialContext(ctx, network, address)
	if err != nil {
		r.release()
		return nil, err
	}
	if !r.accepting() {
		_ = conn.Close()
		r.release()
		return nil, net.ErrClosed
	}
	return TrackConn(conn, r.release), nil
}

func (d *runtimeDialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	r := d.runtime
	if !r.acquire() {
		return nil, net.ErrClosed
	}
	conn, err := r.layer.Data.ListenPacket(ctx, address)
	if err != nil {
		r.release()
		return nil, err
	}
	if !r.accepting() {
		_ = conn.Close()
		r.release()
		return nil, net.ErrClosed
	}
	return TrackPacketConn(conn, r.release), nil
}

// NewRuntime transfers ownership of layer to a Runtime.
func NewRuntime(layer Layer) *Runtime {
	if layer.Data == nil {
		panic(ErrMissingDialer)
	}
	runtime := &Runtime{layer: layer, done: make(chan struct{})}
	runtime.dialer = &runtimeDialer{runtime: runtime}
	switch len(layer.Sessions) {
	case 0:
	case 1:
		runtime.session = &runtimeSession{Session: layer.Sessions[0], runtime: runtime}
	default:
		runtime.sessionGroup = NewSessionGroup(layer.Sessions...)
		runtime.session = &runtimeSession{Session: runtime.sessionGroup, runtime: runtime}
	}
	return runtime
}

// Dialer returns the data-plane view. It does not expose Session or ownership.
func (r *Runtime) Dialer() Dialer { return r.dialer }

// Session returns the shared-connection controller, or nil for a stateless
// chain. The controller does not expose resource ownership.
func (r *Runtime) Session() Session { return r.session }

func (r *Runtime) acquire() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.retired {
		return false
	}
	r.refs++
	return true
}

func (r *Runtime) accepting() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.retired
}

func (r *Runtime) release() {
	r.mu.Lock()
	r.refs--
	closeOwned := r.retired && r.refs == 0
	r.mu.Unlock()
	if closeOwned {
		r.startClose()
	}
}

func (r *Runtime) startClose() {
	r.closeOnce.Do(func() {
		go r.closeOwned()
	})
}

func (r *Runtime) closeOwned() {
	if r.sessionGroup != nil {
		r.sessionGroup.Stop()
	}
	err := r.layer.Close()
	r.closeErr = err
	close(r.done)
}

// Retire rejects new operations. Resource cleanup runs after the last active
// operation or returned connection releases its implicit lease.
func (r *Runtime) Retire() {
	r.mu.Lock()
	r.retired = true
	closeOwned := r.refs == 0
	r.mu.Unlock()
	if closeOwned {
		r.startClose()
	}
}

// Wait waits for a retired Runtime to finish releasing its owned chain.
func (r *Runtime) Wait(ctx context.Context) error {
	select {
	case <-r.done:
		return r.closeErr
	default:
	}
	select {
	case <-r.done:
		return r.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
