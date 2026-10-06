// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"io"
	"net"
	"sync"
	"syscall"

	"github.com/daeuniverse/outbound/netproxy"
)

// dormantTransport preserves a logical path while disposing of unused physical
// sessions. Runtime leases and active operations prevent sleep during traffic.
type dormantTransport struct {
	mu             sync.Mutex
	connectMu      sync.Mutex
	factory        func() (*netproxy.Runtime, error)
	runtime        *netproxy.Runtime
	state          *netproxy.StateBroadcaster
	watchCancel    context.CancelFunc
	childReadiness uint64
	childSeq       uint64
	hasChild       bool
	active         int
	demand         bool
	closed         bool
}

// NewRecreatableDialer validates the chain once, then allows unused sessions to
// sleep. Every subsequent generation is constructed from the same immutable path.
func NewRecreatableDialer(factory func() (*netproxy.Runtime, error), option *GlobalOption, property *Property, scope string) (*Dialer, error) {
	runtime, err := factory()
	if err != nil {
		return nil, err
	}
	transport := &dormantTransport{factory: factory, state: netproxy.NewStateBroadcaster(netproxy.SessionDisconnected), demand: true}
	transport.mu.Lock()
	transport.attachLocked(runtime)
	transport.mu.Unlock()
	owner := netproxy.NewRuntime(netproxy.Layer{Data: transport, Sessions: []netproxy.Session{transport}, Resources: []io.Closer{transport}})
	d := NewDialer(owner, option, property, true, scope)
	d.dormant = transport
	return d, nil
}

func (t *dormantTransport) attachLocked(runtime *netproxy.Runtime) {
	t.runtime = runtime
	t.childReadiness = 0
	t.hasChild = false
	if session := runtime.Session(); session != nil {
		ctx, cancel := context.WithCancel(context.Background())
		t.watchCancel = cancel
		t.publishLocked(session.Snapshot())
		go func() {
			for event := range session.WatchState(ctx) {
				t.mu.Lock()
				if t.runtime == runtime {
					t.publishLocked(event)
				}
				t.mu.Unlock()
			}
		}()
	} else {
		t.publishLocked(netproxy.StateEvent{State: netproxy.SessionConnected, Accepting: true, UsableCapacity: 1, Resource: netproxy.NewResourceRef()})
	}
}

func (t *dormantTransport) publishLocked(event netproxy.StateEvent) {
	if t.hasChild && event.Seq <= t.childSeq {
		return
	}
	t.childSeq, t.hasChild = event.Seq, true
	readiness := t.state.Snapshot().ReadinessVersion
	if event.ReadinessVersion != t.childReadiness {
		t.childReadiness = event.ReadinessVersion
		readiness++
	}
	event.ReadinessVersion = readiness
	t.state.Publish(event)
}

func (t *dormantTransport) Snapshot() netproxy.StateEvent { return t.state.Snapshot() }
func (t *dormantTransport) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return t.state.WatchState(ctx)
}

func (t *dormantTransport) Connect(ctx context.Context) error {
	t.connectMu.Lock()
	defer t.connectMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return net.ErrClosed
	}
	t.active++
	runtime := t.runtime
	t.mu.Unlock()
	defer t.release()
	if runtime == nil {
		var err error
		runtime, err = t.factory()
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			runtime.Retire()
			return err
		}
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			runtime.Retire()
			return net.ErrClosed
		}
		t.attachLocked(runtime)
		t.mu.Unlock()
	}
	if session := runtime.Session(); session != nil {
		err := session.Connect(ctx)
		t.mu.Lock()
		if t.runtime == runtime {
			t.publishLocked(session.Snapshot())
		}
		t.mu.Unlock()
		return err
	}
	return nil
}

func (t *dormantTransport) acquire() (*netproxy.Runtime, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, net.ErrClosed
	}
	if t.runtime == nil {
		return nil, netproxy.ErrNotConnected
	}
	t.active++
	return t.runtime, nil
}

func (t *dormantTransport) release() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.active--
	t.sleepLocked()
}

func (t *dormantTransport) setDemand(demand bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.demand = demand
	t.sleepLocked()
}

func (t *dormantTransport) status() (netproxy.StateEvent, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state.Snapshot(), t.runtime == nil && t.active == 0 && !t.closed
}

func (t *dormantTransport) sleepLocked() {
	if t.demand || t.active != 0 || t.runtime == nil {
		return
	}
	runtime := t.runtime
	t.runtime = nil
	if t.watchCancel != nil {
		t.watchCancel()
		t.watchCancel = nil
	}
	t.state.Publish(netproxy.StateEvent{State: netproxy.SessionDisconnected,
		Cause: netproxy.WrapFailure(netproxy.ErrNotConnected, netproxy.Failure{Origin: netproxy.OriginLocalCleanup, Code: "idle"})})
	runtime.Retire()
}

type dormantConn struct {
	net.Conn
	release func()
}

func (c *dormantConn) Close() error                     { defer c.release(); return c.Conn.Close() }
func (c *dormantConn) CloseWrite() error                { return netproxy.CloseWrite(c.Conn) }
func (c *dormantConn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }

type dormantPacketConn struct {
	net.PacketConn
	release func()
}

type dormantSyscallConn struct {
	*dormantConn
	raw syscall.Conn
}

func (c *dormantSyscallConn) SyscallConn() (syscall.RawConn, error) { return c.raw.SyscallConn() }

type dormantSyscallPacketConn struct {
	*dormantPacketConn
	raw syscall.Conn
}

func (c *dormantSyscallPacketConn) SyscallConn() (syscall.RawConn, error) { return c.raw.SyscallConn() }

func (c *dormantPacketConn) Close() error { defer c.release(); return c.PacketConn.Close() }

func (t *dormantTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	runtime, err := t.acquire()
	if err != nil {
		return nil, err
	}
	conn, err := runtime.Dialer().DialContext(ctx, network, address)
	if err != nil {
		t.release()
		return nil, err
	}
	tracked := &dormantConn{conn, sync.OnceFunc(t.release)}
	if raw, ok := conn.(syscall.Conn); ok {
		return &dormantSyscallConn{tracked, raw}, nil
	}
	return tracked, nil
}

func (t *dormantTransport) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	runtime, err := t.acquire()
	if err != nil {
		return nil, err
	}
	conn, err := runtime.Dialer().ListenPacket(ctx, address)
	if err != nil {
		t.release()
		return nil, err
	}
	tracked := &dormantPacketConn{conn, sync.OnceFunc(t.release)}
	if raw, ok := conn.(syscall.Conn); ok {
		return &dormantSyscallPacketConn{tracked, raw}, nil
	}
	return tracked, nil
}

func (t *dormantTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	runtime := t.runtime
	t.runtime = nil
	if t.watchCancel != nil {
		t.watchCancel()
	}
	t.state.Transition(netproxy.SessionClosed, nil)
	t.mu.Unlock()
	if runtime == nil {
		return nil
	}
	runtime.Retire()
	return runtime.Wait(context.Background())
}

func (d *pathRuntime) updateTransportDemandLocked() {
	if d.dormant == nil {
		return
	}
	needed := !d.checkPaused || d.checkRunning || d.pendingCheck != 0 || d.retains > 0 || d.proofHolds > 0
	for _, flight := range d.selectionChecks {
		needed = needed || flight != nil
	}
	for member := range d.members {
		needed = needed || member.selected && !member.closed
	}
	d.dormant.setDemand(needed)
}

func (d *Dialer) SetSelected(selected bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.selected == selected {
		return
	}
	d.selected = selected
	d.statusRevision++
	d.updateTransportDemandLocked()
}
