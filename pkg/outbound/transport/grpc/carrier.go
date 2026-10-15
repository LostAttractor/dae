package grpc

import (
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

// gRPC retains RemoteAddr in each RPC's peer context, including across TLS.
// Carry the physical dependency there instead of assuming a channel has just
// one transport: a GOAWAY can leave old streams draining beside a replacement.
type carrierAddr struct {
	network, address string
	lease            *netproxy.Lease
}

func (a carrierAddr) Network() string                  { return a.network }
func (a carrierAddr) String() string                   { return a.address }
func (a carrierAddr) DependencyLease() *netproxy.Lease { return a.lease }

type carrier struct {
	net.Conn
	dialer    *Dialer
	lease     *netproxy.Lease
	remote    net.Addr
	failOnce  sync.Once
	closeOnce sync.Once
	closeErr  error
}

func (d *Dialer) trackCarrier(conn net.Conn) net.Conn {
	c := &carrier{Conn: conn, dialer: d, lease: netproxy.NewLease(netproxy.NewResourceRef(), netproxy.DependencyOf(conn))}
	remote := carrierAddr{lease: c.lease}
	// Logical parent tunnels may not expose a socket address.
	if addr := conn.RemoteAddr(); addr != nil {
		remote.network, remote.address = addr.Network(), addr.String()
	}
	c.remote = remote
	d.carrier.Store(c)
	go func() {
		<-c.lease.Done()
		c.publishFailure(c.sharedFailure(c.lease.Cause(), netproxy.OpRead))
		if c.lease.AbortCause() != nil {
			_ = c.Close()
		}
	}()
	return c
}

func (c *carrier) RemoteAddr() net.Addr { return c.remote }
func (c *carrier) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.fail(err, netproxy.OpRead)
	return n, err
}
func (c *carrier) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.fail(err, netproxy.OpWrite)
	return n, err
}

func (c *carrier) fail(err error, phase netproxy.Operation) {
	if err == nil || c.dialer.closed.Load() {
		return
	}
	fact := netproxy.ClassifyFailure(err)
	if fact.Reason == netproxy.ReasonDeadline || fact.Origin == netproxy.OriginLocalCleanup {
		return
	}
	c.failOnce.Do(func() {
		if cause := c.lease.Cause(); cause != nil {
			err = cause
		}
		cause := c.sharedFailure(err, phase)
		c.lease.Abort(cause)
		// Revoke streams before any potentially blocking transport cleanup.
		c.publishFailure(cause)
	})
}

func (c *carrier) sharedFailure(cause error, phase netproxy.Operation) error {
	fact := netproxy.ClassifyFailure(cause)
	fact.Resource, fact.Scope, fact.Phase = c.lease.Resource(), netproxy.ScopeSharedResource, phase
	if fact.Layer == netproxy.LayerUnknown {
		fact.Layer = netproxy.LayerTCP
	}
	if cause == io.EOF {
		fact.Reason = netproxy.ReasonClosed
	}
	return netproxy.WrapFailure(cause, fact)
}

func (c *carrier) publishFailure(cause error) {
	c.dialer.stateMu.Lock()
	defer c.dialer.stateMu.Unlock()
	if c.dialer.carrier.Load() == c {
		if handle := c.dialer.handle.Load(); handle != nil {
			handle.Transition(netproxy.SessionDisconnected, cause)
		}
	}
}

func (c *carrier) Close() error {
	c.closeOnce.Do(func() {
		if c.dialer.closed.Load() {
			c.lease.Invalidate(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Scope: netproxy.ScopeSharedResource, Layer: netproxy.LayerGRPC, Origin: netproxy.OriginLocalCleanup}))
		} else {
			// gRPC also closes carriers for HTTP/2 protocol and keepalive failures
			// that do not surface as a raw socket Read or Write error.
			c.fail(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Layer: netproxy.LayerH2, Reason: netproxy.ReasonClosed}), netproxy.OpClose)
		}
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}
