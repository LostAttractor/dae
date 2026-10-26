// Package singmux implements the sing-box multiplex (sing-mux) client over
// smux v1 or yamux sessions. Both share the session pool, the per-stream
// request/response and the UDP packet framing.
package singmux

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/pkg/outbound/common"
	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

// Protocol is the sing-mux session protocol byte.
type Protocol byte

const (
	ProtocolSmux Protocol = iota
	ProtocolYAMux
)

func (p Protocol) String() string {
	switch p {
	case ProtocolSmux:
		return "smux"
	case ProtocolYAMux:
		return "yamux"
	default:
		return fmt.Sprintf("protocol(%d)", byte(p))
	}
}

func (p Protocol) layer() netproxy.FailureLayer {
	if p == ProtocolYAMux {
		return netproxy.LayerYAMUX
	}
	return netproxy.LayerSMUX
}

const Version0 = 0

const (
	flagUDP     = 0b01
	flagAddr    = 0b10
	statusError = 1
)

const (
	DefaultMaxConnections = 4
	MaxConnectionsLimit   = 16
)

type Mux struct {
	Dialer         netproxy.Dialer
	Protocol       Protocol
	PassthroughUdp bool
	MaxConnections int

	initOnce  sync.Once
	lifecycle *sessionPool
}

type sessionResource struct {
	session session
	monitor *monitoredConn
}

func (r *sessionResource) connected() bool {
	return !r.monitor.broken.Load() && !r.session.IsClosed()
}

// cause is the failure that ended the session, if any. The library's own
// reason is more specific than the carrier error its close then induces.
func (r *sessionResource) cause() error {
	if err := r.session.closeErr(); err != nil {
		return err
	}
	return r.monitor.cause()
}

type monitoredConn struct {
	net.Conn
	reportOnce   sync.Once
	failureMu    sync.Mutex
	failureCause error
	failed       chan error
	broken       atomic.Bool
	// readFailed is set once a read from the carrier failed.
	readFailed atomic.Bool
}

func (c *monitoredConn) report(err error) {
	if err != nil {
		c.broken.Store(true)
		c.reportOnce.Do(func() {
			c.failureMu.Lock()
			c.failureCause = err
			c.failureMu.Unlock()
			select {
			case c.failed <- err:
			default:
			}
		})
	}
}

func (c *monitoredConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.readFailed.Store(true)
	}
	c.report(err)
	return n, err
}

func (c *monitoredConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.report(err)
	return n, err
}

func (c *monitoredConn) CloseWrite() error { return netproxy.CloseWrite(c.Conn) }

// lingerCarrier half-closes the carrier of a closing session whose queued
// frames are written, then waits until its receive loop ends on the peer's
// EOF (done) or ctx ends. The peer has then read every frame, and closing
// the drained carrier cannot reset it. A carrier that cannot half-close
// returns at once, and a failed one ends the session, closing done.
func lingerCarrier(ctx context.Context, carrier *monitoredConn, done <-chan struct{}) {
	// CloseWrite may wait behind a blocked carrier write until the caller
	// closes the carrier.
	halfClosed := make(chan error, 1)
	go func() { halfClosed <- carrier.CloseWrite() }()
	select {
	case err := <-halfClosed:
		if err != nil {
			return
		}
	case <-done:
		return
	case <-ctx.Done():
		return
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (c *monitoredConn) cause() error {
	c.failureMu.Lock()
	defer c.failureMu.Unlock()
	return c.failureCause
}

func (c *monitoredConn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }
func (c *monitoredConn) WriteThrough() net.Conn           { return c.Conn }

type Config struct {
	Protocol       Protocol
	PassThroughUDP bool
	MaxConnections int
}

func (s *Config) Build(_ *dialer.ExtraOption, upstream dialer.Upstream) (netproxy.Layer, error) {
	if s.MaxConnections < 0 || s.MaxConnections > MaxConnectionsLimit {
		return netproxy.Layer{}, fmt.Errorf("%s max connections must be between 1 and %d", s.Protocol, MaxConnectionsLimit)
	}
	if s.Protocol != ProtocolSmux && s.Protocol != ProtocolYAMux {
		return netproxy.Layer{}, fmt.Errorf("unsupported multiplex %s", s.Protocol)
	}
	mux := &Mux{
		Dialer:         upstream,
		Protocol:       s.Protocol,
		PassthroughUdp: s.PassThroughUDP,
		MaxConnections: s.MaxConnections,
	}
	return netproxy.Layer{
		Data:      mux,
		Sessions:  []netproxy.Session{mux},
		Resources: []io.Closer{mux},
	}, nil
}

func (s *Mux) pool() *sessionPool {
	s.initOnce.Do(func() {
		maxConnections := s.MaxConnections
		if maxConnections == 0 {
			maxConnections = DefaultMaxConnections
		}
		if maxConnections < 1 || maxConnections > MaxConnectionsLimit {
			panic(fmt.Sprintf("%s max connections must be between 1 and %d", s.Protocol, MaxConnectionsLimit))
		}
		s.lifecycle = newSessionPool(s, maxConnections)
	})
	return s.lifecycle
}

func (s *Mux) Snapshot() netproxy.StateEvent {
	return s.pool().Snapshot()
}

func (s *Mux) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return s.pool().WatchState(ctx)
}

func (s *Mux) Connect(ctx context.Context) error {
	return s.pool().Connect(ctx)
}

func (s *Mux) establish(ctx context.Context) (*sessionResource, error) {
	conn, err := s.Dialer.DialContext(ctx, "tcp", "sp.mux.sing-box.arpa:444")
	if err != nil {
		return nil, err
	}
	netproxy.CaptureDependency(ctx, conn)
	_, err = common.Invoke(ctx, func() (any, error) {
		return conn.Write([]byte{Version0, byte(s.Protocol)})
	}, func() {
		_ = conn.Close()
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	monitored := &monitoredConn{Conn: conn, failed: make(chan error, 1)}
	session, err := newSession(s.Protocol, monitored)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &sessionResource{session: session, monitor: monitored}, nil
}

func (s *Mux) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	if network == "udp" && s.PassthroughUdp {
		return s.Dialer.DialContext(ctx, network, addr)
	}
	switch network {
	case "tcp":
		stream, err := s.pool().OpenStream(ctx)
		if err != nil {
			return nil, err
		}
		return &Conn{Conn: stream, layer: s.Protocol.layer(), addr: addr}, nil
	case "udp":
		conn, err := s.ListenPacket(ctx, addr)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{
			PacketConn: conn,
			Address:    netproxy.NewAddr("udp", addr),
		}, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *Mux) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	if s.PassthroughUdp {
		return s.Dialer.ListenPacket(ctx, addr)
	}
	stream, err := s.pool().OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	if leased, ok := stream.(*leasedStream); ok {
		if smux, ok := leased.Conn.(*smuxStream); ok {
			return newSmuxPacketConn(leased, smux, s.Protocol.layer(), addr)
		}
	}
	return &UDPConn{Conn: Conn{Conn: stream, layer: s.Protocol.layer(), addr: addr, udp: true, packetAddr: true}}, nil
}

func (s *Mux) observe(ctx context.Context, handle *netproxy.SingleSessionHandle[*sessionResource]) {
	resource := handle.Resource()
	select {
	case <-ctx.Done():
		return
	case <-resource.session.CloseChan():
	case <-resource.monitor.failed:
	}
	cause := resource.cause()
	if cause == nil {
		cause = net.ErrClosed
	}
	fact := netproxy.ClassifyFailure(cause)
	fact.Resource, fact.Scope = handle.Ref(), netproxy.ScopeSharedResource
	if fact.Layer == netproxy.LayerUnknown {
		fact.Layer = s.Protocol.layer()
	}
	handle.Abort(netproxy.WrapFailure(cause, fact))
}

func (s *Mux) Close() error {
	return s.pool().Close()
}
