package tls

import (
	"crypto/tls"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	utls "github.com/refraction-networking/utls"
)

// Keep the concrete TLS methods (including CloseWrite) while exposing the
// tunnel used for this handshake to shared sessions above TLS.
type leasedTLSConn struct {
	*tls.Conn
	lease *netproxy.Lease
}

func (c *leasedTLSConn) DependencyLease() *netproxy.Lease { return c.lease }
func (c *leasedTLSConn) TLSConn() net.Conn                { return c.Conn }
func (c *leasedTLSConn) NegotiatedProtocol() string       { return c.ConnectionState().NegotiatedProtocol }

type leasedUTLSConn struct {
	*utls.UConn
	lease *netproxy.Lease
}

func (c *leasedUTLSConn) DependencyLease() *netproxy.Lease { return c.lease }
func (c *leasedUTLSConn) TLSConn() net.Conn                { return c.UConn }
func (c *leasedUTLSConn) NegotiatedProtocol() string       { return c.ConnectionState().NegotiatedProtocol }
func (c *FragmentConn) DependencyLease() *netproxy.Lease   { return netproxy.DependencyOf(c.Conn) }
func (c *RealityUConn) DependencyLease() *netproxy.Lease   { return c.lease }
func (c *RealityUConn) TLSConn() net.Conn                  { return c.UConn }
func (c *RealityUConn) NegotiatedProtocol() string         { return c.ConnectionState().NegotiatedProtocol }
