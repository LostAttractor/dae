package shadowsocks

import (
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func (c *TCPConn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }
func (c *TCPConn) WriteThrough() net.Conn           { return c.Conn }
func (c *UdpConn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }
