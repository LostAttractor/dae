package shadowsocks

import "github.com/daeuniverse/dae/pkg/outbound/netproxy"

func (c *TCPConn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }
func (c *UdpConn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }
