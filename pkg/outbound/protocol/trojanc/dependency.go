package trojanc

import "github.com/daeuniverse/dae/pkg/outbound/netproxy"

func (c *Conn) DependencyLease() *netproxy.Lease       { return netproxy.DependencyOf(c.Conn) }
func (c *PacketConn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }
