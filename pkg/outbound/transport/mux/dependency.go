package mux

import "github.com/daeuniverse/dae/pkg/outbound/netproxy"

func (c *Conn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }
