// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net"
	"net/netip"

	"github.com/daeuniverse/dae/common"
)

// Each rewritten UDP association owns a socket and a fixed destination. This
// keeps replies unambiguous even if multiple original IPs map to the same peer.
type destinationPacketConn struct {
	net.PacketConn
	original, target netip.AddrPort
}

func (c *destinationPacketConn) WriteTo(data []byte, _ net.Addr) (int, error) {
	return c.PacketConn.WriteTo(data, net.UDPAddrFromAddrPort(c.target))
}

func (c *destinationPacketConn) ReadFrom(data []byte) (int, net.Addr, error) {
	for {
		n, from, err := c.PacketConn.ReadFrom(data)
		if err != nil {
			return n, from, err
		}
		if common.ConvergeAddrPort(addrPortOf(from)) == c.target {
			return n, net.UDPAddrFromAddrPort(c.original), nil
		}
	}
}
