// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"github.com/daeuniverse/dae/common/consts"
	"net/netip"
)

// routingInput carries flow properties shared by routing and destination predicates.
type routingInput struct {
	sourceAddr, destAddr, mac []byte
	sourcePort, destPort      uint16
	ipVersion                 consts.IpVersionType
	l4proto                   consts.L4ProtoType
	domain                    string
	processName               [16]uint8
	ifindex                   uint32
	tos                       uint8
	trustedDomainBitmap       [][]uint32
	afterTarget               bool
}

// Copy ingress identity once; callers supply the target and requested protocol.
func (r *bpfRoutingResult) routingInput(src, dst netip.AddrPort, domain string, protocol consts.L4ProtoType) routingInput {
	source, destination := src.Addr().As16(), dst.Addr().As16()
	var mac [16]byte
	copy(mac[10:], r.Mac[:])
	return routingInput{sourceAddr: source[:], destAddr: destination[:], sourcePort: src.Port(), destPort: dst.Port(),
		ipVersion: consts.IpVersionFromAddr(dst.Addr()), l4proto: protocol, domain: domain, processName: r.Pname, ifindex: r.Ifindex, tos: r.Dscp, mac: mac[:]}
}

func (p *RouteParam) routingInput(domain string, destination netip.AddrPort) routingInput {
	return p.routingResult.routingInput(p.Src, destination, domain, p.networkType.L4Proto.ToL4ProtoType())
}
