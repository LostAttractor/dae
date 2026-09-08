// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
)

// routingInput carries the flow properties shared by routing and destination
// predicates. profileID is the stable identity selected by the kernel; zero
// selects this matcher's default for callers without a kernel routing context.
type routingInput struct {
	src, dst           netip.AddrPort
	l4proto            consts.L4ProtoType
	domain             string
	processName        [16]byte
	ifindex, profileID uint32
	dscp               uint8
	mac                [6]byte
	domainBitmap       []uint32
	// Tests can model the kernel's uncertain domain matches explicitly.
	domainBumpBitmap []uint32
	kernel           bool
	// The destination has already been selected. Start at FlowProgram, keeping
	// API bypass and destination capture tied to the original ingress tuple.
	stage routingStage
}

type routingStage uint8

const (
	routeFromIngress routingStage = iota
	routeAfterTarget
)

// Copy ingress identity once; callers supply the target and requested protocol.
func (r *bpfRoutingResult) routingInput(src, dst netip.AddrPort, domain string, protocol consts.L4ProtoType) routingInput {
	return routingInput{
		src: src, dst: dst, domain: domain, l4proto: protocol,
		processName: r.Pname, ifindex: r.Ifindex, profileID: r.ProfileId,
		dscp: r.Dscp, mac: r.Mac,
	}
}

func (p *RouteParam) routingInput(domain string, destination netip.AddrPort) routingInput {
	return p.routingResult.routingInput(p.Src, destination, domain, p.networkType.L4Proto.ToL4ProtoType())
}
