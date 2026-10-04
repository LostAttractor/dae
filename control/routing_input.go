// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

// routingResult adds userspace process identity to the compact kernel decision.
// Ingress does not publish PID/comm; internal daemon requests supply them here.
// Only bpfRoutingResult is serialized to or from BPF maps.
type routingResult struct {
	bpfRoutingResult
	Pid   uint32
	Pname [16]byte
}

func retrieveRoutingResult(m *ebpf.Map, src, dst netip.AddrPort, l4proto uint8) (*routingResult, error) {
	tuples := bpfTuplesKey{
		Sport:   common.Htons(src.Port()),
		Dport:   common.Htons(dst.Port()),
		L4proto: l4proto,
	}
	tuples.Sip.U6Addr8 = src.Addr().As16()
	tuples.Dip.U6Addr8 = dst.Addr().As16()

	var handoff bpfRoutingHandoff
	var err error
	if l4proto == unix.IPPROTO_TCP {
		err = m.LookupAndDelete(&tuples, &handoff)
	} else {
		err = m.Lookup(&tuples, &handoff)
	}
	if err != nil {
		return nil, fmt.Errorf("reading map: key [%v, %v, %v]: %w", src.String(), l4proto, dst.String(), err)
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return nil, err
	}
	if int32(handoff.Expires-uint32(now.Sec)) <= 0 {
		return nil, fmt.Errorf("routing handoff expired")
	}
	return &routingResult{bpfRoutingResult: handoff.Result}, nil
}

// routingInput carries the flow properties shared by routing and destination
// predicates. profileID is local to the selected configuration generation; zero
// selects this matcher's default for callers without a kernel routing context.
type routingInput struct {
	src, dst           netip.AddrPort
	l4proto            consts.L4ProtoType
	domain             string
	processName        [16]byte
	ifindex, profileID uint32
	physinif           uint32
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
func (r *routingResult) routingInput(src, dst netip.AddrPort, domain string, protocol consts.L4ProtoType) routingInput {
	return routingInput{
		src: src, dst: dst, domain: domain, l4proto: protocol,
		processName: r.Pname, ifindex: r.Ifindex, profileID: r.ProfileId,
		physinif: r.Physinif,
		dscp:     r.Dscp, mac: r.Mac,
	}
}

func (p *RouteParam) routingInput(domain string, destination netip.AddrPort) routingInput {
	return p.routingResult.routingInput(p.Src, destination, domain, p.networkType.L4Proto.ToL4ProtoType())
}
