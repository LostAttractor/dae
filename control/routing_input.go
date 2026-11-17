// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	"golang.org/x/sys/unix"
)

// routingResult adds process identity to the compact kernel decision. The
// kernel handoff carries the sending local process name; internal daemon
// requests also supply their PID. Only bpfRoutingResult is stored in BPF caches.
type routingResult struct {
	bpfRoutingResult
	Pid   uint32
	Pname [16]byte
	dns   *dnsPacket
}

func (r *routingResult) sourceOrigin() plugin.SourceOrigin {
	// The kernel ABI uses 0/1/2; unrecognized values stay unknown, never local.
	switch r.SourceOrigin {
	case 1:
		return plugin.SourceLocal
	case 2:
		return plugin.SourceLAN
	default:
		return plugin.SourceUnknown
	}
}

func tuplesKey(src, dst netip.AddrPort, l4proto uint8) bpfTuplesKey {
	tuples := bpfTuplesKey{
		Sport:   common.Htons(src.Port()),
		Dport:   common.Htons(dst.Port()),
		L4proto: l4proto,
	}
	tuples.Sip.U6Addr8 = src.Addr().As16()
	tuples.Dip.U6Addr8 = dst.Addr().As16()
	return tuples
}

func handoffLive(handoff *bpfRoutingHandoff) (bool, error) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return false, err
	}
	return int32(handoff.Expires-uint32(now.Sec)) > 0, nil
}

func retrieveRoutingResult(m *ebpf.Map, src, dst netip.AddrPort, l4proto uint8) (*routingResult, error) {
	tuples := tuplesKey(src, dst, l4proto)
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
	if live, err := handoffLive(&handoff); err != nil {
		return nil, err
	} else if !live {
		return nil, fmt.Errorf("routing handoff expired")
	}
	return &routingResult{bpfRoutingResult: handoff.Result, Pname: handoff.Pname}, nil
}

// routingInput carries the flow properties shared by routing and destination
// predicates. profileID is local to the selected configuration generation; zero
// selects this matcher's default for callers without a kernel routing context.
type routingInput struct {
	wanEgress          bool
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
	// The destination has already been selected. Skip ingress spans, keeping
	// API bypass and destination capture tied to the original ingress tuple.
	stage routingStage
	trace *routingExecution
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
		physinif: r.Physinif, wanEgress: r.sourceOrigin() != plugin.SourceLAN,
		dscp: r.Dscp, mac: r.Mac,
	}
}

func (p *RouteParam) routingInput(domain string, destination netip.AddrPort) routingInput {
	return p.routingResult.routingInput(p.Src, destination, domain, p.networkType.L4Proto.ToL4ProtoType())
}

// targetInput is shared by live routing and its explanation. Explicit targets
// own their logical identity; an IP literal never borrows a retained DNS name.
func (input routingInput) targetInput(domain string, explicit bool, bump, routing []uint32) routingInput {
	input.kernel, input.stage, input.domain = false, routeAfterTarget, domain
	input.domainBitmap, input.domainBumpBitmap = nil, nil
	if domain == "" && !explicit {
		input.domainBumpBitmap, input.domainBitmap = bump, routing
	}
	return input
}
