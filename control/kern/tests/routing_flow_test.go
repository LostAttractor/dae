//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
)

func TestRoutingDomainShortCircuit(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	packet, ctx, key := routingFlowPacket(t, obj)
	port := binary.BigEndian.Uint16(packet[36:38])
	invalidDomain := obj.RoutingMap.MaxEntries()
	for _, tc := range []struct {
		name   string
		first  bpftestMatchSet
		second bpftestMatchSet
		want   uint32
	}{
		{"OR hit skips invalid domain", routingPortRule(port, consts.MatchActionOr, 0), routingDomainRule(invalidDomain, consts.MatchActionRoute, consts.OutboundDirect), ^uint32(0)},
		{"AND miss skips invalid domain", routingPortRule(1, consts.MatchActionAnd, 0), routingDomainRule(invalidDomain, consts.MatchActionRoute, consts.OutboundBlock), ^uint32(0)},
		{"OR miss evaluates invalid domain", routingPortRule(1, consts.MatchActionOr, 0), routingDomainRule(invalidDomain, consts.MatchActionRoute, consts.OutboundDirect), 2},
		{"AND hit evaluates invalid domain", routingPortRule(port, consts.MatchActionAnd, 0), routingDomainRule(invalidDomain, consts.MatchActionRoute, consts.OutboundDirect), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installRoutingFlow(t, obj, []bpftestMatchSet{tc.first, tc.second, {Type: uint8(consts.MatchType_Fallback)}})
			for _, program := range []*ebpf.Program{obj.LanIngressL2, obj.TproxyWanEgressL2} {
				status, _, _, err := runBpfProgram(program, packet, ctx)
				if err != nil || status != tc.want {
					t.Fatalf("%s: status=%d want=%d err=%v", program, status, tc.want, err)
				}
				var route bpftestRoutingResult
				if err := lookupHandoff(obj.RoutingTuplesMap, key, &route); !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("direct or rejected packet created proxy state: %+v, %v", route, err)
				}
			}
		})
	}
}

func TestRoutingShortCircuitActionBoundaries(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	packet, ctx, key := routingFlowPacket(t, obj)
	port, invalidDomain := binary.BigEndian.Uint16(packet[36:38]), obj.RoutingMap.MaxEntries()
	var domain bpftestDomainRouting
	domain.Bump[0] = 1 << 1 // An ambiguous match must not short-circuit a later OR hit.
	if err := obj.DomainRoutingMap.Update(key.Dip.U6Addr8, domain, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	direct := bpftestMatchSet{Type: uint8(consts.MatchType_Fallback)}
	marked := direct
	marked.Mark = 37
	negated := routingDomainRule(invalidDomain, consts.MatchActionRoute, consts.OutboundBlock)
	negated.Flags = 1
	negatedAnd := negated
	negatedAnd.Action = uint8(consts.MatchActionAnd)
	capture := routingDomainRule(invalidDomain, consts.MatchActionCapture, 0)
	capture.Flags = 2 << 3
	flowEnd := bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionFlowEnd)}
	for _, tc := range []struct {
		name          string
		rules         []bpftestMatchSet
		mark          uint32
		must, capture uint8
		bump          bool
	}{
		{
			name: "OR tail applies NOT",
			rules: []bpftestMatchSet{
				routingPortRule(port, consts.MatchActionOr, 0), negated, direct,
			},
		},
		{
			name: "OR success still evaluates next AND",
			rules: []bpftestMatchSet{
				routingPortRule(port, consts.MatchActionOr, 0),
				routingDomainRule(invalidDomain, consts.MatchActionAnd, 0),
				routingPortRule(1, consts.MatchActionRoute, consts.OutboundBlock), direct,
			},
		},
		{
			name: "failed AND skips later successful OR",
			rules: []bpftestMatchSet{
				routingPortRule(1, consts.MatchActionAnd, 0),
				routingPortRule(port, consts.MatchActionOr, 0),
				routingDomainRule(invalidDomain, consts.MatchActionRoute, consts.OutboundBlock), direct,
			},
		},
		{
			name: "failed rule does not skip next capture",
			rules: []bpftestMatchSet{
				routingPortRule(1, consts.MatchActionAnd, 0),
				routingDomainRule(invalidDomain, consts.MatchActionRoute, consts.OutboundBlock),
				{Type: uint8(consts.MatchType_Fallback), Flags: 2 << 3, Action: uint8(consts.MatchActionCapture)}, marked,
			},
			bump: true, capture: 2,
		},
		{
			name: "OR capture tail preserves earlier must",
			rules: []bpftestMatchSet{
				{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionMust)},
				routingPortRule(port, consts.MatchActionOr, 0), capture, flowEnd, marked,
			},
			bump: true, must: 1, capture: 2,
		},
		{
			name: "OR capture tail accumulates earlier capture",
			rules: []bpftestMatchSet{
				{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionCapture), Flags: 1 << 3},
				routingPortRule(port, consts.MatchActionOr, 0), capture, marked,
			},
			bump: true, capture: 3,
		},
		{
			name: "failed AND skips capture tail",
			rules: []bpftestMatchSet{
				routingPortRule(1, consts.MatchActionAnd, 0), capture, marked,
			},
			mark: 37,
		},
		{
			name: "OR tail applies must",
			rules: []bpftestMatchSet{
				routingPortRule(port, consts.MatchActionOr, 0),
				routingDomainRule(invalidDomain, consts.MatchActionMust, 0), flowEnd, marked,
			},
			mark: 37, must: 1,
		},
		{
			name: "OR tail applies bump",
			rules: []bpftestMatchSet{
				routingPortRule(port, consts.MatchActionOr, 0),
				routingDomainRule(invalidDomain, consts.MatchActionBump, 0), flowEnd, marked,
			},
			bump: true,
		},
		{
			name: "ambiguous OR becomes definite",
			rules: []bpftestMatchSet{
				routingDomainRule(1, consts.MatchActionOr, 0),
				{Type: uint8(consts.MatchType_Fallback), Mark: 37},
				{Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundBlock)},
			},
			mark: 37,
		},
		{
			name: "ambiguous AND later fails",
			rules: []bpftestMatchSet{
				routingDomainRule(1, consts.MatchActionAnd, 0),
				routingPortRule(1, consts.MatchActionRoute, consts.OutboundBlock), direct,
			},
		},
		{
			name: "failed AND clears earlier ambiguity before next rule",
			rules: []bpftestMatchSet{
				routingDomainRule(1, consts.MatchActionAnd, 0),
				routingPortRule(1, consts.MatchActionAnd, 0), capture, marked,
			},
			mark: 37,
		},
		{
			name: "negated OR hit skips capture after AND tail",
			rules: []bpftestMatchSet{
				routingPortRule(port, consts.MatchActionOr, 0), negatedAnd, capture, marked,
			},
			mark: 37,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installRoutingFlow(t, obj, tc.rules)
			want := ^uint32(0)
			if tc.capture != 0 || tc.bump {
				want = 7
			}
			for _, program := range []*ebpf.Program{obj.LanIngressL2, obj.TproxyWanEgressL2} {
				if err := obj.RoutingTuplesMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatal(err)
				}
				status, _, _, err := runBpfProgram(program, packet, ctx)
				if err != nil || status != want {
					t.Fatalf("%s: status=%d want=%d err=%v", program, status, want, err)
				}
				var route bpftestRoutingResult
				err = lookupHandoff(obj.RoutingTuplesMap, key, &route)
				if tc.capture == 0 && !tc.bump {
					if !errors.Is(err, ebpf.ErrKeyNotExist) {
						t.Fatalf("kernel direct created proxy state: %+v, %v", route, err)
					}
					assertDirectTCPFlow(t, obj, key, tc.mark)
					continue
				}
				outbound := uint8(consts.OutboundDirect)
				if tc.bump {
					outbound = uint8(consts.OutboundControlPlaneRouting)
				}
				if err != nil || route.Outbound != outbound || route.Mark != tc.mark || route.Must != tc.must || route.CaptureFlags != tc.capture {
					t.Fatalf("rule boundary lost outbound/mark/must/capture: %+v, %v", route, err)
				}
			}
		})
	}
}

func TestRoutingJumpBounds(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	packet, ctx, _ := routingFlowPacket(t, obj)
	port := binary.BigEndian.Uint16(packet[36:38])
	for _, tc := range []struct {
		name      string
		distance  uint32
		action    consts.MatchAction
		matchPort uint16
		want      uint32
	}{
		{"OR zero distance fails closed", 0, consts.MatchActionOr, port, 2},
		{"AND zero distance fails closed", 0, consts.MatchActionAnd, 1, 2},
		{"OR relative jump follows profile order", 1, consts.MatchActionOr, port, ^uint32(0)},
		{"AND relative jump follows profile order", 2, consts.MatchActionAnd, 1, ^uint32(0)},
		{"AND jump clears clause state before target evaluation", 1, consts.MatchActionAnd, 1, 2},
		{"OR beyond profile length fails closed", 3, consts.MatchActionOr, port, 2},
		{"AND beyond profile length fails closed", 3, consts.MatchActionAnd, 1, 2},
		{"OR outside instruction pool fails closed", 65535, consts.MatchActionOr, port, 2},
		{"AND outside instruction pool fails closed", 65535, consts.MatchActionAnd, 1, 2},
		{"OR addition cannot wrap to earlier terminal", ^uint32(0), consts.MatchActionOr, port, 2},
		{"AND addition cannot wrap to earlier rule", ^uint32(0), consts.MatchActionAnd, 1, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := routingPortRule(tc.matchPort, tc.action, 0)
			first.Mark = tc.distance
			rules := []bpftestMatchSet{
				// Start the jump at PC 1. An overflowing OR jump to PC 0
				// would carry HIT into this otherwise missed direct terminal.
				routingPortRule(1, consts.MatchActionRoute, consts.OutboundDirect),
				first,
				routingDomainRule(obj.RoutingMap.MaxEntries(), consts.MatchActionRoute, consts.OutboundDirect),
				{Type: uint8(consts.MatchType_Fallback)},
			}
			// Physical pool order is deliberately unrelated to execution order.
			profile := bpftestRoutingProfile{Length: 4}
			for i, index := range []uint16{333, 101, 5, 700} {
				profile.Steps[i] = index
				if err := obj.RoutingMap.Update(uint32(index), rules[i], ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			}
			if err := obj.RoutingProfileMap.Update(uint32(0), profile, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			for _, program := range []*ebpf.Program{obj.LanIngressL2, obj.TproxyWanEgressL2} {
				status, _, _, err := runBpfProgram(program, packet, ctx)
				if err != nil || status != tc.want {
					t.Fatalf("%s: status=%d want=%d err=%v", program, status, tc.want, err)
				}
			}
		})
	}
}

func TestRoutingShortCircuitTailLookup(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	packet, ctx, key := routingFlowPacket(t, obj)
	port := binary.BigEndian.Uint16(packet[36:38])
	for _, tc := range []struct {
		name      string
		action    consts.MatchAction
		matchPort uint16
		distance  uint32
		want      uint32
	}{
		{"AND miss skips unreadable terminal", consts.MatchActionAnd, 1, 2, ^uint32(0)},
		{"AND hit needs terminal", consts.MatchActionAnd, port, 2, 2},
		{"OR hit needs subrule tail", consts.MatchActionOr, port, 1, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := routingPortRule(tc.matchPort, tc.action, 0)
			first.Mark = tc.distance
			if err := obj.RoutingMap.Update(uint32(101), first, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			if err := obj.RoutingMap.Update(uint32(700), bpftestMatchSet{Type: uint8(consts.MatchType_Fallback)}, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			// The rule tail has no valid physical instruction. An AND miss
			// must skip the lookup itself, not merely suppress its predicate.
			profile := bpftestRoutingProfile{Length: 3}
			profile.Steps[0], profile.Steps[1], profile.Steps[2] = 101, uint16(obj.RoutingMap.MaxEntries()), 700
			if err := obj.RoutingProfileMap.Update(uint32(0), profile, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			for _, program := range []*ebpf.Program{obj.LanIngressL2, obj.TproxyWanEgressL2} {
				status, _, _, err := runBpfProgram(program, packet, ctx)
				if err != nil || status != tc.want {
					t.Fatalf("%s: status=%d want=%d err=%v", program, status, tc.want, err)
				}
				var route bpftestRoutingResult
				if err := lookupHandoff(obj.RoutingTuplesMap, key, &route); !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("direct or rejected packet created proxy state: %+v, %v", route, err)
				}
			}
		})
	}
}

// Domain IDs do not equal physical instruction positions. Replacing and removing
// the mapping between packets must immediately affect both LAN and WAN routing.
func TestRoutingDomainLookupLifetime(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	packet, ctx, key := routingFlowPacket(t, obj)
	second := routingDomainRule(65, consts.MatchActionRoute, consts.OutboundDirect)
	second.Mark, second.Flags = 37, 1<<1
	installRoutingFlow(t, obj, []bpftestMatchSet{
		routingDomainRule(1, consts.MatchActionRoute, consts.OutboundBlock),
		second,
		{Type: uint8(consts.MatchType_Fallback)},
	})
	for _, tc := range []struct {
		name    string
		bit     int
		missing bool
		want    uint32
		mark    uint32
	}{
		{"missing", -1, true, ^uint32(0), 0},
		{"unrelated", 32, false, ^uint32(0), 0},
		{"second ID", 65, false, ^uint32(0), 37},
		{"first ID", 1, false, 2, 0},
		{"replaced", 65, false, ^uint32(0), 37},
		{"empty", -1, false, ^uint32(0), 0},
		{"removed", -1, true, ^uint32(0), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.missing {
				if err := obj.DomainRoutingMap.Delete(key.Dip.U6Addr8); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatal(err)
				}
			} else {
				var domain bpftestDomainRouting
				if tc.bit >= 0 {
					domain.Routing[tc.bit/32] = 1 << (tc.bit % 32)
					domain.Bump[tc.bit/32] = domain.Routing[tc.bit/32]
				}
				if err := obj.DomainRoutingMap.Update(key.Dip.U6Addr8, domain, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			}
			for _, program := range []*ebpf.Program{obj.LanIngressL2, obj.TproxyWanEgressL2} {
				if err := obj.RoutingTuplesMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatal(err)
				}
				status, _, _, err := runBpfProgram(program, packet, ctx)
				if err != nil || status != tc.want {
					t.Fatalf("%s: status=%d want=%d err=%v", program, status, tc.want, err)
				}
				var route bpftestRoutingResult
				err = lookupHandoff(obj.RoutingTuplesMap, key, &route)
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("unexpected proxy state: %+v, %v", route, err)
				}
				if tc.want == ^uint32(0) {
					assertDirectTCPFlow(t, obj, key, tc.mark)
				}
			}
		})
	}
}
