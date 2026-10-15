//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
)

func TestRoutingConditionalBlocks(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	packet, ctx, key := routingFlowPacket(t, obj)
	var domains bpftestDomainRouting
	domains.Bump[0], domains.Routing[0] = 1, 2 // ID 0 ambiguous, 1 true, 2 false.
	if err := obj.DomainRoutingMap.Update(key.Dip.U6Addr8, domains, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	jump := func(id, distance uint32) bpftestMatchSet {
		rule := routingDomainRule(id, consts.MatchActionConditionalJump, 0)
		rule.Mark = distance
		return rule
	}
	miss := routingPortRule(1, consts.MatchActionRoute, 0)
	marked := bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Mark: 37}
	must := bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionMust)}
	flowEnd := bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Action: uint8(consts.MatchActionFlowEnd)}
	invalid := routingDomainRule(obj.RoutingMap.MaxEntries(), consts.MatchActionRoute, 0)
	for _, tc := range []struct {
		name  string
		rules []bpftestMatchSet
		bump  bool
		must  uint8
	}{
		{"miss skips unreadable body", []bpftestMatchSet{jump(2, 2), invalid, marked}, false, 0},
		{"AND miss skips jump tail and body", []bpftestMatchSet{routingDomainRule(2, consts.MatchActionAnd, 0), jump(0, 2), invalid, marked}, false, 0},
		{"ambiguous unused scope", []bpftestMatchSet{jump(0, 2), miss, marked}, false, 0},
		{"ambiguity survives failed first rule", []bpftestMatchSet{jump(0, 3), miss, marked, marked}, true, 0},
		{"inner ambiguity expires", []bpftestMatchSet{jump(1, 4), jump(0, 2), miss, marked, marked}, false, 0},
		{"outer ambiguity survives inner scope", []bpftestMatchSet{jump(0, 4), jump(1, 2), miss, marked, marked}, true, 0},
		{"nested ambiguity preserves outer end", []bpftestMatchSet{jump(0, 4), jump(0, 2), miss, marked, marked}, true, 0},
		{"missed inner jump preserves outer end", []bpftestMatchSet{jump(0, 4), jump(2, 2), invalid, marked, marked}, true, 0},
		{"ambiguous must survives scope end", []bpftestMatchSet{jump(0, 2), must, flowEnd, marked}, true, 0},
		{"later definite must resolves ambiguity", []bpftestMatchSet{jump(0, 2), must, must, flowEnd, marked}, false, 1},
		{"jump retains preceding AND ambiguity", []bpftestMatchSet{routingDomainRule(0, consts.MatchActionAnd, 0), jump(1, 2), marked, marked}, true, 0},
		{"OR hit resolves jump ambiguity", []bpftestMatchSet{routingDomainRule(0, consts.MatchActionOr, 0), jump(1, 2), marked, marked}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installRoutingFlow(t, obj, tc.rules)
			for _, program := range []*ebpf.Program{obj.LanIngressL2, obj.TproxyWanEgressL2} {
				_ = obj.RoutingTuplesMap.Delete(key)
				status, _, output, err := runBpfProgram(program, packet, ctx)
				want := ^uint32(0)
				if tc.bump {
					want = 7
				}
				if err != nil || status != want {
					t.Fatalf("%s: status=%d want=%d err=%v", program, status, want, err)
				}
				if tc.bump {
					var result bpftestRoutingResult
					if err := lookupHandoff(obj.RoutingTuplesMap, key, &result); err != nil || result.Outbound != uint8(consts.OutboundControlPlaneRouting) || result.Mark != 0 || result.Must != tc.must {
						t.Fatalf("handoff=%+v err=%v", result, err)
					}
				} else if binary.NativeEndian.Uint32(output[8:12]) != 37 {
					t.Fatal("lost definite route mark")
				}
			}
		})
	}
}
