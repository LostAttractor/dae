// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestRoutingInterfaceBridgeMember(t *testing.T) {
	for _, test := range []struct {
		name, predicate string
		ifindex, member uint32
		port            uint16
		match           bool
	}{
		{"bridge", "interface(br-lan)", 7, 8, 443, true},
		{"member", "interface(lan)", 7, 8, 443, true},
		{"other member", "interface(lan)", 7, 9, 443, false},
		{"absent metadata", "interface(lan)", 7, 0, 443, false},
		{"unresolved", "interface(missing)", 7, 0, 443, false},
		{"no identity", "interface(missing)", 0, 0, 443, false},
		{"multi value", "interface(direct,lan)", 7, 8, 443, true},
		{"negated member", "!interface(lan)", 7, 8, 443, false},
		{"negated bridge", "!interface(br-lan)", 7, 8, 443, false},
		{"negated multi value", "!interface(direct,lan)", 7, 8, 443, false},
		{"negated miss", "!interface(direct)", 7, 8, 443, true},
		{"both identities", "interface(br-lan) && interface(lan)", 7, 8, 443, true},
		{"wrong port", "interface(lan)", 7, 8, 22, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			matcher, builder := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", test.predicate+" && dport(443) -> proxy(mark:37)"))
			indices := map[string]uint32{"br-lan": 7, "lan": 8, "direct": 9}
			for _, patch := range builder.interfaceRulePatches {
				if err := builder.updateIfindex(patch.matchIndex, indices[patch.ifname], false); err != nil {
					t.Fatal(err)
				}
			}
			identity := routingResult{Ifindex: test.ifindex, Physinif: test.member}
			input := identity.routingInput(netip.MustParseAddrPort("192.0.2.2:40001"), netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), test.port), "", consts.L4ProtoType_TCP)
			outbound, mark, _, err := matcher.match(input)
			want, wantMark := consts.OutboundDirect, uint32(0)
			if test.match {
				want, wantMark = consts.OutboundUserDefinedMin, 37
			}
			if err != nil || outbound != want || mark != wantMark {
				t.Fatalf("route: outbound=%d mark=%d err=%v, want=%d/%d", outbound, mark, err, want, wantMark)
			}
		})
	}
}
