// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestCompiledRoutingJumpsSurviveFragmentReuseAndInterfaceUpdates(t *testing.T) {
	conf := parseStructuredTestConfig(t, `
 rule_set { shared { !dport(80,443) && interface(lan0,lan1) -> proxy(mark:0x1234) } }
 use: shared
 fallback: direct(mark:11)
 policy { lan {
  dport(22) -> block
  use: shared
  fallback: direct(mark:22)
 } }
 interface { br-lan:lan }
`)
	b, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0, "block": 1, "proxy": 2}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Two OR subrules, joined by AND, occupy four shared instructions. Only
	// their terminal may retain a packet mark; relative edges stay inside it.
	want := []uint32{1, 3, 1}
	for i, distance := range want {
		if b.rules[i].Mark != distance {
			t.Fatalf("instruction %d: got %+v, want tail distances %#x", i, b.rules[i], distance)
		}
	}
	if b.rules[3].Mark != 0x1234 {
		t.Fatalf("terminal mark overwritten: %+v", b.rules[3])
	}
	m, err := b.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	for _, patch := range b.interfaceRulePatches {
		before := b.rules[patch.matchIndex]
		if err := b.updateIfindex(patch.matchIndex, 7, false); err != nil {
			t.Fatal(err)
		}
		after := b.rules[patch.matchIndex]
		if before.Mark != after.Mark || before.Flags != after.Flags || before.Action != after.Action {
			t.Fatal("interface resolution overwrote instruction control metadata")
		}
	}
	for _, test := range []struct {
		profile  uint32
		port     uint16
		outbound consts.OutboundIndex
		mark     uint32
	}{
		{b.defaultProfileID, 445, 2, 0x1234},
		{b.profiles[1].ID, 445, 2, 0x1234},
		{b.defaultProfileID, 443, 0, 11},
		{b.profiles[1].ID, 443, 0, 22},
		{b.profiles[1].ID, 22, 1, 0},
	} {
		outbound, mark, _, err := m.match(routingInput{
			src:     netip.MustParseAddrPort("192.0.2.1:12345"),
			dst:     netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), test.port),
			l4proto: consts.L4ProtoType_TCP, ifindex: 7, profileID: test.profile,
		})
		if err != nil || outbound != test.outbound || mark != test.mark {
			t.Fatalf("profile=%d port=%d: got %v/%d, %v", test.profile, test.port, outbound, mark, err)
		}
	}
}

// Evaluate the source expression independently of instruction traversal:
// three AND clauses, each containing two OR atoms, with all truth values and
// all NOT combinations. Unknown domains must never commit terminal mark/must.
func TestRoutingThreeValuedExpressions(t *testing.T) {
	rules := make([]bpfMatchSet, 7)
	for i := range rules[:6] {
		rules[i] = bpfMatchSet{Type: uint8(consts.MatchType_DomainSet), Action: uint8(consts.MatchActionOr)}
		binary.LittleEndian.PutUint32(rules[i].Value[:], uint32(i))
		if i%2 == 1 {
			rules[i].Action = uint8(consts.MatchActionAnd)
		}
	}
	rules[5].Action, rules[5].Outbound, rules[5].Mark = uint8(consts.MatchActionRoute), uint8(consts.OutboundBlock), 37
	rules[6] = bpfMatchSet{Type: uint8(consts.MatchType_Fallback), Mark: 11}
	if err := encodeRoutingJumps(rules); err != nil {
		t.Fatal(err)
	}
	m := &RoutingMatcher{matches: rules}
	spans := []routingSpan{{End: uint32(len(rules))}}
	input := routingInput{src: netip.MustParseAddrPort("192.0.2.1:12345"), dst: netip.MustParseAddrPort("198.51.100.1:443"), l4proto: consts.L4ProtoType_TCP, kernel: true}
	for not := 0; not < 8; not++ {
		for j := 0; j < 3; j++ {
			rules[2*j+1].Flags = routingMatchFlags(not&(1<<j) != 0, j == 2, false)
		}
		for values := 0; values < 729; values++ {
			var atoms [6]int // 0=false, 1=unknown, 2=true.
			trusted, uncertain := uint32(0), uint32(0)
			encoded := values
			for i := range atoms {
				atoms[i], encoded = encoded%3, encoded/3
				if atoms[i] == 2 {
					trusted |= 1 << i
				} else if atoms[i] == 1 {
					uncertain |= 1 << i
				}
			}
			truth := 2
			for j := 0; j < 3; j++ {
				clause := 0
				if atoms[2*j] == 2 || atoms[2*j+1] == 2 {
					clause = 2
				} else if atoms[2*j] == 1 || atoms[2*j+1] == 1 {
					clause = 1
				}
				if not&(1<<j) != 0 {
					clause = 2 - clause
				}
				if clause == 0 {
					truth = 0
					break
				}
				if clause == 1 {
					truth = 1
				}
			}
			input.domainBitmap, input.domainBumpBitmap = []uint32{trusted}, []uint32{uncertain}
			got, err := m.evaluateSpans(spans, input)
			want := []routingEvaluation{
				{outbound: consts.OutboundDirect, mark: 11},
				{outbound: consts.OutboundControlPlaneRouting},
				{outbound: consts.OutboundBlock, mark: 37, must: true},
			}[truth]
			if err != nil || got != want {
				t.Fatalf("NOT=%03b values=%d: %+v, %v; want %+v", not, values, got, err, want)
			}
		}
	}
}

func TestUserspaceRoutingRejectsInvalidJumps(t *testing.T) {
	for _, action := range []consts.MatchAction{consts.MatchActionOr, consts.MatchActionAnd} {
		for _, distance := range []uint32{0, 3, ^uint32(0)} {
			typeID := consts.MatchType_Fallback // OR hits; AND misses.
			if action == consts.MatchActionAnd {
				typeID = consts.MatchType_Port
			}
			m := &RoutingMatcher{matches: []bpfMatchSet{
				{Type: uint8(typeID), Action: uint8(action), Mark: distance},
				{Type: uint8(consts.MatchType_Fallback)},
			}}
			_, err := m.evaluateSpans([]routingSpan{{End: 2}}, routingInput{src: netip.MustParseAddrPort("192.0.2.1:12345"), dst: netip.MustParseAddrPort("198.51.100.1:443")})
			if err == nil {
				t.Fatalf("accepted action %d jump %d", action, distance)
			}
		}
	}
}
