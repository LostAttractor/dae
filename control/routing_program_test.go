// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestFlowProgramDefersUncertainMust(t *testing.T) {
	for _, laterMust := range []bool{false, true} {
		controls := `domain(full: one.example) -> must`
		if laterMust {
			controls += "\ndport(443) -> must"
		}
		prepared := prepareFlowRulesForTest(t, controls, "dport(443) -> direct(mark:37)")
		prepared.enableMITMPlan(mitmRoutingPlugin("one.example").Plan())
		m, _ := routingMatcherForTest(t, prepared)
		first := m.domainMatcher.MatchDomainBitmap("one.example")
		second := m.domainMatcher.MatchDomainBitmap("two.example")
		bump, trusted := make([]uint32, len(first)), make([]uint32, len(first))
		for i := range first {
			bump[i], trusted[i] = first[i]|second[i], first[i]&second[i]
		}
		address := netip.IPv4Unspecified()
		result, err := m.evaluateSpans(m.profiles[m.defaultProfileID], routingInput{
			src: netip.AddrPortFrom(address, 12345), dst: netip.AddrPortFrom(address, 443),
			l4proto:      consts.L4ProtoType_TCP,
			domainBitmap: trusted, domainBumpBitmap: bump,
		})
		want, mark := consts.OutboundControlPlaneRouting, uint32(0)
		if laterMust {
			want, mark = consts.OutboundDirect, 37
		}
		if err != nil || result.outbound != want || result.mark != mark || result.must != laterMust || result.captureFlags != captureHTTP {
			t.Fatalf("later must=%v: %+v, %v", laterMust, result, err)
		}
	}
}

func TestRoutingProgramsSharePredicateResources(t *testing.T) {
	prepared := prepareFlowRulesForTest(t, `
domain(full: one.example, full: two.example) -> must
domain(full: two.example, full: one.example) -> bump
domain(full: one.example, full: two.example) && sip(192.0.2.3/24) -> dnat(198.51.100.20)
domain(full: one.example, full: two.example) && dip(192.0.2.0/24) -> dnat(198.51.100.21)`, `
!domain(full: two.example, full: one.example) -> block`)
	_, b := routingMatcherForTest(t, prepared)
	if len(b.simulatedDomainSet) != 1 || len(b.simulatedLpmTries) != 1 || b.kernelLpmLen != 1 {
		t.Fatalf("duplicate predicate resources: domains=%d lpm=%d kernel_lpm=%d", len(b.simulatedDomainSet), len(b.simulatedLpmTries), b.kernelLpmLen)
	}
	for _, rule := range b.rules {
		if rule.Type == uint8(consts.MatchType_DomainSet) && binary.LittleEndian.Uint32(rule.Value[:]) != 0 {
			t.Fatal("domain ID depends on the instruction position")
		}
		if rule.Outbound >= uint8(consts.OutboundMustRules) {
			t.Fatal("instruction/control action leaked into outbound ID")
		}
	}
	if len(b.destination.predicates) != 2 || int(b.destination.predicates[0].span.Start) < b.routing.end || b.rules[b.flow.end-1].Action != uint8(consts.MatchActionFlowEnd) {
		t.Fatal("invalid flow/routing/destination boundaries")
	}
	if b.destination.start != 0 || b.destination.end != b.flow.start || b.flow.end != b.routing.start {
		t.Fatal("program order must be destination -> flow -> routing")
	}
	for i, rule := range b.rules[:b.routing.end] {
		if ((rule.Flags>>3)&3)&captureDestination != 0 && (i < b.destination.start || i >= b.destination.end) {
			t.Fatal("destination capture must precede flow controls")
		}
		if rule.Action == uint8(consts.MatchActionMust) || rule.Action == uint8(consts.MatchActionBump) || ((rule.Flags>>3)&3)&captureHTTP != 0 {
			if i < b.flow.start || i >= b.flow.end {
				t.Fatal("flow control escaped its program")
			}
		}
	}
}

func TestDestinationPredicatesDoNotConsumeKernelInstructions(t *testing.T) {
	var rules strings.Builder
	// Each rule needs one capture instruction and two userspace instructions.
	// The old combined budget rejected this valid kernel program.
	count := consts.MaxMatchSetLen * 3 / 5
	for i := range count {
		fmt.Fprintf(&rules, "dport(%d) -> dnat(198.51.100.20)\n", i+1)
	}
	_, b := destinationTestMatcher(t, rules.String())
	if b.routing.end != count+1 || len(b.rules) <= consts.MaxMatchSetLen || len(b.destination.predicates) != count || b.flow.start != b.flow.end {
		t.Fatalf("unexpected program sizes: kernel=%d all=%d destinations=%d", b.routing.end, len(b.rules), len(b.destination.predicates))
	}
}

func TestDestinationInterfaceUpdateStaysInUserspace(t *testing.T) {
	_, b := destinationTestMatcher(t, "interface(lan0) -> dnat(198.51.100.20)")
	// No BPF handles exist in this test. Updating the destination half of an
	// interface predicate must neither access nor publish a kernel table slot.
	i := int(b.destination.predicates[0].span.Start)
	if err := b.updateIfindex(i, 42, true); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(b.rules[i].Value[:]) != 42 || b.rules[i].Action != uint8(consts.MatchActionMatch) {
		t.Fatal("interface update replaced the destination action")
	}
}
