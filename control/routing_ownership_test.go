// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

func TestRoutingReusesOnlyUnchangedDomainSets(t *testing.T) {
	b := newRoutingMatcherBuilder(nil, nil, nil)
	b.simulatedDomainSet = []routing.DomainSet{{Key: consts.RoutingDomainKey_Suffix, RuleIndex: 0, Domains: []string{"example.com"}}}
	first, err := b.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.buildUserspace(first)
	if err != nil || second.domainMatcher != first.domainMatcher || second.routingState == first.routingState {
		t.Fatalf("immutable matcher reuse or mutable state isolation failed: %v", err)
	}
	b.simulatedDomainSet[0].Domains[0] = "other.test"
	third, err := b.buildUserspace(first)
	if err != nil || third.domainMatcher == first.domainMatcher {
		t.Fatalf("changed predicates reused stale matcher: %v", err)
	}
	if !bitmapHas(first.domainMatcher.MatchDomainBitmap("example.com"), 0) || bitmapHas(third.domainMatcher.MatchDomainBitmap("example.com"), 0) {
		t.Fatal("rebuilt matcher or compiler changed an installed domain set")
	}
}

func BenchmarkRoutingDomainRebuild(b *testing.B) {
	builder := newRoutingMatcherBuilder(nil, nil, nil)
	domains := make([]string, 2048)
	for i := range domains {
		domains[i] = fmt.Sprintf("d%d.example.com", i)
	}
	builder.simulatedDomainSet = []routing.DomainSet{{Key: consts.RoutingDomainKey_Suffix, RuleIndex: 0, Domains: domains}}
	previous, err := builder.BuildUserspace()
	if err != nil {
		b.Fatal(err)
	}
	for _, reuse := range []bool{false, true} {
		b.Run(fmt.Sprintf("reuse=%t", reuse), func(b *testing.B) {
			var old *RoutingMatcher
			if reuse {
				old = previous
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := builder.buildUserspace(old); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestBuiltRoutingOwnsInterfaceBindings(t *testing.T) {
	first, builder := buildInterfaceRoutingMatcher(t)
	second, err := builder.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	if err := first.updateIfindex(0, 7, false); err != nil {
		t.Fatal(err)
	}
	if matchIfindex(t, first, 7) != consts.OutboundUserDefinedMin || matchIfindex(t, second, 7) != consts.OutboundDirect {
		t.Fatal("independent builds share interface bindings")
	}
	if builder.rules[0].Value != [16]byte{} {
		t.Fatal("runtime binding mutated compilation")
	}
	builder.rules[0].Outbound = uint8(consts.OutboundBlock)
	if matchIfindex(t, first, 7) != consts.OutboundUserDefinedMin {
		t.Fatal("compiler mutated an installed program")
	}
}

func TestBuiltRoutingOwnsClientMembership(t *testing.T) {
	builder, first := buildClientMatcher(t, clientRule("work", false, "proxy"))
	second, err := builder.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	if err := first.SetClientMembers("work", [][6]byte{mac}, false); err != nil {
		t.Fatal(err)
	}
	requireClientRoute(t, first, mac, 443, consts.OutboundUserDefinedMin)
	requireClientRoute(t, second, mac, 443, consts.OutboundDirect)
	if len(builder.simulatedLpmTries[builder.clientSetSlots["work"]]) != 0 {
		t.Fatal("membership mutated compilation")
	}
}

func TestDestinationSnapshotOwnsInterfaceBindings(t *testing.T) {
	live, builder := destinationTestMatcher(t, "interface(test0) -> dnat(198.51.100.20)")
	update := func(index uint32) {
		for _, patch := range builder.interfaceRulePatches {
			if err := live.updateIfindex(patch.matchIndex, index, false); err != nil {
				t.Error(err)
			}
		}
	}
	update(7)
	frozen := live.snapshotDestinations()
	p := &RouteParam{Src: netip.MustParseAddrPort("192.0.2.1:40000"), Dest: netip.MustParseAddrPort("192.0.2.2:443"), routingResult: &routingResult{Ifindex: 7}, networkType: *common.NetworkTCP4.NetworkType()}
	var worker sync.WaitGroup
	worker.Go(func() {
		for range 1000 {
			update(9)
			update(7)
		}
	})
	for range 1000 {
		got, err := frozen.matchDestination(p)
		if err != nil || got != netip.MustParseAddrPort("198.51.100.20:443") {
			t.Errorf("live interface update changed UDP lifetime: %s, %v", got, err)
			break
		}
	}
	worker.Wait()
}

func TestRoutingReusesOnlyUnchangedStaticTries(t *testing.T) {
	b := newRoutingMatcherBuilder(nil, nil, nil)
	b.simulatedLpmTries = [][]netip.Prefix{{netip.MustParsePrefix("192.0.2.0/24")}, {netip.MustParsePrefix("2001:db8::/32")}, {netip.MustParsePrefix("198.51.100.0/24")}}
	b.clientSetSlots["dynamic"] = 2
	first, err := b.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	b.simulatedLpmTries[1] = []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/48")}
	second, err := b.buildUserspace(first)
	if err != nil {
		t.Fatal(err)
	}
	if second.lpmMatcher[0] != first.lpmMatcher[0] || second.lpmMatcher[1] == first.lpmMatcher[1] || second.lpmMatcher[2] == first.lpmMatcher[2] {
		t.Fatal("static reuse did not isolate changed predicates and dynamic membership")
	}
	ip := netip.MustParseAddr("2001:db8:2::1").As16()
	if !first.lpmMatcher[1].HasPrefixIP(ip) || second.lpmMatcher[1].HasPrefixIP(ip) {
		t.Fatal("rebuild changed the old predicate")
	}
	if err := first.SetClientMembers("dynamic", [][6]byte{{2, 0, 0, 0, 0, 1}}, false); err != nil {
		t.Fatal(err)
	}
	if !second.lpmMatcher[2].HasPrefixIP(netip.MustParseAddr("198.51.100.1").As16()) {
		t.Fatal("membership update changed successor")
	}
	// A slot changing from dynamic to static must not reuse predecessor state.
	delete(b.clientSetSlots, "dynamic")
	b.simulatedLpmTries[2] = first.simulatedLpmTries[2]
	third, err := b.buildUserspace(first)
	if err != nil {
		t.Fatal(err)
	}
	if third.lpmMatcher[2] == first.lpmMatcher[2] {
		t.Fatal("reused a previous dynamic slot")
	}
}

func BenchmarkRoutingLPMRebuild(b *testing.B) {
	builder := newRoutingMatcherBuilder(nil, nil, nil)
	prefixes := make([]netip.Prefix, 4096)
	for i := range prefixes {
		prefixes[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)
	}
	builder.simulatedLpmTries = [][]netip.Prefix{prefixes}
	previous, err := builder.BuildUserspace()
	if err != nil {
		b.Fatal(err)
	}
	for _, reuse := range []bool{false, true} {
		b.Run(fmt.Sprintf("reuse=%t", reuse), func(b *testing.B) {
			var old *RoutingMatcher
			if reuse {
				old = previous
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := builder.buildUserspace(old); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
