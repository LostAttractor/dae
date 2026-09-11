// SPDX-License-Identifier: AGPL-3.0-only
package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func parseStructuredTestConfig(t *testing.T, text string) *config.Config {
	t.Helper()
	sections, err := config_parser.Parse("global {}\nrouting {\n" + text + "\n}")
	if err != nil {
		t.Fatal(err)
	}
	conf, err := config.New(sections)
	if err != nil {
		t.Fatal(err)
	}
	return conf
}

func TestStructuredGeneratedFragmentSharesCaptureAndPreservesPolicy(t *testing.T) {
	conf := parseStructuredTestConfig(t, `
 rule_set { shared { client(gaming) -> proxy } }
  use: shared
 fallback: direct(mark: 10)
 policy { lan {
 use: shared
 fallback: block(mark: 20) }
tunnel {
 use: shared
 fallback: proxy(mark: 30) } }
 interface { br-lan: lan
wg0: tunnel }`)
	// Preparation's context is cancelled by errgroup.Wait before compilation.
	ctx, cancel := context.WithCancel(context.Background())
	prepared, err := prepareRoutingRules(ctx, &conf.Routing, nil)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	prepared.enableMITMPlan(mitmRoutingPlugin("service0.example").Plan())
	for i := range 100 {
		prepared.destinations = append(prepared.destinations, routing.DestinationRewrite{
			Filter: []*config_parser.Function{{Name: "domain", Params: []*config_parser.Param{{Key: "full", Val: fmt.Sprintf("service%d.example", i)}}}},
			To:     []netip.Addr{netip.MustParseAddr("198.51.100.10")},
		})
	}
	prepared.bypassAPI(8081, []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}})
	b, err := prepared.compileRouting(map[string]uint8{"direct": 0, "block": 1, "proxy": 2}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 3 API matches + 100 destination captures + 4 scoped HTTP conditions
	// + FlowEnd + 1 shared client + 3 fallbacks + 200 userspace instructions.
	if len(b.rules) != 312 {
		t.Fatalf("physical rules = %d, want 312", len(b.rules))
	}
	captures := 0
	for _, rule := range b.rules {
		if ((rule.Flags >> 3) & 3) != 0 {
			captures++
		}
	}
	if captures != 101 {
		t.Fatalf("capture predicates = %d, want 101", captures)
	}
	for _, profile := range b.profiles {
		if profile.Spans[0].Start != 0 || spanExecutionLen(profile.Spans) != 110 {
			t.Fatalf("profile did not share preamble: %+v", profile)
		}
	}
	m, err := b.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	for _, member := range []bool{false, true, false} {
		var members [][6]byte
		if member {
			members = append(members, mac)
		}
		if err := b.SetClientMembers(m, "gaming", members, false); err != nil {
			t.Fatal(err)
		}
		for index, profile := range b.profiles {
			id := profile.ID
			src := netip.MustParseAddr("192.0.2.1")
			dst := netip.MustParseAddr("203.0.113.1")
			got, mark, _, err := m.match(routingInput{
				src:       netip.AddrPortFrom(src, 1234),
				dst:       netip.AddrPortFrom(dst, 443),
				l4proto:   consts.L4ProtoType_TCP,
				domain:    "service42.example",
				ifindex:   7,
				profileID: id,
				mac:       mac,
			})
			want, wantMark := consts.OutboundIndex(index), uint32(index+1)*10
			if member {
				want, wantMark = 2, 0
			}
			if err != nil || got != want || mark != wantMark {
				t.Fatalf("profile %d member %v = %v/%d, %v", id, member, got, mark, err)
			}
			p := &RouteParam{Src: netip.MustParseAddrPort("192.0.2.1:1234"), Dest: netip.MustParseAddrPort("203.0.113.1:443"), Domain: "service42.example", routingResult: &bpfRoutingResult{Ifindex: 7, ProfileId: id, Mac: mac}, networkType: *common.NetworkTCP4.NetworkType()}
			decision, err := m.matchDestination(p)
			if err != nil || !decision.IsValid() || decision.String() != "198.51.100.10:443" {
				t.Fatalf("profile %d destination = %+v, %v", id, decision, err)
			}
			api := netip.MustParseAddr("10.0.0.1")
			got, _, _, err = m.match(routingInput{
				src:       netip.AddrPortFrom(src, 1234),
				dst:       netip.AddrPortFrom(api, 8081),
				l4proto:   consts.L4ProtoType_TCP,
				ifindex:   7,
				profileID: id,
				mac:       mac,
			})
			if err != nil || got != consts.OutboundDirect {
				t.Fatalf("API bypass profile %d: %v, %v", id, got, err)
			}
		}
	}
	if _, _, _, err := m.match(routingInput{
		src:       netip.AddrPortFrom(netip.IPv4Unspecified(), 1),
		dst:       netip.AddrPortFrom(netip.IPv4Unspecified(), 1),
		l4proto:   consts.L4ProtoType_TCP,
		ifindex:   7,
		profileID: 999,
	}); err == nil {
		t.Fatal("unknown profile silently used default")
	}
}

func TestStructuredSharedDomainUsesSharedBitmapID(t *testing.T) {
	conf := parseStructuredTestConfig(t, `
 rule_set { domains { domain(full: service.example) -> proxy } }
  dport(80) -> block
 use: domains
 fallback: direct
 policy { lan {
 use: domains
 fallback: block } }
 interface { br-lan: lan }
 `)
	b, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0, "block": 1, "proxy": 2}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := b.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.IPv4Unspecified()
	bitmap := m.domainMatcher.MatchDomainBitmap("service.example")
	for _, id := range []uint32{b.defaultProfileID, b.profileIDPlan.ids["lan"]} {
		for _, trusted := range []bool{false, true} {
			var trustedBitmap []uint32
			domain := "service.example"
			if trusted {
				trustedBitmap = bitmap
				domain = ""
			}
			got, _, _, err := m.match(routingInput{
				src:          netip.AddrPortFrom(addr, 1),
				dst:          netip.AddrPortFrom(addr, 443),
				l4proto:      consts.L4ProtoType_TCP,
				domain:       domain,
				ifindex:      7,
				profileID:    id,
				domainBitmap: trustedBitmap,
			})
			if err != nil || got != 2 {
				t.Fatalf("profile %d bitmap %v = %v, %v", id, trusted, got, err)
			}
		}
	}
}

func TestRoutingModulePriorityInEveryProfile(t *testing.T) {
	conf := parseStructuredTestConfig(t, `
 rule_set { user {
 domain(full: api.biliapi.com) -> direct(mark: 10)
 domain(full: api.cloudflare.com) -> block(mark: 20)
 } }
  use: user
 fallback: proxy(mark: 30)
 policy { lan {
 use: user
 fallback: direct(mark: 40) } }
 interface { br-lan: lan }
 `)
	prepared := preparedRules{routing: &conf.Routing}
	plan := mitmRoutingPlugin("api.cloudflare.com").Plan()
	plan.EarlyRoutes = planRulesForTest(t, "domain(full: api.biliapi.com) -> block")
	plan.Routes = planRulesForTest(t, "domain(full: api.cloudflare.com) -> direct\ndomain(keyword: api.) -> block")
	prepared.enableMITMPlan(plan)
	builder, err := compileTestRouting(prepared, map[string]uint8{"direct": 0, "block": 1, "proxy": 2}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	for index, profile := range builder.profiles {
		id := profile.ID
		for _, test := range []struct {
			host     string
			outbound consts.OutboundIndex
			mark     uint32
		}{
			// Module pre-matching rules precede explicit user routes.
			{"api.biliapi.com", 1, 0},
			// Ordinary module routes follow explicit user routes.
			{"api.cloudflare.com", 1, 20},
			// They still precede each profile's fallback.
			{"api.other.example", 1, 0},
			{"unmatched.example", consts.OutboundIndex(2 - index*2), uint32(30 + index*10)},
		} {
			got, mark, _, err := matcher.match(routingInput{
				src:    netip.MustParseAddrPort("192.0.2.1:12345"),
				dst:    netip.MustParseAddrPort("198.51.100.1:443"),
				domain: test.host, l4proto: consts.L4ProtoType_TCP, profileID: id,
			})
			if err != nil || got != test.outbound || mark != test.mark {
				t.Fatalf("profile %d host %s: got %d/%d, %v; want %d/%d", id, test.host, got, mark, err, test.outbound, test.mark)
			}
		}
	}
}

func TestFailedStructuredCandidateDoesNotConsumeProfileIDs(t *testing.T) {
	conf := parseStructuredTestConfig(t, ` fallback: direct  policy { lan {
 fallback: direct } }
 interface { br-lan: lan }`)
	state := &BPFState{}
	first, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0}, state, nil)
	if err != nil {
		t.Fatal(err)
	}
	state.routingProfileIDs = *first.profileIDPlan // Commit the first successful generation.
	conf.Routing.Interfaces[0].Policy = "failed"
	conf.Routing.Policies[1].Name = "failed"
	conf.Routing.Policies[1].Fallback.Name = "missing"
	if _, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0}, state, nil); err == nil {
		t.Fatal("invalid candidate accepted")
	}
	if _, ok := state.routingProfileIDs.ids["failed"]; ok {
		t.Fatal("failed candidate consumed identity")
	}
	conf.Routing.Interfaces[0].Policy = "next"
	conf.Routing.Policies[1].Name = "next"
	conf.Routing.Policies[1].Fallback.Name = "direct"
	next, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0}, state, nil)
	if err != nil {
		t.Fatal(err)
	}
	if next.profileIDPlan.ids["next"] != 3 {
		t.Fatalf("next identity = %d", next.profileIDPlan.ids["next"])
	}
}

func TestProfileSeparatesDNSReroutes(t *testing.T) {
	source := netip.MustParseAddrPort("192.0.2.1:1234")
	c := &ControlPlane{}
	a, _, err := c.dnsRequest(nil, "udp", source, netip.MustParseAddrPort("192.0.2.53:53"), bpfRoutingResult{Ifindex: 7, ProfileId: 1})
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := c.dnsRequest(nil, "udp", source, netip.MustParseAddrPort("192.0.2.53:53"), bpfRoutingResult{Ifindex: 7, ProfileId: 2})
	if err != nil {
		t.Fatal(err)
	}
	if a.ContextKey == b.ContextKey {
		t.Fatal("DNS reroutes coalesce across profiles")
	}

}

func TestStructuredCollectsTargetsInAllBlocks(t *testing.T) {
	conf := parseStructuredTestConfig(t, `
 rule_set { unused { dport(80) -> node_a } }
 policy { unused { fallback: group_a } }
  fallback: node_b
 policy { lan {
 dport(443) -> node_c
 fallback: group_b } }
 interface { br-lan: lan }
 `)
	names := collectRoutingTargetNames(&conf.Routing)
	if !slices.Equal(names, []string{"node_a", "node_b", "group_a", "node_c", "group_b"}) {
		t.Fatalf("routing targets = %v", names)
	}
}

func TestStructuredUnusedInterfacePredicateIsValidated(t *testing.T) {
	for _, name := range []string{"", "bad/name", "space name", "1234567890123456"} {
		conf := parseStructuredTestConfig(t, `rule_set { unused { interface(`+config_parser.QuoteLiteral(name)+`) -> direct } }  fallback: direct `)
		if _, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0}, nil, nil); err == nil {
			t.Fatalf("accepted invalid interface %q in unused fragment", name)
		}
	}
}
