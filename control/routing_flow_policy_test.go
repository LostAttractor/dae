// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
)

const policyFlowFixture = `
rule_set {
 common {
  client(work) && dport(443) -> dnat('198.51.100.20:8443')
  dip(198.51.100.20) && dport(8443) -> must
 }
 gated { sip(192.0.2.0/24) -> use(common) }
 controls {
  dport(53) -> must
  dport(9443) -> bump
 }
 dormant { interface(dormant0) -> dnat(203.0.113.20) }
}
policy {
 main {
  rules { use: gated, controls }
  dip(192.0.2.20) && dport(443) -> block
  dip(198.51.100.20) && dport(8443) -> proxy(mark:37)
  fallback: direct
 }
 copy {
  rules { use: gated }
  fallback: direct
 }
 tor {
  dport(443) -> direct(mark:9)
  fallback: direct
 }
 inactive { rules { use: dormant } fallback: direct }
}
default: main
interface { tor0: tor copy0: copy }
`

func flowPolicyIDs(m *RoutingMatcher) map[string]uint32 {
	ids := make(map[string]uint32)
	for _, profile := range m.profileInfo {
		ids[profile.Name] = profile.ID
	}
	return ids
}

func TestPolicyFlowIsolationAndSharedPrograms(t *testing.T) {
	conf := parseStructuredTestConfig(t, policyFlowFixture)
	m, b := routingMatcherForTest(t, preparedRules{routing: &conf.Routing})
	ids := flowPolicyIDs(m)
	mac := [6]byte{2, 0, 0, 0, 0, 10}
	if err := b.SetClientMembers(m, "work", [][6]byte{mac}, false); err != nil {
		t.Fatal(err)
	}
	main, shared := m.destinationProgram(ids["main"]), m.destinationProgram(ids["copy"])
	if len(main.predicates) != 1 || len(shared.predicates) != 1 || main.predicates[0].span != shared.predicates[0].span || len(m.destinationProgram(ids["tor"]).predicates) != 0 {
		t.Fatal("destination programs were duplicated or leaked across policies")
	}
	if len(b.interfaceRulePatches) != 0 {
		t.Fatal("inactive flow rules registered live interface patches")
	}
	for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
		for _, tc := range []struct {
			policy   string
			port     uint16
			outbound consts.OutboundIndex
			flags    uint8
			mark     uint32
			must     bool
		}{
			{"main", 443, consts.OutboundControlPlaneRouting, captureDestination, 0, false},
			{"copy", 443, consts.OutboundControlPlaneRouting, captureDestination, 0, false},
			{"tor", 443, consts.OutboundDirect, 0, 9, false},
			{"main", 53, consts.OutboundDirect, 0, 0, true},
			{"tor", 53, consts.OutboundDirect, 8, 0, false},
			{"main", 9443, consts.OutboundControlPlaneRouting, 0, 0, false},
			{"tor", 9443, consts.OutboundDirect, 0, 0, false},
			{"main", 80, consts.OutboundDirect, 0, 0, false},
		} {
			input := routingInput{src: netip.MustParseAddrPort("192.0.2.10:40000"), dst: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.20"), tc.port), l4proto: proto, mac: mac, profileID: ids[tc.policy], kernel: true}
			result, err := m.evaluateSpans(m.profiles[input.profileID], input)
			if err != nil || result.outbound != tc.outbound || result.captureFlags != tc.flags || result.mark != tc.mark || result.must != tc.must {
				t.Fatalf("policy=%s port=%d proto=%d: %+v, %v", tc.policy, tc.port, proto, result, err)
			}
		}
	}
	for _, name := range []string{"main", "copy", "tor"} {
		param := RouteParam{Src: netip.MustParseAddrPort("192.0.2.10:40000"), Dest: netip.MustParseAddrPort("192.0.2.20:443"), routingResult: &routingResult{ProfileId: ids[name], Mac: mac}, networkType: *common.NetworkTCP4.NetworkType()}
		target, err := m.matchDestination(&param)
		if err != nil {
			t.Fatal(err)
		}
		want := netip.MustParseAddrPort("198.51.100.20:8443")
		if name == "tor" {
			want = netip.AddrPort{}
		}
		if target != want {
			t.Fatalf("%s selected target %v, want %v", name, target, want)
		}
		param.destination = target
		input := param.routingInput("", param.effectiveDestination())
		input.stage = routeAfterTarget
		outbound, mark, must, err := m.match(input)
		wantOutbound, wantMark := consts.OutboundDirect, uint32(0)
		if name == "main" {
			wantOutbound, wantMark = consts.OutboundUserDefinedMin, 37
		}
		if name == "tor" {
			wantMark = 9
		}
		if err != nil || outbound != wantOutbound || mark != wantMark || must != (name != "tor") || param.Dest.String() != "192.0.2.20:443" || param.routingResult.ProfileId != ids[name] {
			t.Fatalf("%s did not route the effective target with original identity: %v,%d,%v,%v", name, outbound, mark, must, err)
		}
	}
	// The exact predicate receives the conditional use filter as well.
	param := RouteParam{Src: netip.MustParseAddrPort("203.0.113.10:40000"), Dest: netip.MustParseAddrPort("192.0.2.20:443"), routingResult: &routingResult{ProfileId: ids["main"], Mac: mac}, networkType: *common.NetworkTCP4.NetworkType()}
	if target, err := m.matchDestination(&param); err != nil || target.IsValid() {
		t.Fatalf("conditional use leaked: %v, %v", target, err)
	}
	param.routingResult.ProfileId = 999
	if _, err := m.matchDestination(&param); err == nil {
		t.Fatal("unknown policy used another policy's target rules")
	}
}

func TestPolicyFlowUDPSnapshotRetainsPolicyAndMembership(t *testing.T) {
	conf := parseStructuredTestConfig(t, policyFlowFixture)
	m, b := routingMatcherForTest(t, preparedRules{routing: &conf.Routing})
	ids := flowPolicyIDs(m)
	mac := [6]byte{2, 0, 0, 0, 0, 10}
	if err := b.SetClientMembers(m, "work", [][6]byte{mac}, false); err != nil {
		t.Fatal(err)
	}
	frozen := m.snapshotDestinations()
	if err := b.SetClientMembers(m, "work", nil, false); err != nil {
		t.Fatal(err)
	}
	m.defaultProfileID = ids["tor"]
	for _, policy := range []string{"main", "tor"} {
		param := RouteParam{Src: netip.MustParseAddrPort("192.0.2.10:40000"), Dest: netip.MustParseAddrPort("192.0.2.20:443"), routingResult: &routingResult{ProfileId: ids[policy], Mac: mac}, networkType: *common.NetworkUDP4.NetworkType()}
		endpoint := UdpEndpoint{destinationMatcher: frozen, destinationParam: param, destinations: make(map[netip.AddrPort]netip.AddrPort)}
		other := netip.MustParseAddrPort("192.0.2.21:443")
		target, err := endpoint.socketTarget(other)
		want := other
		if policy == "main" {
			want = netip.MustParseAddrPort("198.51.100.20:8443")
		}
		if err != nil || target != want {
			t.Fatalf("old %s association: %v, %v; want %v", policy, target, err, want)
		}
		if current, err := m.matchDestination(&param); err != nil || current.IsValid() {
			t.Fatalf("new %s association ignored membership update: %v, %v", policy, current, err)
		}
	}
}

func TestPolicyFlowPluginDestinationsRemainGlobal(t *testing.T) {
	conf := parseStructuredTestConfig(t, `policy {
 main { rules { dport(443) -> dnat(198.51.100.20) } fallback: direct }
 tor { fallback: direct }
} default: main interface { tor0: tor }`)
	prepared := preparedRules{routing: &conf.Routing, destinations: destinationRulesForTest(t, "dport(443) -> dnat(203.0.113.20)")}
	m, _ := routingMatcherForTest(t, prepared)
	for name, id := range flowPolicyIDs(m) {
		param := RouteParam{Src: netip.MustParseAddrPort("192.0.2.10:40000"), Dest: netip.MustParseAddrPort("192.0.2.20:443"), routingResult: &routingResult{ProfileId: id}, networkType: *common.NetworkTCP4.NetworkType()}
		target, err := m.matchDestination(&param)
		want := "203.0.113.20:443"
		if name == "main" {
			want = "198.51.100.20:443"
		}
		if err != nil || target.String() != want {
			t.Fatalf("%s target=%v, %v; want %s", name, target, err, want)
		}
		input := param.routingInput("", param.Dest)
		input.kernel = true
		decision, err := m.evaluateSpans(m.profiles[id], input)
		if err != nil || decision.captureFlags != captureDestination {
			t.Fatalf("%s lost destination capture: %+v, %v", name, decision, err)
		}
	}
}

func TestPolicyFlowDiagnosticsUseSelectedProgram(t *testing.T) {
	conf := parseStructuredTestConfig(t, policyFlowFixture)
	c := diagnosticPreparedPlane(t, preparedRules{routing: &conf.Routing})
	request := diagnosticRequest()
	request.Flow.Destination.IP = "192.0.2.20"
	request.Flow.SNI = new("")
	request.Compare = &api.DiagnosticAssumptions{ClientSets: map[string]bool{"work": true}}
	for _, name := range []string{"main", "tor"} {
		request.Context.Policy = name
		response, err := c.Explain(t.Context(), request, false)
		if err != nil {
			t.Fatal(err)
		}
		decision := response.Compared.Decision
		want := "192.0.2.20:443"
		if name == "main" {
			want = "198.51.100.20:8443"
		}
		if !decision.Complete || len(decision.Targets) != 1 || decision.Targets[0] != want {
			t.Fatalf("%s explanation: %+v", name, response)
		}
		for _, step := range response.Compared.Steps {
			if step.Section == "rules" && step.Status != "inactive" && step.Policy != name {
				t.Fatalf("%s attributed another policy's rule: %+v", name, step)
			}
		}
	}
	impact, err := c.ClientImpact(t.Context(), "work", api.ClientImpactRequest{Context: diagnosticRequest().Context, Joined: new(true)}, false)
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]int)
	for _, step := range impact.Rules {
		if step.Section != "rules" || step.Policy == "" {
			t.Fatalf("policy flow reference is global: %+v", step)
		}
		counts[step.Policy]++
	}
	if counts["main"] != 1 || counts["copy"] != 1 || len(counts) != 2 {
		t.Fatalf("shared flow references: %v", counts)
	}
}

func TestPolicyFlowUnusedPredicatesStillValidate(t *testing.T) {
	for _, body := range []string{
		`rule_set { unused { unknown_predicate(x) -> bump } } fallback: direct`,
		`policy { unused { rules { dport(70000) -> must } fallback: direct } } fallback: direct`,
		`rule_set { empty {} } policy { unused { rules { unknown_predicate(x) -> use(empty) } fallback: direct } } fallback: direct`,
	} {
		conf := parseStructuredTestConfig(t, body)
		_, err := compileTestRouting(preparedRules{routing: &conf.Routing}, map[string]uint8{"direct": 0}, nil, nil)
		if err == nil || strings.Contains(err.Error(), "unknown outbound") {
			t.Fatalf("unused flow validation: %v", err)
		}
	}
}
