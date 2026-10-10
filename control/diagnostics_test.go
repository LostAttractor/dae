// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"encoding/json/v2"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/settings"
)

func diagnosticPlane(t *testing.T, rules, controls string) *ControlPlane {
	t.Helper()
	prepared := prepareFlowRulesForTest(t, controls, rules)
	matcher, builder := routingMatcherForTest(t, prepared)
	store, err := settings.Open(filepath.Join(t.TempDir(), "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &ControlPlane{routingMatcher: matcher, routingState: builder.routingState, routingMatcherBuilder: builder, settings: store, routingGeneration: 7, sniffVerifyMode: consts.SniffVerifyMode_None, core: &controlPlaneCore{domainRegistry: newRoutingDomainRegistry()}}
}

func diagnosticRequest() api.ExplainRequest {
	return api.ExplainRequest{Context: api.DiagnosticContext{Origin: "lan", SourceIP: "192.0.2.10", SourcePort: new(40000), MAC: "02:00:00:00:00:10", IfIndex: new(uint32(0)), PhysicalIfIndex: new(uint32(0)), DSCP: new(0)}, Flow: api.DiagnosticFlow{Protocol: "tcp", Destination: api.DiagnosticTarget{IP: "198.51.100.10", Port: 443}}, Detail: "predicates"}
}

func TestDiagnosticsKernelEvidenceDoesNotBorrowSNI(t *testing.T) {
	c := diagnosticPlane(t, "domain(full: target.example) -> block", "")
	request := diagnosticRequest()
	request.Flow.SNI = new("target.example")
	response, err := c.Explain(t.Context(), request, false)
	if err != nil || !response.Current.Decision.Complete || response.Current.Decision.Verdict != "kernel_direct" {
		t.Fatalf("SNI without mapping: %+v, %v", response, err)
	}
	request.Compare = &api.DiagnosticAssumptions{Bindings: []api.DiagnosticBinding{{IP: request.Flow.Destination.IP, Domains: []string{"target.example"}}}}
	response, err = c.Explain(t.Context(), request, false)
	if err != nil || response.Compared.Decision.Verdict != "drop" || response.Current.Decision.Verdict != "kernel_direct" {
		t.Fatalf("assumed mapping: %+v, %v", response, err)
	}
	if usage := c.core.domainRegistry.Usage(); usage.UserUsed != 0 || usage.KernelUsed != 0 {
		t.Fatal("diagnostics published assumed DNS evidence")
	}
}

func TestDiagnosticsMembershipComparisonIsPrivate(t *testing.T) {
	c := diagnosticPlane(t, "client(work) && dport(443) -> block\n!client(work) && dport(80) -> block", "")
	request := diagnosticRequest()
	request.Compare = &api.DiagnosticAssumptions{ClientSets: map[string]bool{"work": true}}
	before := slices.Clone(c.routingMatcher.matches)
	response, err := c.Explain(t.Context(), request, false)
	if err != nil || response.Current.Decision.Verdict != "kernel_direct" || response.Compared.Decision.Verdict != "drop" {
		t.Fatalf("membership: %+v, %v", response, err)
	}
	if len(c.settings.Members("work")) != 0 || !reflect.DeepEqual(before, c.routingMatcher.matches) {
		t.Fatal("comparison changed live state")
	}
	impact, err := c.ClientImpact(t.Context(), "work", api.ClientImpactRequest{Context: request.Context, Joined: new(true), Flow: &request.Flow}, false)
	if err != nil || len(impact.Rules) != 2 || impact.Rules[0].Conditions[0].Expected != "true" || impact.Rules[1].Conditions[0].Expected != "false" {
		t.Fatalf("impact: %+v, %v", impact, err)
	}
}

func TestDiagnosticsMissingContextCannotSelectFallback(t *testing.T) {
	for _, test := range []struct {
		rule     string
		complete bool
	}{{"sport(40000) -> block", false}, {"sport(40000) && dport(22) -> block", true}, {"dport(443) -> direct\nsport(40000) -> block", true}} {
		t.Run(test.rule, func(t *testing.T) {
			c := diagnosticPlane(t, test.rule, "")
			request := diagnosticRequest()
			request.Context.SourcePort = nil
			response, err := c.Explain(t.Context(), request, false)
			if err != nil || response.Current.Decision.Complete != test.complete {
				t.Fatalf("%+v %v", response, err)
			}
			if !test.complete && (response.Current.Decision.Verdict != "unknown" || !slices.Contains(response.Current.Decision.Missing, "source_port")) {
				t.Fatalf("fabricated zero source port: %+v", response.Current)
			}
		})
	}
}

func TestDiagnosticsDestinationAndMust(t *testing.T) {
	c := diagnosticPlane(t, "dip(203.0.113.20) -> direct(mark:91)", "dip(198.51.100.10) && dport(443) -> dnat(203.0.113.20)\ndport(443) -> must")
	request := diagnosticRequest()
	request.Flow.SNI = new("")
	response, err := c.Explain(t.Context(), request, false)
	if err != nil || response.Current.Decision.Verdict != "userspace" || response.Current.Decision.Outbound != "direct" || response.Current.Decision.Mark != 91 || !response.Current.Decision.Must || !slices.Equal(response.Current.Decision.Targets, []string{"203.0.113.20:443"}) {
		t.Fatalf("destination route: %+v, %v", response, err)
	}
}

func TestDiagnosticsUnknownDestinationNeverBecomesUnspecifiedAddress(t *testing.T) {
	c := diagnosticPlane(t, "dip(0.0.0.0/32) -> block", "")
	request := diagnosticRequest()
	request.Flow.Destination.IP = ""
	request.Flow.Destination.Domain = "target.example"
	response, err := c.Explain(t.Context(), request, false)
	if err != nil || response.Current.Decision.Complete || response.Current.Decision.Verdict != "unknown" {
		t.Fatalf("%+v, %v", response, err)
	}
}

func TestDiagnosticsRetainsOptimizedRuleOrigins(t *testing.T) {
	c := diagnosticPlane(t, "dport(80) -> block\ndport(443) -> block", "")
	response, err := c.Explain(t.Context(), diagnosticRequest(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Current.Steps[0].Sources) != 2 || response.Current.Steps[0].Sources[0].Line == 0 {
		t.Fatalf("origins lost: %+v", response.Current.Steps)
	}
	if response.Current.Steps[1].Status != "not_reached" {
		t.Fatal("fallback reported as evaluated", response.Current.Steps)
	}
}

func TestDiagnosticsDomainSnapshotDoesNotRefreshRetention(t *testing.T) {
	c := diagnosticPlane(t, "domain(full: target.example) -> block", "")
	g := c.core.domainRegistry
	when := time.Now().Add(-time.Minute)
	ip := netip.MustParseAddr("198.51.100.10")
	g.ObserveDNS([]domainObservation{{name: "target.example.", ips: []netip.Addr{ip}, bitmap: c.routingMatcher.domainMatcher.MatchDomainBitmap("target.example"), ttl: 120}}, when)
	g.mu.Lock()
	before := g.generation
	deadline := g.byName["target.example."].addresses[ip].retainUntil
	g.mu.Unlock()
	response, err := c.Explain(t.Context(), diagnosticRequest(), false)
	if err != nil || response.Current.Decision.Verdict != "drop" {
		t.Fatalf("%+v %v", response, err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.generation != before || g.byName["target.example."].addresses[ip].retainUntil != deadline {
		t.Fatal("read refreshed DNS retention")
	}
	if _, err := json.Marshal(response); err != nil {
		t.Fatal(err)
	}
}

func TestDiagnosticsSharedFragmentOccurrences(t *testing.T) {
	c := diagnosticPlane(t, "rule_set { repeated { dport(443) -> block } }\nuse: repeated, repeated", "")
	response, err := c.Explain(t.Context(), diagnosticRequest(), false)
	if err != nil {
		t.Fatal(err)
	}
	steps := response.Current.Steps
	if len(steps) != 3 || steps[0].Status != "selected" || steps[1].Status != "not_reached" || steps[0].ID == steps[1].ID {
		t.Fatalf("shared bytecode confused logical occurrences: %+v", steps)
	}
}

type diagnosticResolver struct{}

func (diagnosticResolver) Plan() plugin.Plan { return plugin.Plan{DNS: []plugin.DNSScope{{}}} }
func (diagnosticResolver) WrapDNS(plugin.DNSHandler) plugin.DNSHandler {
	panic("diagnostics entered DNS execution")
}
func (diagnosticResolver) Explain(context.Context, api.ExplainRequest) plugin.Explanation {
	return plugin.Explanation{Complete: true, Dials: []plugin.DiagnosticDial{{Protocol: "tcp", Target: api.DiagnosticTarget{IP: "203.0.113.53", Domain: "resolver.example", Port: 853}}}}
}

func TestDiagnosticsDNSRoutesChosenUpstreamWithOriginalIdentity(t *testing.T) {
	c := diagnosticPlane(t, "sip(192.0.2.10) && dip(203.0.113.53) && dport(853) -> direct(mark:91)", "")
	host, err := mitm.New(mitm.Options{}, mitm.Instance{ID: "resolver", Type: "fixture", Plugin: diagnosticResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	c.mitmHost = host
	request := diagnosticRequest()
	request.Kind = "dns"
	request.Flow.Protocol = "udp"
	request.Flow.Destination.Port = 53
	request.DNS = &api.DiagnosticDNS{Name: "target.example", Type: "A"}
	response, err := c.Explain(t.Context(), request, false)
	if err != nil || !response.Current.Decision.Complete || response.Current.Decision.Mark != 91 || !slices.Equal(response.Current.Decision.Targets, []string{"203.0.113.53:853"}) {
		t.Fatalf("upstream routing: %+v, %v", response, err)
	}
	request.Context.SourceIP = ""
	response, err = c.Explain(t.Context(), request, false)
	if err != nil || response.Current.Decision.Complete || !slices.Contains(response.Current.Decision.Missing, "source_ip") {
		t.Fatalf("missing client identity became zero: %+v %v", response, err)
	}
}

func TestDiagnosticsExplicitTargetRewritesBeforeRouting(t *testing.T) {
	c := diagnosticPlane(t, "dip(198.51.100.10) -> block", "dip(198.51.100.10) -> dnat(203.0.113.10)")
	request := diagnosticRequest()
	request.Context.Origin = "daemon"
	response, err := c.Explain(t.Context(), request, false)
	if err != nil || !response.Current.Decision.Complete || response.Current.Decision.Verdict != "userspace" || response.Current.Decision.Outbound != "direct" || !slices.Equal(response.Current.Decision.Targets, []string{"203.0.113.10:443"}) {
		t.Fatalf("%+v %v", response, err)
	}
}

func TestDiagnosticsRemovingBindingDoesNotRetainHostnameTrust(t *testing.T) {
	c := diagnosticPlane(t, "domain(full: target.example) -> block\ndport(443) -> proxy", "")
	c.sniffVerifyMode, c.rerouteMode, c.noConnectivityTrySniff = consts.SniffVerifyMode_Loose, consts.RerouteMode_Force, true
	request := diagnosticRequest()
	request.Flow.SNI = new("target.example")
	ip := netip.MustParseAddr(request.Flow.Destination.IP)
	c.core.domainRegistry.ObserveDNS([]domainObservation{{name: "target.example.", ips: []netip.Addr{ip}, bitmap: c.routingMatcher.domainMatcher.MatchDomainBitmap("target.example"), ttl: 120}}, time.Now())
	request.Compare = &api.DiagnosticAssumptions{Bindings: []api.DiagnosticBinding{{IP: ip.String(), Domains: []string{}}}}
	response, err := c.Explain(t.Context(), request, false)
	if err != nil || response.Current.Decision.Verdict != "drop" || response.Compared.Decision.Complete || !slices.Contains(response.Compared.Decision.Missing, "hostname_verification") {
		t.Fatalf("removed evidence still verified hostname: %+v %v", response, err)
	}
}

func TestDiagnosticsConcurrentMembershipSnapshot(t *testing.T) {
	c := diagnosticPlane(t, "client(work) -> block", "")
	request := diagnosticRequest()
	request.Compare = &api.DiagnosticAssumptions{ClientSets: map[string]bool{"work": true}}
	mac, _ := diagnosticMAC(request.Context.MAC)
	var workers sync.WaitGroup
	workers.Go(func() {
		for i := range 30 {
			if _, err := c.UpdateClientSet("work", netip.MustParseAddr(request.Context.SourceIP), mac, i%2 == 0); err != nil {
				t.Error(err)
				return
			}
		}
	})
	workers.Go(func() {
		for range 30 {
			response, err := c.Explain(t.Context(), request, false)
			if err != nil {
				t.Error(err)
				return
			}
			joined := false
			for _, field := range response.Context {
				if field.Name == "client.work" {
					joined = field.Value == "true"
				}
			}
			if (response.Current.Decision.Verdict == "drop") != joined || response.Compared.Decision.Verdict != "drop" {
				t.Errorf("membership and route snapshots diverged: %+v", response)
				return
			}
		}
	})
	workers.Wait()
}
