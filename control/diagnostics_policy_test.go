// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net"
	"testing"

	"github.com/daeuniverse/dae/api"
)

func TestDiagnosticsPolicyApplicability(t *testing.T) {
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	conf := parseStructuredTestConfig(t, `rule_set {
  shared { client(work) && dport(443) -> direct }
}
policy {
  main { rules { client(work) -> must } use: shared
    fallback: direct }
  tor { use: shared
    fallback: block }
  unbound { use: shared
    fallback: direct }
}
default: main
interface { lo: tor }`)
	prepared := preparedRules{routing: &conf.Routing, destinations: destinationRulesForTest(t, "client(work) && dport(80) -> dnat(198.51.100.20)")}
	c := diagnosticPreparedPlane(t, prepared)
	for _, tt := range []struct {
		name, selected string
		context        api.DiagnosticContext
	}{
		{name: "default interface", selected: "main", context: api.DiagnosticContext{IfIndex: new(uint32(0))}},
		{name: "bound interface", selected: "tor", context: api.DiagnosticContext{IfIndex: new(uint32(loopback.Index))}},
		{name: "interface name", selected: "tor", context: api.DiagnosticContext{Interface: "lo"}},
		{name: "explicit policy", selected: "tor", context: api.DiagnosticContext{Policy: "tor"}},
		{name: "daemon default", selected: "main", context: api.DiagnosticContext{Origin: "daemon"}},
		{name: "missing ingress", context: api.DiagnosticContext{}},
		{name: "physical interface does not select policy", context: api.DiagnosticContext{PhysicalIfIndex: new(uint32(loopback.Index))}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := diagnosticRequest()
			request.Context = tt.context
			request.Context.MAC = "02:00:00:00:00:10"
			impact, err := c.ClientImpact(t.Context(), "work", api.ClientImpactRequest{Context: request.Context, Joined: new(true), Flow: &request.Flow}, false)
			if err != nil {
				t.Fatal(err)
			}
			policies := make(map[string]bool)
			for _, step := range impact.Rules {
				policies[step.Policy] = true
				want := "unknown"
				if step.Policy == "" {
					want = ""
				} else if tt.selected != "" {
					want = "miss"
					if step.Policy == tt.selected {
						want = "match"
					}
				}
				if step.PolicyMatch != want || step.Status != "referenced" || step.Match != "unknown" {
					t.Fatalf("policy applicability confused with a rule result: %+v, want policy_match %q", step, want)
				}
			}
			if !policies["main"] || !policies["tor"] || !policies[""] || policies["unbound"] {
				t.Fatalf("unexpected reference scopes: %v", policies)
			}
			for _, field := range impact.Trace.Context {
				if field.Name == "policy" && (tt.selected == "" && (field.Source != "unknown" || field.Value != "") || tt.selected != "" && field.Value != tt.selected) {
					t.Fatalf("policy context overstates the evidence: %+v", field)
				}
			}
			for _, result := range []*api.ExplainResult{&impact.Trace.Current, impact.Trace.Compared} {
				if result.Decision.Policy != tt.selected {
					t.Fatalf("decision claims policy %q, want %q", result.Decision.Policy, tt.selected)
				}
				for _, step := range result.Steps {
					if step.Policy == "" {
						continue
					}
					want := "unknown"
					if step.Policy == "unbound" || tt.selected != "" && step.Policy != tt.selected {
						want = "miss"
					} else if tt.selected != "" {
						want = "match"
					}
					if step.PolicyMatch != want {
						t.Fatalf("trace policy %q = %q, want %q", step.Policy, step.PolicyMatch, want)
					}
					if want == "unknown" && step.Status == "inactive" {
						t.Fatalf("unknown ingress ruled out an active policy: %+v", step)
					}
				}
			}
		})
	}
	if len(c.settings.Members("work")) != 0 {
		t.Fatal("policy diagnostics changed membership")
	}
	for _, input := range []api.DiagnosticContext{{Policy: "missing"}, {Interface: "lo", IfIndex: new(uint32(0))}} {
		input.MAC = "02:00:00:00:00:10"
		if _, err := c.ClientImpact(t.Context(), "work", api.ClientImpactRequest{Context: input, Joined: new(true)}, false); err == nil {
			t.Fatalf("invalid context accepted: %+v", input)
		}
	}
}

func TestDiagnosticsSinglePolicyNeedsNoIngress(t *testing.T) {
	c := diagnosticPlane(t, "client(work) -> direct", "")
	impact, err := c.ClientImpact(t.Context(), "work", api.ClientImpactRequest{Context: api.DiagnosticContext{MAC: "02:00:00:00:00:10"}, Joined: new(true)}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(impact.Rules) != 1 || impact.Rules[0].PolicyMatch != "match" || impact.Rules[0].Match != "unknown" {
		t.Fatalf("the only policy does not require an interface to select it: %+v", impact)
	}
}
