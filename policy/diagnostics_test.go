// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestExplainUsesProductionPredicatesAndPreservesUnknowns(t *testing.T) {
	sections, err := config_parser.Parse("request { qname(suffix: example) && qtype(A) -> reject\nsip(192.0.2.0/24) -> asis }")
	if err != nil {
		t.Fatal(err)
	}
	var rules []*config_parser.RoutingRule
	for _, item := range sections[0].Items {
		rules = append(rules, item.Value.(*config_parser.RoutingRule))
	}
	conf := &Config{}
	conf.Routing.Request.Fallback = config.FunctionOrString("reject")
	conf.Routing.Response.Fallback = config.FunctionOrString("accept")
	policy, err := New(conf, rules, nil, &NewOption{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"test.example.", "outside.test."} {
		input := api.ExplainRequest{Kind: "dns", Context: api.DiagnosticContext{SourceIP: "192.0.2.4"}, DNS: &api.DiagnosticDNS{Name: name, Type: "A"}}
		result := policy.Explain(t.Context(), input, nil)
		selected, err := policy.RequestSelect(name, 1, 0, netip.IPv4Unspecified(), netip.MustParseAddr("192.0.2.4"))
		if err != nil || !result.Complete {
			t.Fatal(result, err)
		}
		found := false
		for _, step := range result.Steps {
			if step.Stage == "dns_request" && step.Status == "selected" {
				found = true
				if step.Action != selected.String() {
					t.Fatalf("explain=%s production=%s", step.Action, selected)
				}
			}
		}
		if !found {
			t.Fatal("missing selected rule")
		}
	}
	result := policy.Explain(t.Context(), api.ExplainRequest{DNS: &api.DiagnosticDNS{Name: "outside.test.", Type: "A"}}, nil)
	if result.Complete {
		t.Fatal("missing source IP selected fallback")
	}
}
