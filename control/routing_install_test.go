// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
)

func TestRoutingInstallationDerivesSniffingFromProgram(t *testing.T) {
	for _, tc := range []struct {
		name, flow, routes string
		plan               plugin.Plan
		want               bool
	}{
		{name: "ordinary domain routing", routes: "domain(example.com) -> direct"},
		{name: "IP DNAT", flow: "dip(192.0.2.1) -> dnat(198.51.100.1)"},
		{name: "domain DNAT", flow: "domain(example.com) -> dnat(198.51.100.1)", want: true},
		{name: "HTTP request capture", plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{{Host: "192.0.2.1"}}}}}, want: true},
		{name: "HTTP preserve route", plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{{Host: "example.com"}}, PreserveRoute: true}}}, want: true},
		{name: "empty capture program", plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{{Host: "example.com", Exclude: true}}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := outboundUsageConfig(t, "global {}\nrouting { fallback: direct }")
			conf.Global.DNSRetentionWindow = 0
			core := &controlPlaneCore{closed: t.Context()}
			outbounds, err := core.buildOutbounds(t.Context(), nil, nil, &conf.Routing, &conf.Global, consts.OutboundBlock)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = outbounds.close() })
			plane := &ControlPlane{core: core}
			plane.adoptOutbounds(outbounds)
			rules := prepareFlowRulesForTest(t, tc.flow, tc.routes)
			if err := plane.initializeRouting(rules, outbounds, conf); err != nil {
				t.Fatal(err)
			}
			before := plane.routingMatcher
			rules.enableMITMPlan(tc.plan)
			if err := plane.installRouting(&rules, outbounds.nameToID, conf.Group, nil); err != nil {
				t.Fatal(err)
			}
			if plane.routingMatcher == before || plane.routingState != plane.routingMatcherBuilder.routingState {
				t.Fatal("routing installation retained an old matcher or state")
			}
			want := time.Duration(0)
			if tc.want {
				want = time.Second
			}
			if plane.sniffingTimeout != want {
				t.Fatalf("sniff timeout = %v, want %v", plane.sniffingTimeout, want)
			}
			plane.sniffingTimeout = 2 * time.Second
			if err := plane.installRouting(&rules, outbounds.nameToID, conf.Group, nil); err != nil {
				t.Fatal(err)
			}
			if plane.sniffingTimeout != 2*time.Second {
				t.Fatal("installation replaced configured sniff timeout")
			}
		})
	}
}
