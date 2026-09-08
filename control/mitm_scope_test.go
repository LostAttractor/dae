// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type scopeHostCase struct {
	host    string
	mitm    bool
	capture bool // A positive wildcard may also cover an excluded hostname.
}

func testMITMScopeRouting(t *testing.T, scopes []plugin.HTTPScope, hosts []scopeHostCase) {
	t.Helper()
	for _, order := range []struct {
		name    string
		indices [2]int
	}{
		{name: "first then second", indices: [2]int{0, 1}},
		{name: "second then first", indices: [2]int{1, 0}},
	} {
		t.Run(order.name, func(t *testing.T) {
			plan := plugin.Plan{Scopes: []plugin.HTTPScope{scopes[order.indices[0]], scopes[order.indices[1]]}}
			host := controlTestHost(t, &controlTestPlugin{plan: plan}, nil)
			// Mark the explicit direct rule so a fallback to direct cannot conceal
			// an accidentally replaced or skipped user rule.
			original := &config_parser.RoutingRule{
				AndFunctions: []*config_parser.Function{{Name: "dport", Params: []*config_parser.Param{{Val: "443"}}}},
				Outbound:     config_parser.Function{Name: "direct", Params: []*config_parser.Param{{Key: "mark", Val: "37"}}},
			}
			preparation := &ControlPlanePreparation{rules: preparedRules{routing: testRoutingConfig([]*config_parser.RoutingRule{original}, "direct")}}
			preparation.rules.enableMITMPlan(host.Plan())
			if len(preparation.rules.routing.Policies[0].Statements) != 1 || preparation.rules.routing.Policies[0].Statements[0].Rule != original {
				t.Fatal("module capture replaced the explicit direct route")
			}
			userspace, _ := routingMatcherForTest(t, preparation.rules)
			capture, builder := routingMatcherForTest(t, preparation.rules)
			// Keep the kernel's match conditions, replacing only its terminal
			// action so the userspace evaluator exposes capture without BPF maps.
			exposeCapturePredicates(t, builder)
			for _, target := range hosts {
				t.Run(target.host, func(t *testing.T) {

					if got := host.Match(target.host, 443) != mitm.HTTPBypass; got != target.mitm {
						t.Errorf("MITM match = %v, want %v", got, target.mitm)
					}
					for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
						got, mark, must := matchTestRoute(t, userspace, target.host, proto)
						if got != consts.OutboundDirect || mark != 37 || must {
							t.Errorf("userspace route(%v) = (%v,%d,%v), want (direct,37,false)", proto, got, mark, must)
						}
						got, mark, must = matchTestRoute(t, capture, target.host, proto)
						wantOutbound, wantMark := consts.OutboundDirect, uint32(37)
						// HTTP/3 uses the same per-plugin scope as TCP HTTP.
						// Candidate capture still does not override exclusions.
						if target.mitm || target.capture {
							wantOutbound, wantMark = consts.OutboundUserDefinedMin, 0
						}
						if got != wantOutbound || mark != wantMark || must {
							t.Errorf("capture route(%v) = (%v,%d,%v), want (%v,%d,false)", proto, got, mark, must, wantOutbound, wantMark)
						}
					}
				})
			}
		})
	}
}

func TestMITMPluginScopesCombine(t *testing.T) {
	testMITMScopeRouting(t, []plugin.HTTPScope{
		mitmRoutingPlugin("app.video.example", "api.video.example").plan.Scopes[0],
		mitmRoutingPlugin("media.example").plan.Scopes[0],
	}, []scopeHostCase{
		{host: "app.video.example", mitm: true},
		{host: "api.video.example", mitm: true},
		{host: "media.example", mitm: true},
		{host: "outside.example"},
		{host: "app.video.example.outside.example"},
	})
}

func TestMITMPluginScopeExclusionDoesNotEraseAnotherPlugin(t *testing.T) {
	testMITMScopeRouting(t, []plugin.HTTPScope{
		{PreserveRoute: true, Scope: plugin.Scope{
			{Host: "private.example.com", Ports: []uint16{80, 443}, Exclude: true},
			{Host: "blocked.example.com", Ports: []uint16{80, 443}, Exclude: true},
			{Host: "*.example.com", Ports: []uint16{80, 443}},
		}},
		mitmRoutingPlugin("private.example.com").plan.Scopes[0],
	}, []scopeHostCase{
		{host: "private.example.com", mitm: true},
		{host: "public.example.com", mitm: true},
		// Capture is an overapproximation; exclusions are enforced by each
		// plugin at MITM selection, not by the shared kernel capture rule.
		{host: "blocked.example.com", mitm: false, capture: true},
		{host: "outside.test"},
	})
}
