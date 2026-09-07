// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm/surge"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type surgeScopeHostCase struct {
	host string
	mitm bool
}

func testSurgeModuleScopeRouting(t *testing.T, sources []string, hosts []surgeScopeHostCase) {
	t.Helper()
	for _, order := range []struct {
		name    string
		indices [2]int
	}{
		{name: "first then second", indices: [2]int{0, 1}},
		{name: "second then first", indices: [2]int{1, 0}},
	} {
		t.Run(order.name, func(t *testing.T) {
			var modules []*surge.Module
			for _, index := range order.indices {
				module, err := surge.Parse(sources[index], nil)
				if err != nil {
					t.Fatal(err)
				}
				modules = append(modules, module)
			}
			engine, err := surge.NewEngine(surge.EngineOptions{
				Modules: modules, Runtime: &surge.Runtime{},
				MaxBodySize: 1 << 20, MaxConcurrentScripts: 1, ScriptTimeout: time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			// Mark the explicit direct rule so a fallback to direct cannot conceal
			// an accidentally replaced or skipped user rule.
			original := &config_parser.RoutingRule{
				AndFunctions: []*config_parser.Function{{Name: "dport", Params: []*config_parser.Param{{Val: "443"}}}},
				Outbound:     config_parser.Function{Name: "direct", Params: []*config_parser.Param{{Key: "mark", Val: "37"}}},
			}
			preparation := &ControlPlanePreparation{rules: preparedRules{routing: []*config_parser.RoutingRule{original}}}
			preparation.rules.enableMITMPlan(engine.Plan())
			if len(preparation.rules.routing) != 1 || preparation.rules.routing[0] != original {
				t.Fatal("module capture replaced the explicit direct route")
			}
			userspace, _ := surgeRoutingMatcher(t, preparation.rules)
			capture, builder := surgeRoutingMatcher(t, preparation.rules)
			if len(builder.rules) != 3 ||
				builder.rules[0].Type != uint8(consts.MatchType_L4Proto) ||
				builder.rules[0].CaptureFlags != captureHTTP {
				t.Fatal("module capture must use one kernel match set")
			}
			// Keep the kernel's match conditions, replacing only its terminal
			// action so the userspace evaluator exposes capture without BPF maps.
			builder.rules[0].Outbound = uint8(consts.OutboundUserDefinedMin)
			builder.rules[0].CaptureFlags = 0 // Expose the capture predicate as a test terminal.
			for _, host := range hosts {
				t.Run(host.host, func(t *testing.T) {

					if got := controlTestHost(t, engine, nil).Match(host.host, 443); got != host.mitm {
						t.Errorf("MITM match = %v, want %v", got, host.mitm)
					}
					for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
						got, mark, must := surgeMatchRoute(t, userspace, host.host, proto)
						if got != consts.OutboundDirect || mark != 37 || must {
							t.Errorf("userspace route(%v) = (%v,%d,%v), want (direct,37,false)", proto, got, mark, must)
						}
						got, mark, must = surgeMatchRoute(t, capture, host.host, proto)
						wantOutbound, wantMark := consts.OutboundDirect, uint32(37)
						if proto == consts.L4ProtoType_TCP {
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

func TestSurgeModuleScopeBilijumpAndEmbyCapture(t *testing.T) {
	testSurgeModuleScopeRouting(t, []string{
		"#!name=Bilijump-like\n[MITM]\nhostname = %APPEND% app.bilibili.com, api.bilibili.com\n",
		"#!name=Emby-like\n[MITM]\nhostname = mb3admin.com\n",
	}, []surgeScopeHostCase{
		{host: "app.bilibili.com", mitm: true},
		{host: "api.bilibili.com", mitm: true},
		{host: "mb3admin.com", mitm: true},
		{host: "outside.example"},
		{host: "app.bilibili.com.outside.example"},
	})
}

func TestSurgeModuleScopeExclusionDoesNotEraseAnotherModule(t *testing.T) {
	testSurgeModuleScopeRouting(t, []string{
		"#!name=Wildcard exclusions\n[MITM]\nhostname = -private.example.com, -blocked.example.com, *.example.com\n",
		"#!name=Explicit private host\n[MITM]\nhostname = %APPEND% private.example.com\n",
	}, []surgeScopeHostCase{
		{host: "private.example.com", mitm: true},
		{host: "public.example.com", mitm: true},
		// Capture is an overapproximation; exclusions are enforced by each
		// module at MITM selection, not by the shared kernel capture rule.
		{host: "blocked.example.com", mitm: false},
		{host: "outside.test"},
	})
}
