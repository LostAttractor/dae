// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/surgemodule"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func moduleRuleEngine(t *testing.T) *surgemodule.Engine {
	t.Helper()
	module, err := surgemodule.Parse(`[Rule]
DOMAIN,api.cloudflare.com,DIRECT
DOMAIN,api.biliapi.com,REJECT,pre-matching,extended-matching
DOMAIN,app.biliapi.com,REJECT,pre-matching,extended-matching
DOMAIN,api.biliapi.net,REJECT,pre-matching,extended-matching
DOMAIN,app.biliapi.net,REJECT,pre-matching,extended-matching
AND,((DOMAIN-SUFFIX,chat.bilibili.com),(OR,((DOMAIN-KEYWORD,stun),(DOMAIN-KEYWORD,tracker),(DOMAIN-KEYWORD,p2p)))),REJECT,pre-matching
AND,((DOMAIN-SUFFIX,negative.example),(NOT,((OR,((DOMAIN,private.negative.example),(DOMAIN-WILDCARD,secret?.negative.example)))))),REJECT
DOMAIN-WILDCARD,api-*.wild.example,DIRECT
DOMAIN-KEYWORD,api.,REJECT
[MITM]
hostname = grpc.biliapi.net, api.cloudflare.com
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := surgemodule.NewEngine(surgemodule.EngineOptions{
		Modules: []*surgemodule.Module{module}, Runtime: &surgemodule.Runtime{},
		MaxBodySize: 1 << 20, MaxConcurrentScripts: 1, ScriptTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func moduleRuleMatcher(t *testing.T, engine *surgemodule.Engine, userRules []*config_parser.RoutingRule) *RoutingMatcher {
	t.Helper()
	preparation := &ControlPlanePreparation{rules: preparedRules{routing: userRules}}
	preparation.rules.enableMITMPlan(engine.Plan())
	builder, err := NewRoutingMatcherBuilder(preparation.rules.routing, map[string]uint8{
		"direct": uint8(consts.OutboundDirect), "block": uint8(consts.OutboundBlock), "proxy": uint8(consts.OutboundUserDefinedMin),
	}, nil, "proxy", nil, preparation.rules.capture, nil)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	return matcher
}

func TestSurgeModuleRulesNativeRouting(t *testing.T) {
	engine := moduleRuleEngine(t)
	matcher := moduleRuleMatcher(t, engine, nil)
	for _, test := range []struct {
		host  string
		proto consts.L4ProtoType
		want  consts.OutboundIndex
	}{
		{"api.cloudflare.com", consts.L4ProtoType_TCP, consts.OutboundDirect},
		{"api.biliapi.com", consts.L4ProtoType_TCP, consts.OutboundBlock},
		{"app.biliapi.com", consts.L4ProtoType_TCP, consts.OutboundBlock},
		{"api.biliapi.net", consts.L4ProtoType_TCP, consts.OutboundBlock},
		{"app.biliapi.net", consts.L4ProtoType_TCP, consts.OutboundBlock},
		{"stun.chat.bilibili.com", consts.L4ProtoType_UDP, consts.OutboundBlock},
		{"tracker.chat.bilibili.com", consts.L4ProtoType_TCP, consts.OutboundBlock},
		{"p2p.chat.bilibili.com", consts.L4ProtoType_UDP, consts.OutboundBlock},
		{"chat.bilibili.com", consts.L4ProtoType_TCP, consts.OutboundUserDefinedMin},
		{"stun.chat.bilibili.com.evil", consts.L4ProtoType_TCP, consts.OutboundUserDefinedMin},
		{"public.negative.example", consts.L4ProtoType_TCP, consts.OutboundBlock},
		{"private.negative.example", consts.L4ProtoType_TCP, consts.OutboundUserDefinedMin},
		{"secret1.negative.example", consts.L4ProtoType_TCP, consts.OutboundUserDefinedMin},
		{"secret12.negative.example", consts.L4ProtoType_TCP, consts.OutboundBlock},
		{"api-one.two.wild.example", consts.L4ProtoType_TCP, consts.OutboundDirect},
		{"api-one.wild.example.evil", consts.L4ProtoType_TCP, consts.OutboundUserDefinedMin},
		{"api.example.com", consts.L4ProtoType_TCP, consts.OutboundBlock},
		{"API.EXAMPLE.COM.", consts.L4ProtoType_TCP, consts.OutboundBlock},
		{"capillary.example.com", consts.L4ProtoType_TCP, consts.OutboundUserDefinedMin},
		{"api-v2.example.com", consts.L4ProtoType_TCP, consts.OutboundUserDefinedMin},
	} {
		got, _, _ := surgeMatchRoute(t, matcher, test.host, test.proto)
		if got != test.want {
			t.Errorf("module route(%s,%v)=%v, want %v", test.host, test.proto, got, test.want)
		}
	}
}

func TestSurgeModuleDirectCannotOverrideExplicitUserPolicy(t *testing.T) {
	engine := moduleRuleEngine(t)
	for _, test := range []struct {
		policy string
		want   consts.OutboundIndex
	}{{"block", consts.OutboundBlock}, {"proxy", consts.OutboundUserDefinedMin}} {
		rule := &config_parser.RoutingRule{AndFunctions: []*config_parser.Function{{Name: "domain", Params: []*config_parser.Param{{Key: "full", Val: "api.cloudflare.com"}}}}, Outbound: config_parser.Function{Name: test.policy}}
		matcher := moduleRuleMatcher(t, engine, []*config_parser.RoutingRule{rule})
		got, _, _ := surgeMatchRoute(t, matcher, "api.cloudflare.com", consts.L4ProtoType_TCP)
		if got != test.want {
			t.Fatalf("module DIRECT overrode user %s with %v", test.policy, got)
		}
		// The same order must survive the original-kernel-route reconstruction
		// used when the module host itself is intercepted.
		bitmap := matcher.domainMatcher.MatchDomainBitmap("api.cloudflare.com")
		address := make([]byte, 16)
		got, _, _, err := matcher.Match(address, address, 12345, 443, consts.IpVersion_4, consts.L4ProtoType_TCP, "different.example", [16]uint8{}, 0, 0, address, bitmap, bitmap)
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Fatalf("reconstruction allowed module DIRECT to override user %s", test.policy)
		}
	}
}

func TestSurgeModulePreRejectPrecedesUserDirect(t *testing.T) {
	rule := &config_parser.RoutingRule{AndFunctions: []*config_parser.Function{{Name: "domain", Params: []*config_parser.Param{{Key: "full", Val: "api.biliapi.com"}}}}, Outbound: config_parser.Function{Name: "direct"}}
	matcher := moduleRuleMatcher(t, moduleRuleEngine(t), []*config_parser.RoutingRule{rule})
	got, _, _ := surgeMatchRoute(t, matcher, "api.biliapi.com", consts.L4ProtoType_TCP)
	if got != consts.OutboundBlock {
		t.Fatalf("pre-matching reject lost priority: %v", got)
	}
}
