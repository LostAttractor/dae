/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"reflect"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestNodeAndSubscriptionOptions(t *testing.T) {
	conf := parseConfig(t, `
global {}
subscription {
	legacy: 'https://example.com/legacy'
	my_sub {
		link: 'https://example.com/subscription'
		option {
			multiplex: off
			check_async: true
			filter: protocol(shadowsocks) && name(regex: '^HK-\d+$') [multiplex: smux, check_async: false]
			filter: name(HK-legacy, HK-2, HK-3, HK-4, HK-5, HK-6) [multiplex: off]
		}
	}
}

node {
	hk: 'ss://example' [multiplex: smux-udp-passthrough, multiplex_max_connections: 10, check_async: true]
	'socks5://localhost:1080'
}
routing { fallback: direct }
`)
	if len(conf.Subscription) != 2 {
		t.Fatalf("subscriptions = %d, want 2", len(conf.Subscription))
	}
	legacy := conf.Subscription[0]
	if legacy.Name != "legacy" || legacy.Link != "https://example.com/legacy" || !legacy.Option.IsZero() {
		t.Fatalf("unexpected legacy subscription: %+v", legacy)
	}
	subscription := conf.Subscription[1]
	if subscription.Name != "my_sub" || subscription.Link != "https://example.com/subscription" {
		t.Fatalf("unexpected expanded subscription: %+v", subscription)
	}
	if subscription.Option.Defaults.Multiplex != MultiplexModeOff {
		t.Fatalf("default multiplex = %q, want off", subscription.Option.Defaults.Multiplex)
	}
	if subscription.Option.Defaults.CheckAsync == nil || !*subscription.Option.Defaults.CheckAsync {
		t.Fatalf("default check_async = %v, want true", subscription.Option.Defaults.CheckAsync)
	}
	if len(subscription.Option.Rules) != 2 {
		t.Fatalf("option rules = %d, want 2", len(subscription.Option.Rules))
	}
	if got := subscription.Option.Rules[0].Options.Multiplex; got != MultiplexModeSmux {
		t.Fatalf("first rule multiplex = %q, want smux", got)
	}
	if got := subscription.Option.Rules[0].Options.CheckAsync; got == nil || *got {
		t.Fatalf("first rule check_async = %v, want false", got)
	}
	if len(conf.Node) != 2 || conf.Node[0].Name != "hk" || conf.Node[0].Options.Multiplex != MultiplexModeSmuxUDPPassthrough ||
		conf.Node[0].Options.MultiplexMaxConnections == nil || *conf.Node[0].Options.MultiplexMaxConnections != 10 ||
		conf.Node[0].Options.CheckAsync == nil || !*conf.Node[0].Options.CheckAsync {
		t.Fatalf("unexpected nodes: %+v", conf.Node)
	}

	marshaled, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	sections, err := config_parser.Parse(string(marshaled))
	if err != nil {
		t.Fatalf("parse marshaled config: %v\n%s", err, marshaled)
	}
	roundTrip, err := New(sections)
	if err != nil {
		t.Fatalf("decode marshaled config: %v\n%s", err, marshaled)
	}
	if !reflect.DeepEqual(conf, roundTrip) {
		t.Fatalf("config changed after round trip\nfirst:  %+v\nsecond: %+v", conf, roundTrip)
	}
}

func TestNestedGroupNameDoesNotEnableProxyPathContext(t *testing.T) {
	conf := parseConfig(t, `
global {}
subscription {
	group {
		link: 'https://example.com/subscription'
		option { filter: name(HK) [multiplex: smux] }
	}
}
routing { fallback: direct }
`)
	if len(conf.Subscription) != 1 || conf.Subscription[0].Name != "group" || len(conf.Subscription[0].Option.Rules) != 1 {
		t.Fatalf("subscription = %#v", conf.Subscription)
	}
}

func TestNodeOptionsRejectInvalidValues(t *testing.T) {
	for _, test := range []struct {
		name   string
		config string
	}{
		{
			name: "unknown inline option",
			config: `
global {}
node { test: 'ss://example' [unknown: value] }
routing { fallback: direct }
`,
		},
		{
			name: "boolean multiplex",
			config: `
global {}
node { test: 'ss://example' [multiplex: true] }
routing { fallback: direct }
`,
		},
		{
			name: "invalid check_async",
			config: `
global {}
node { test: 'ss://example' [check_async: maybe] }
routing { fallback: direct }
`,
		},
		{
			name: "zero multiplex connections",
			config: `
global {}
node { test: 'ss://example' [multiplex: smux, multiplex_max_connections: 0] }
routing { fallback: direct }
`,
		},
		{
			name: "too many multiplex connections",
			config: `
global {}
node { test: 'ss://example' [multiplex: smux, multiplex_max_connections: 17] }
routing { fallback: direct }
`,
		},
		{
			name: "multiplex connections without smux",
			config: `
global {}
node { test: 'ss://example' [multiplex_max_connections: 4] }
routing { fallback: direct }
`,
		},
		{
			name: "multiplex off with connection limit",
			config: `
global {}
node { test: 'ss://example' [multiplex: off, multiplex_max_connections: 4] }
routing { fallback: direct }
`,
		},
		{
			name: "subscription rule disables multiplex with connection limit",
			config: `
global {}
subscription {
	test {
		link: 'https://example.com/subscription'
		option { filter: name(test) [multiplex: off, multiplex_max_connections: 4] }
	}
}
routing { fallback: direct }
`,
		},
		{
			name: "numeric check_async alias",
			config: `
global {}
node { test: 'ss://example' [check_async: 1] }
routing { fallback: direct }
`,
		},
		{
			name: "node reference used as option filter",
			config: `
global {}
subscription {
	test {
		link: 'https://example.com/subscription'
		option { filter: node(test) [multiplex: smux] }
	}
}
routing { fallback: direct }
`,
		},
		{
			name: "empty filter options",
			config: `
global {}
subscription {
	test {
		link: 'https://example.com/subscription'
		option { filter: name(test) }
	}
}
routing { fallback: direct }
`,
		},
		{
			name: "unreachable invalid filter",
			config: `
global {}
subscription {
	test {
		link: 'https://example.com/subscription'
		option { filter: name(absent) && typo(value) [multiplex: smux] }
	}
}
routing { fallback: direct }
`,
		},
		{
			name: "invalid filter regexp",
			config: `
global {}
subscription {
	test {
		link: 'https://example.com/subscription'
		option { filter: name(regex: '[') [multiplex: smux] }
	}
}
routing { fallback: direct }
`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sections, err := config_parser.Parse(test.config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(sections); err == nil {
				t.Fatal("invalid node options were accepted")
			}
		})
	}
}

func TestMultiplexOffClearsInheritedConnectionLimit(t *testing.T) {
	connections := uint16(10)
	options := NodeOptions{
		Multiplex:               MultiplexModeSmux,
		MultiplexMaxConnections: &connections,
	}
	options.Overlay(NodeOptions{Multiplex: MultiplexModeOff})
	if options.Multiplex != MultiplexModeOff || options.MultiplexMaxConnections != nil {
		t.Fatalf("overlaid options = %+v, want multiplex off without a connection limit", options)
	}
}

func parseConfig(t *testing.T, in string) *Config {
	t.Helper()
	sections, err := config_parser.Parse(in)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	return conf
}

func TestNew_GlobalDefaults(t *testing.T) {
	conf := parseConfig(t, `
global {}
routing {
	fallback: direct
}
`)
	g := conf.Global
	if g.TproxyPort != 12345 {
		t.Errorf("TproxyPort: got %v", g.TproxyPort)
	}
	if !g.TproxyPortProtect {
		t.Errorf("TproxyPortProtect should default to true")
	}
	if g.LogLevel != "info" {
		t.Errorf("LogLevel: got %v", g.LogLevel)
	}
	if g.CheckInterval != 3*time.Minute {
		t.Errorf("CheckInterval: got %v", g.CheckInterval)
	}
	if g.CheckIntervalMax != time.Hour {
		t.Errorf("CheckIntervalMax: got %v", g.CheckIntervalMax)
	}
	if !g.DialTargetOverride {
		t.Errorf("DialTargetOverride should default to true")
	}
	if g.RerouteMode != consts.RerouteMode_WhileNeed {
		t.Errorf("RerouteMode: got %v", g.RerouteMode)
	}
	if g.SniffVerifyMode != consts.SniffVerifyMode_Loose {
		t.Errorf("SniffVerifyMode: got %v", g.SniffVerifyMode)
	}
	if g.SniffingTimeout != 100*time.Millisecond {
		t.Errorf("SniffingTimeout: got %v", g.SniffingTimeout)
	}
	if g.TlsImplementation != "tls" {
		t.Errorf("TlsImplementation: got %v", g.TlsImplementation)
	}
	if g.UtlsImitate != "chrome_auto" {
		t.Errorf("UtlsImitate: got %v", g.UtlsImitate)
	}
	if g.MetricsPort != 0 {
		t.Errorf("MetricsPort: got %v", g.MetricsPort)
	}
	if g.FallbackResolver != "8.8.8.8:53" {
		t.Errorf("FallbackResolver: got %v", g.FallbackResolver)
	}
	if !g.NoConnectivityTrySniff {
		t.Errorf("NoConnectivityTrySniff should default to true")
	}
	if g.NoConnectivityBehavior != "block" {
		t.Errorf("NoConnectivityBehavior: got %v", g.NoConnectivityBehavior)
	}
	if g.UDPHopInterval != 30*time.Second {
		t.Errorf("UDPHopInterval: got %v", g.UDPHopInterval)
	}
}

func TestNew_GlobalExplicitValues(t *testing.T) {
	conf := parseConfig(t, `
global {
	reroute_mode: force
	sniff_verify_mode: strict
	dial_target_override: false
	no_connectivity_try_sniff: false
	no_connectivity_behavior: direct
	check_interval: 45s
	check_interval_max: 10m
	udphop_interval: 5s
	metrics_port: 9090
	pprof_port: 6060
}
routing {
	fallback: direct
}
`)
	g := conf.Global
	if g.RerouteMode != consts.RerouteMode_Force {
		t.Errorf("RerouteMode: got %v", g.RerouteMode)
	}
	if g.SniffVerifyMode != consts.SniffVerifyMode_Strict {
		t.Errorf("SniffVerifyMode: got %v", g.SniffVerifyMode)
	}
	if g.DialTargetOverride {
		t.Errorf("DialTargetOverride should be false")
	}
	if g.NoConnectivityTrySniff {
		t.Errorf("NoConnectivityTrySniff should be false")
	}
	if g.NoConnectivityBehavior != "direct" {
		t.Errorf("NoConnectivityBehavior: got %v", g.NoConnectivityBehavior)
	}
	if g.CheckInterval != 45*time.Second {
		t.Errorf("CheckInterval: got %v", g.CheckInterval)
	}
	if g.CheckIntervalMax != 10*time.Minute {
		t.Errorf("CheckIntervalMax: got %v", g.CheckIntervalMax)
	}
	if g.UDPHopInterval != 5*time.Second {
		t.Errorf("UDPHopInterval: got %v", g.UDPHopInterval)
	}
	if g.MetricsPort != 9090 {
		t.Errorf("MetricsPort: got %v", g.MetricsPort)
	}
	if g.PprofPort != 6060 {
		t.Errorf("PprofPort: got %v", g.PprofPort)
	}
}

func TestNew_RequiredSections(t *testing.T) {
	sections, err := config_parser.Parse(`global {}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = New(sections); err == nil {
		t.Errorf("New should fail without the required routing section")
	}

	sections, err = config_parser.Parse(`routing { fallback: direct }`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = New(sections); err == nil {
		t.Errorf("New should fail without the required global section")
	}
}

func TestNew_RejectsInvalidCheckIntervals(t *testing.T) {
	for _, field := range []string{"check_interval", "check_interval_max"} {
		for _, value := range []string{"0s", "-1s"} {
			sections, err := config_parser.Parse(`
global { ` + field + `: ` + value + ` }
routing { fallback: direct }
`)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = New(sections); err == nil {
				t.Errorf("%s: %s should be rejected", field, value)
			}
		}
	}
	sections, err := config_parser.Parse(`
global { check_interval_max: 500ms }
routing { fallback: direct }
`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = New(sections); err == nil {
		t.Error("check_interval_max below the 1s initial backoff should be rejected")
	}
	sections, err = config_parser.Parse(`
global { check_interval_max: 1281024h }
routing { fallback: direct }
`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = New(sections); err == nil {
		t.Error("check_interval_max above half the time.Duration range should be rejected")
	}
	for _, field := range []string{"check_interval", "check_interval_max"} {
		sections, err = config_parser.Parse(`
global {}
group { target { policy: random ` + field + `: 0s } }
routing { fallback: target }
`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = New(sections); err == nil {
			t.Errorf("group %s: explicit 0s should be rejected", field)
		}
	}
}

func TestNewRejectsInvalidControlModes(t *testing.T) {
	for field, value := range map[string]string{
		"reroute_mode":      "always",
		"sniff_verify_mode": "verify",
	} {
		sections, err := config_parser.Parse(`
global { ` + field + `: ` + value + ` }
routing { fallback: direct }
`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := New(sections); err == nil {
			t.Errorf("%s=%s unexpectedly succeeded", field, value)
		}
	}
}

func TestNew_UnknownSection(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing { fallback: direct }
unknown_section {}
`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = New(sections); err == nil {
		t.Errorf("New should fail on unknown section")
	}
}

func TestNew_RejectsAnnotationOnUnsupportedField(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
group { target { policy: random [priority: 1] } }
routing { fallback: target }
`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = New(sections); err == nil {
		t.Fatal("annotation on policy was silently accepted")
	}
}

func TestNew_TracksExplicitGroupRuntimeFields(t *testing.T) {
	conf := parseConfig(t, `
global {}
group { target { policy: random check_tolerance: 0s } }
routing { fallback: target }
`)
	if !conf.Group[0].Present["check_tolerance"] {
		t.Fatal("explicit zero-valued group field was not tracked")
	}
}

func TestNew_ParsesProxyPathExpressions(t *testing.T) {
	conf := parseConfig(t, `
global {}
group {
	entry {
		filter: name(relay)
	}
	target {
		filter: name(relay) [priority: 1]
		filter: name(relay) -> filter: subtag(flowercloud) && name(keyword: '日本')
		node(relay) -> group(entry)
		policy: min_moving_avg
	}
}
routing { fallback: target }
`)
	paths := conf.Group[1].Paths
	if len(paths) != 3 {
		t.Fatalf("paths = %#v", paths)
	}
	if len(paths[0].Stages) != 1 || paths[0].Stages[0].Key != "filter" || paths[0].Stages[0].Annotation[0].Key != "priority" {
		t.Fatalf("direct path = %#v", paths[0])
	}
	if len(paths[1].Stages) != 2 || len(paths[1].Stages[1].AndFunctions) != 2 {
		t.Fatalf("inline chain = %#v", paths[1])
	}
	if len(paths[2].Stages) != 2 || paths[2].Stages[0].AndFunctions[0].Name != "node" ||
		paths[2].Stages[1].AndFunctions[0].Name != "group" {
		t.Fatalf("typed chain = %#v", paths[2])
	}
}

func TestNew_DecodesQuotedPathReferenceName(t *testing.T) {
	conf := parseConfig(t, `
global {}
group { target { node("Node \"A\" \\ path") policy: random } }
routing { fallback: target }
`)
	stage := conf.Group[0].Paths[0].Stages[0]
	if stage.AndFunctions[0].Name != "node" || stage.AndFunctions[0].Params[0].Val != `Node "A" \ path` {
		t.Fatalf("stage = %#v", stage)
	}
}

func TestNew_PatchMustOutbound(t *testing.T) {
	conf := parseConfig(t, `
global {}
routing {
	dip(geoip:cn) -> must_direct
	fallback: must_my_group
}

`)
	rule := conf.Routing.Rules[0]
	if rule.Outbound.Name != "direct" {
		t.Fatalf("must_ prefix should be trimmed: got %v", rule.Outbound.Name)
	}
	if len(rule.Outbound.Params) != 1 || rule.Outbound.Params[0].Val != "must" {
		t.Fatalf("must param expected: got %+v", rule.Outbound.Params)
	}
	fallback, err := ParseFunctionOrString(conf.Routing.Fallback)
	if err != nil {
		t.Fatal(err)
	}
	if fallback.Name != "my_group" {
		t.Fatalf("must_ prefix should be trimmed from fallback: got %v", fallback.Name)
	}
	if len(fallback.Params) != 1 || fallback.Params[0].Val != "must" {
		t.Fatalf("must param expected in fallback: got %+v", fallback.Params)
	}
}

func TestNew_QuotedMustPrefixIsLiteralTargetName(t *testing.T) {
	conf := parseConfig(t, `
global {}
routing {
	dip(geoip:cn) -> 'must_edge'
	domain(full: example.com) -> 'must_callable'(mark: 0x800)
	fallback: 'must_fallback'
}
`)
	if outbound := conf.Routing.Rules[0].Outbound; outbound.Name != "must_edge" || !outbound.Quoted || len(outbound.Params) != 0 {
		t.Fatalf("quoted must target was rewritten: %+v", outbound)
	}
	if outbound := conf.Routing.Rules[1].Outbound; outbound.Name != "must_callable" || !outbound.Quoted || len(outbound.Params) != 1 {
		t.Fatalf("quoted callable must target was rewritten: %+v", outbound)
	}
	fallback := FunctionOrStringToFunction(conf.Routing.Fallback)
	if fallback.Name != "must_fallback" || !fallback.Quoted || len(fallback.Params) != 0 {
		t.Fatalf("quoted must fallback was rewritten: %+v", fallback)
	}
}

func TestNew_PatchEmptyDns(t *testing.T) {
	conf := parseConfig(t, `
global {}
routing { fallback: direct }
`)
	requestFallback, err := ParseFunctionOrString(conf.Dns.Routing.Request.Fallback)
	if err != nil {
		t.Fatal(err)
	}
	if requestFallback.Name != consts.DnsRequestOutboundIndex_AsIs.String() {
		t.Errorf("dns request fallback should default to %v", consts.DnsRequestOutboundIndex_AsIs)
	}
	responseFallback, err := ParseFunctionOrString(conf.Dns.Routing.Response.Fallback)
	if err != nil {
		t.Fatal(err)
	}
	if responseFallback.Name != consts.DnsResponseOutboundIndex_Accept.String() {
		t.Errorf("dns response fallback should default to %v", consts.DnsResponseOutboundIndex_Accept)
	}
}
