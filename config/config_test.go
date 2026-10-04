/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"reflect"
	"strings"
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
			filter: protocol(shadowsocks) && name(regex: '^HK-\d+$') [multiplex: smux]
			filter: name(HK-legacy, HK-2, HK-3, HK-4, HK-5, HK-6) [multiplex: off]
		}
	}
}

node {
	hk: 'ss://example' [multiplex: smux-udp-passthrough, multiplex_max_connections: 10]
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
	if len(subscription.Option.Rules) != 2 {
		t.Fatalf("option rules = %d, want 2", len(subscription.Option.Rules))
	}
	if got := subscription.Option.Rules[0].Options.Multiplex; got != MultiplexModeSmux {
		t.Fatalf("first rule multiplex = %q, want smux", got)
	}
	if len(conf.Node) != 2 || conf.Node[0].Name != "hk" || conf.Node[0].Options.Multiplex != MultiplexModeSmuxUDPPassthrough ||
		conf.Node[0].Options.MultiplexMaxConnections == nil || *conf.Node[0].Options.MultiplexMaxConnections != 10 {
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

func TestDNSRetentionWindow(t *testing.T) {
	for _, test := range []struct {
		value   string
		want    time.Duration
		invalid bool
	}{
		{"", 168 * time.Hour, false}, {"dns_retention_window: 48h", 48 * time.Hour, false},
		{"dns_retention_window: 0s", 0, true}, {"dns_retention_window: -1h", 0, true},
	} {
		t.Run(test.value, func(t *testing.T) {
			sections, err := config_parser.Parse("global { " + test.value + " } routing { fallback: direct }")
			if err != nil {
				t.Fatal(err)
			}
			conf, err := New(sections)
			if test.invalid {
				if err == nil || !strings.Contains(err.Error(), "dns_retention_window") {
					t.Fatalf("invalid window accepted: %v", err)
				}
				return
			}
			if err != nil || conf.Global.DNSRetentionWindow != test.want {
				t.Fatalf("window=%v error=%v", conf, err)
			}
			wire, err := conf.Marshal(2)
			if err != nil {
				t.Fatal(err)
			}
			if got := parseConfig(t, string(wire)).Global.DNSRetentionWindow; got != test.want {
				t.Fatalf("window changed in round trip: %v", got)
			}
		})
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
			name: "removed node check_async",
			config: `
global {}
node { test: 'ss://example' [check_async: true] }
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

func TestNewRejectsInvalidCheckDNS(t *testing.T) {
	for _, value := range []string{
		`"missing-port"`,
		`":53"`,
		`"dns.test:0"`,
		`"dns.test:53", "not-an-ip"`,
	} {
		sections, err := config_parser.Parse(`
global { udp_check_dns: ` + value + ` }
routing { fallback: direct }
`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = New(sections); err == nil {
			t.Errorf("udp_check_dns %s should be rejected", value)
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

func TestGroupCheckAsyncRoundTrip(t *testing.T) {
	for _, value := range []string{"", "true", "false"} {
		name := value
		if name == "" {
			name = "omitted"
		}
		t.Run(name, func(t *testing.T) {
			setting := ""
			if value != "" {
				setting = "check_async: " + value
			}
			conf := parseConfig(t, `
global {}
group { target { policy: random `+setting+` } }
routing { fallback: target }
`)
			if conf.Group[0].CheckAsync != (value == "true") || conf.Group[0].Present["check_async"] != (value != "") {
				t.Fatalf("unexpected check_async value or presence: %+v", conf.Group[0])
			}
			marshaled, err := conf.Marshal(2)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip := parseConfig(t, string(marshaled))
			if !reflect.DeepEqual(conf.Group, roundTrip.Group) {
				t.Fatalf("group changed after round trip\nfirst:  %+v\nsecond: %+v", conf.Group, roundTrip.Group)
			}
		})
	}
}

func TestGroupTrackAllAndExplicitSelectorDefaultRoundTrip(t *testing.T) {
	for _, policy := range []string{"selector", "selector(0)", "selector(1)"} {
		for _, value := range []string{"", "true", "false"} {
			setting := ""
			if value != "" {
				setting = "track_all: " + value
			}
			conf := parseConfig(t, "global {}\ngroup { target { policy: "+policy+" "+setting+" } }\nrouting { fallback: target }")
			if conf.Group[0].TrackAll != (value == "true") || conf.Group[0].Present["track_all"] != (value != "") {
				t.Fatalf("track_all parse = %+v", conf.Group[0])
			}
			marshaled, err := conf.Marshal(2)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip := parseConfig(t, string(marshaled))
			if !reflect.DeepEqual(conf.Group, roundTrip.Group) {
				t.Fatalf("group changed on round trip: %s", marshaled)
			}
		}
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

func TestNew_QuotedMustPrefixIsLiteralTargetName(t *testing.T) {
	conf := parseConfig(t, `
global {}
routing {
	dip(geoip:cn) -> 'must_edge'
	domain(full: example.com) -> 'must_callable'(mark: 0x800)
	fallback: 'must_fallback'
}
`)
	if outbound := conf.Routing.Policies[0].Statements[0].Rule.Outbound; outbound.Name != "must_edge" || !outbound.Quoted || len(outbound.Params) != 0 {
		t.Fatalf("quoted must target was rewritten: %+v", outbound)
	}
	if outbound := conf.Routing.Policies[0].Statements[1].Rule.Outbound; outbound.Name != "must_callable" || !outbound.Quoted || len(outbound.Params) != 1 {
		t.Fatalf("quoted callable must target was rewritten: %+v", outbound)
	}
	fallback := conf.Routing.Policies[0].Fallback
	if fallback.Name != "must_fallback" || !fallback.Quoted || len(fallback.Params) != 0 {
		t.Fatalf("quoted must fallback was rewritten: %+v", fallback)
	}
}

func TestDNSSettingsBelongToPlugins(t *testing.T) {
	conf := parseConfig(t, `global {} routing { fallback: direct } plugins { dns { type: dns-router upstream { local: 'udp://192.0.2.53' } } }`)
	if len(conf.Plugins) != 1 || conf.Plugins[0].Type != "dns-router" {
		t.Fatal("DNS plugin configuration lost")
	}
	sections, err := config_parser.Parse(`global {} routing { fallback: direct } dns {}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(sections); err == nil {
		t.Fatal("legacy core DNS section accepted")
	}
}

func TestNewRoutingPreservesUseOrder(t *testing.T) {
	conf := parseConfig(t, `global {}
 routing {
  rule_set { base { dip(geoip:private) -> direct } proxy { domain(suffix:example.com) -> my_group } }
  policy {
   main { use: base, proxy
    fallback: my_group }
   lan { use: base
    fallback: direct }
  }
  default: main
  interface { br-lan: lan
   eth1: lan }
 }`)
	got := conf.Routing.Policies[0].Statements
	if len(got) != 2 || got[0].Kind != RoutingStatementUse || got[0].Use != "base" || got[1].Use != "proxy" {
		t.Fatalf("statements lost order: %+v", got)
	}
	if conf.Routing.Default != "main" || len(conf.Routing.Interfaces) != 2 || conf.Routing.Interfaces[0] != (RoutingInterface{Name: "br-lan", Policy: "lan"}) || conf.Routing.Interfaces[1].Name != "eth1" {
		t.Fatalf("bindings = %+v", conf.Routing)
	}
}

func TestNewRoutingValidation(t *testing.T) {
	tests := []struct{ name, body, want string }{
		{"undefined use", "use: missing\nfallback: direct", `undefined rule_set "missing"`},
		{"duplicate rule set", "rule_set { a {} a {} }\nfallback: direct", `duplicate routing rule_set "a"`},
		{"cycle", "rule_set { a { use: b } b { use: a } }\nfallback: direct", "routing rule_set cycle"},
		{"self cycle", "rule_set { default { use: default } }\nfallback: direct", "routing rule_set cycle"},
		{"inline fallback required", "dip(geoip:private) -> direct", "requires exactly one fallback"},
		{"policy fallback required", "policy { main {} }\ndefault: main", "requires exactly one fallback"},
		{"unused policy fallback required", "policy { unused {} }\nfallback: direct", "requires exactly one fallback"},
		{"fragment fallback forbidden", "rule_set { a { fallback: direct } }\nfallback: direct", "rule_set cannot contain fallback"},
		{"duplicate fallback", "fallback: direct\nfallback: block", "duplicate policy fallback"},
		{"duplicate policy", "policy { a { fallback: direct } a { fallback: block } }\ndefault: a", `duplicate routing policy "a"`},
		{"duplicate default", "default: a\ndefault: a", "duplicate routing default"},
		{"undefined default", "default: missing", `undefined policy "missing"`},
		{"undefined binding", "fallback: direct\ninterface { eth0: missing }", `undefined policy "missing"`},
		{"duplicate binding", "policy { a { fallback: direct } }\ndefault: a\ninterface { eth0: a\neth0: a }", "duplicate routing interface binding"},
		{"default with inline fallback", "policy { a { fallback: direct } }\ndefault: a\nfallback: direct", "cannot be combined"},
		{"default with inline use", "policy { a { fallback: direct } }\ndefault: a\nuse: a", "cannot be combined"},
		{"policy use forbidden", "policy { a { fallback: direct } }\nuse: a\nfallback: direct", "undefined rule_set"},
		{"fragment binding forbidden", "rule_set { a {} }\ndefault: a", "undefined policy"},
		{"old default block", "default { fallback: direct }", "unexpected routing section"},
		{"old interface block", "fallback: direct\ninterface { lan { name: eth0\nfallback: direct } }", "expects interface_name: policy_name"},
		{"declaration annotation", "fallback: direct [priority: 1]", "does not support annotations"},
		{"multiple policy references", "default: a,b", "requires exactly one policy"},
		{"empty use", "use: ''\nfallback: direct", "nonempty rule_set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sections, err := config_parser.Parse("global {}\nrouting {\n" + tt.body + "\n}")
			if err != nil {
				t.Fatal(err)
			}
			_, err = New(sections)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRoutingRejectsControlsInPoliciesAndFragments(t *testing.T) {
	for _, action := range []string{"must_rules", "must_direct", "must_proxy", "direct(must)", "bump"} {
		for _, body := range []string{
			"rule_set { base { dport(53) -> " + action + " } } fallback: direct",
			"policy { main {dport(53) -> " + action + "\nfallback:direct} } default:main",
			"policy { main {fallback:" + action + "} } default:main",
		} {
			sections, err := config_parser.Parse("global {}\nrouting {" + body + "}")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = New(sections); err == nil || !strings.Contains(err.Error(), "flow controls belong in rules {}") {
				t.Fatalf("accepted %s: %v", body, err)
			}
		}
	}
}

func TestConnectionBehaviorConfigurationRoundTrip(t *testing.T) {
	conf := parseConfig(t, `
	global { no_connectivity_behavior: direct route_change_behavior: close }
	group { proxy { policy: min reselect_behavior: close } }
	routing { fallback: proxy }
	`)
	if conf.Global.RouteChangeBehavior != "close" || conf.Group[0].ReselectBehavior != "close" {
		t.Fatalf("connection policies = %+v / %+v", conf.Global, conf.Group[0])
	}
	encoded, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	if got := parseConfig(t, string(encoded)); !reflect.DeepEqual(conf, got) {
		t.Fatalf("connection policies changed during round trip")
	}
	if err := ValidateConnectionBehavior("route_change_behavior", "direct"); err == nil {
		t.Fatal("accepted an invalid recovery action")
	}
}
