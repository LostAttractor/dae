/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

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
	fallback := FunctionOrStringToFunction(conf.Routing.Fallback)
	if fallback.Name != "my_group" {
		t.Fatalf("must_ prefix should be trimmed from fallback: got %v", fallback.Name)
	}
	if len(fallback.Params) != 1 || fallback.Params[0].Val != "must" {
		t.Fatalf("must param expected in fallback: got %+v", fallback.Params)
	}
}

func TestNew_PatchEmptyDns(t *testing.T) {
	conf := parseConfig(t, `
global {}
routing { fallback: direct }
`)
	if FunctionOrStringToFunction(conf.Dns.Routing.Request.Fallback).Name != consts.DnsRequestOutboundIndex_AsIs.String() {
		t.Errorf("dns request fallback should default to %v", consts.DnsRequestOutboundIndex_AsIs)
	}
	if FunctionOrStringToFunction(conf.Dns.Routing.Response.Fallback).Name != consts.DnsResponseOutboundIndex_Accept.String() {
		t.Errorf("dns response fallback should default to %v", consts.DnsResponseOutboundIndex_Accept)
	}
}
