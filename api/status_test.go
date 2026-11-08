// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	jsonv1 "encoding/json"
	json "encoding/json/v2"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestStatusWireRoundTrip(t *testing.T) {
	want := benchmarkStatus()
	want.Uptime = time.Hour + 234*time.Nanosecond
	want.DirectFallbackConnections = 1<<53 + 1
	want.Groups[0].Nodes[0].InitialCheckDone = true
	want.Groups[0].Nodes[0].Availability.LastFailureDuration = time.Second
	want.Groups[0].Nodes[0].Dormant = true
	want.Groups[0].Nodes[0].Selection = &SelectionStatus{
		Tracking: "standby", Degraded: true, RecoveryElapsed: 5 * time.Second, FailureRecovery: 30 * time.Second,
		Priority: 10, Score: -time.Second, MeasuredAt: time.Unix(100, 0).UTC(),
	}
	want.CompiledPlugins = []string{"example", "unused"}
	want.Plugins = []PluginInstanceStatus{
		{ID: "example", Type: "example", Enabled: true, State: "active", DeclaredScopes: 2, HTTPReason: "mitm_disabled"},
		{ID: "future", Type: "uncompiled", State: "disabled", HTTPReason: "disabled"},
	}
	want.BufferMemory = BufferMemoryStatus{Limit: 64 << 20, Used: 1 << 20, Peak: 2 << 20, Denied: 3}
	want.Tables = []TableUsage{
		{Name: "domain-registry", Scope: "userspace", OnFull: "unlimited", Used: 8,
			Breakdown: &TableUsageBreakdown{Domains: 3, IPs: 5, IPv4: 4, IPv6: 1, GC: ^uint64(0)}},
		{Name: "domain-kernel", Scope: "kernel", OnFull: "omit", Used: 2, Limit: 4, Candidates: 3, Pending: 1},
		{Name: "tcp_flow_map", Scope: "kernel", OnFull: "evict", Limit: 16, Error: "read map: permission denied"},
		{Name: "udp-sources", Scope: "userspace", OnFull: "reject", Used: 4, Limit: 4},
	}
	payload, err := json.Marshal(want, jsonv1.FormatDurationAsNano(true))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"last":30000000`, `"last_failure_duration":1000000000`, `"schema":15`, `"uptime":3600000000234`, `"scope":"kernel"`, `"on_full":"evict"`, `"error":"read map: permission denied"`, `"plugins":`, `"direct_fallback_connections":9007199254740993`} {
		if !strings.Contains(string(payload), field) {
			t.Fatalf("wire representation missing %s", field)
		}
	}
	if strings.Contains(string(payload), `"fallback_connections":`) || strings.Count(string(payload), `"direct_fallback_connections":`) != 1 {
		t.Fatal("fallback counters leaked into path/group/node statistics")
	}
	for _, field := range []string{`"dormant":true`, `"tracking":"standby"`, `"selection":`, `"recovery_elapsed":5000000000`, `"failure_recovery":30000000000`, `"score":-1000000000`} {
		if !strings.Contains(string(payload), field) {
			t.Fatalf("selection wire representation missing %s", field)
		}
	}
	if strings.Contains(string(payload), `"average_10_failed"`) {
		t.Fatal("failure flag leaked into successful latency statistics")
	}
	var got StatusSnapshot
	if err := json.Unmarshal(payload, &got, jsonv1.FormatDurationAsNano(true)); err != nil {
		t.Fatal(err)
	}
	if got.Groups[0].Nodes[0].InitialCheckDone {
		t.Fatal("runtime-only initial check state leaked into API JSON")
	}
	if got.Uptime != want.Uptime {
		t.Fatal("server uptime units changed after round trip")
	}
	if got.DirectFallbackConnections != want.DirectFallbackConnections {
		t.Fatal("direct fallback precision changed")
	}
	encoded, err := json.Marshal(got, jsonv1.FormatDurationAsNano(true))
	if err != nil || string(encoded) != string(payload) {
		t.Fatal("status changed after round trip", err)
	}
	if !reflect.DeepEqual(got.Groups[0].Nodes[0].Latency, want.Groups[0].Nodes[0].Latency) {
		t.Fatal("latency units changed")
	}
	if !reflect.DeepEqual(got.Groups[0].Nodes[0].Selection, want.Groups[0].Nodes[0].Selection) {
		t.Fatal("selection durations or signed score changed after round trip")
	}
	if !reflect.DeepEqual(got.Plugins, want.Plugins) || !reflect.DeepEqual(got.CompiledPlugins, want.CompiledPlugins) || got.BufferMemory != want.BufferMemory {
		t.Fatal("plugin envelope or process statistics changed after round trip")
	}
	if !reflect.DeepEqual(got.Tables, want.Tables) || strings.Count(string(payload), `"error":`) != 1 {
		t.Fatal("table usage, availability or optional error changed after round trip")
	}
}
