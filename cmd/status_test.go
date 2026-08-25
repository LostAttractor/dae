/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/control"
)

func TestTableUsageRow(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = false
	defer func() { colorsEnabled = previousColorsEnabled }()

	row := tableUsageRow(control.TableUsage{Name: "domain-kernel", Used: 6554, Limit: 65536})
	want := []string{"domain-kernel", "6554", "65536", "10.0%", "-", "-"}
	for i, expected := range want {
		if got := fmt.Sprint(row[i]); got != expected {
			t.Errorf("tableUsageRow()[%d] = %q, want %q", i, got, expected)
		}
	}

	lazy := tableUsageRow(control.TableUsage{
		Name:  "domain-history",
		Used:  32768,
		Limit: 32768,
		Breakdown: &control.TableUsageBreakdown{
			Live:     60000,
			Retained: 5536,
			LimitGC:  123,
		},
	})
	if got := lazy[1].(string); got != "32768 (LAZY)" {
		t.Errorf("lazy used cell = %q, want %q", got, "32768 (LAZY)")
	}
	if got := fmt.Sprint(lazy[2]); got != "32768" {
		t.Errorf("hard limit cell = %q, want %q", got, "32768")
	}
	if got := lazy[4].(string); got != "60000/5536" {
		t.Errorf("live/retained cell = %q, want %q", got, "60000/5536")
	}
	if got := lazy[5].(string); got != "123" {
		t.Errorf("limit GC cell = %q, want %q", got, "123")
	}

	zero := tableUsageRow(control.TableUsage{Name: "domain-kernel"})
	if got := zero[3].(string); got != "0.0%" {
		t.Errorf("zero-limit usage cell = %q, want %q", got, "0.0%")
	}
}

func TestTableUsageRowColors(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = true
	defer func() { colorsEnabled = previousColorsEnabled }()

	tests := []struct {
		used, limit int
		ansi        string
	}{
		{used: 6554, limit: 65536, ansi: "\x1b[32m"},  // 10%: green
		{used: 52429, limit: 65536, ansi: "\x1b[33m"}, // 80%: yellow
		{used: 62260, limit: 65536, ansi: "\x1b[31m"}, // 95%: red
		{used: 65536, limit: 32768, ansi: "\x1b[31m"}, // 200%: red
	}
	for _, tt := range tests {
		row := tableUsageRow(control.TableUsage{Used: tt.used, Limit: tt.limit})
		if got := row[3].(string); !strings.Contains(got, tt.ansi) {
			t.Errorf("usage %d/%d = %q, want ANSI prefix %q", tt.used, tt.limit, got, tt.ansi)
		}
	}
}

func TestNodeStatusRow(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = false
	defer func() { colorsEnabled = previousColorsEnabled }()

	row := nodeStatusRow(control.NodeStatus{
		ID:       "node-a-id",
		Name:     "node-a",
		Protocol: "vless",
		Session:  &control.SessionStatus{State: control.SessionConnected},
		Networks: []control.NodeNetworkStatus{
			{Network: "tcp4", SupportState: "confirmed"},
			{Network: "tcp6", SupportState: "confirmed"},
			{Network: "udp4", SupportState: "confirmed"},
			{Network: "udp6", SupportState: "confirmed"},
		},
		Health: &control.NodeHealthStatus{
			State: control.NodeHealthHealthy,
			Latency: &control.LatencyStatus{
				LastMs:          42,
				Average10Ms:     45,
				MovingAverageMs: 50,
			},
			UpRatio:         0.998,
			ChecksTotal:     1000,
			ChecksFailed:    2,
			UpRatio24h:      0.995,
			ChecksTotal24h:  100,
			ChecksFailed24h: 1,
		},
		ActiveConns: 2,
		TotalConns:  9000,
	}, 0, []control.NetworkStatus{
		{Network: "tcp4", Selected: &control.SelectedNodeStatus{Index: 0}},
		{Network: "tcp6"},
		{Network: "udp4"},
		{Network: "udp6"},
	})
	want := []string{
		"node-a", "-", "vless", "connected", "healthy", "all", "tcp4",
		"42/45/50", "99.8% (2/1000)", "99.5% (1/100)", "-", "-", "-", "-", "2/9000",
	}
	if len(row) != len(want) {
		t.Fatalf("nodeStatusRow() has %d cells, want %d", len(row), len(want))
	}
	for i, expected := range want {
		if got := row[i].(string); got != expected {
			t.Errorf("nodeStatusRow()[%d] = %q, want %q", i, got, expected)
		}
	}
}

func TestNodeStatusRowOnlyShowsConfirmedSupport(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = false
	defer func() { colorsEnabled = previousColorsEnabled }()

	row := nodeStatusRow(control.NodeStatus{
		Name: "tor",
		Networks: []control.NodeNetworkStatus{
			{Network: "tcp4", SupportState: "confirmed"},
			{Network: "tcp6", SupportState: "confirmed"},
			{Network: "udp4", SupportState: "unknown"},
			{Network: "udp6", SupportState: "unsupported"},
		},
	}, 0, nil)
	if got := row[5].(string); got != "all tcp" {
		t.Fatalf("support = %q, want only confirmed modes", got)
	}
}

func TestCompactNetworks(t *testing.T) {
	tests := []struct {
		name     string
		networks []string
		want     string
	}{
		{name: "none", want: "-"},
		{name: "all", networks: []string{"tcp4", "tcp6", "udp4", "udp6"}, want: "all"},
		{name: "tcp", networks: []string{"tcp4", "tcp6"}, want: "all tcp"},
		{name: "udp", networks: []string{"udp4", "udp6"}, want: "all udp"},
		{name: "ipv4", networks: []string{"tcp4", "udp4"}, want: "all ipv4"},
		{name: "ipv6", networks: []string{"tcp6", "udp6"}, want: "all ipv6"},
		{name: "pair and remainder", networks: []string{"tcp4", "tcp6", "udp4"}, want: "all tcp,udp4"},
		{name: "mixed", networks: []string{"tcp4", "udp6"}, want: "tcp4,udp6"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compactNetworks(tt.networks); got != tt.want {
				t.Fatalf("compactNetworks() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCompactNodeStatusRow(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = false
	defer func() { colorsEnabled = previousColorsEnabled }()

	priority := 2
	row := compactNodeStatusRow(control.NodeStatus{
		Name:       "node-a",
		Protocol:   "shadowsocks(smux)",
		CheckAsync: true,
		Annotation: &control.NodeAnnotationStatus{
			AddLatency:          "30ms",
			Priority:            &priority,
			PriorityConditional: true,
		},
		Session:  &control.SessionStatus{State: control.SessionConnected},
		Networks: []control.NodeNetworkStatus{{Network: "tcp4", SupportState: control.NetworkSupportConfirmed}, {Network: "tcp6", SupportState: control.NetworkSupportConfirmed}, {Network: "udp4", SupportState: control.NetworkSupportConfirmed}, {Network: "udp6", SupportState: control.NetworkSupportConfirmed}},
		Health: &control.NodeHealthStatus{
			State:          control.NodeHealthHealthy,
			Latency:        &control.LatencyStatus{LastMs: 42, Average10Ms: 45, MovingAverageMs: 50},
			UpRatio:        0.998,
			UpRatio24h:     0.995,
			ChecksTotal:    1000,
			ChecksTotal24h: 100,
		},
		ActiveConns: 2,
		TotalConns:  9000,
	}, 0, []control.NetworkStatus{
		{Network: "tcp4", Selected: &control.SelectedNodeStatus{Index: 0}},
		{Network: "tcp6", Selected: &control.SelectedNodeStatus{Index: 0}},
		{Network: "udp4", Selected: &control.SelectedNodeStatus{Index: 0}},
		{Network: "udp6", Selected: &control.SelectedNodeStatus{Index: 0}},
	})
	want := []string{"node-a [p=2*,+30ms,async]", "shadowsocks(smux)", "healthy", "all", "all", "42/45/50", "99.8/99.5%", "2/9000"}
	if len(row) != len(want) {
		t.Fatalf("compactNodeStatusRow() has %d cells, want %d", len(row), len(want))
	}
	for i, expected := range want {
		if got := row[i].(string); got != expected {
			t.Errorf("compactNodeStatusRow()[%d] = %q, want %q", i, got, expected)
		}
	}
}

func TestAnnotatedNodeLabelShowsNodeCheckAsyncWithoutPathAnnotation(t *testing.T) {
	if got := annotatedNodeLabel(control.NodeStatus{Name: "node-a", CheckAsync: true}, 0); got != "node-a [async]" {
		t.Fatalf("annotated node label = %q, want %q", got, "node-a [async]")
	}
}

func TestCompactNodeStatePrioritizesSessionFailure(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = false
	defer func() { colorsEnabled = previousColorsEnabled }()

	status := control.NodeStatus{
		Session: &control.SessionStatus{State: control.SessionDisconnected},
		Health:  &control.NodeHealthStatus{State: control.NodeHealthHealthy},
	}
	if got := compactNodeState(status); got != "disconnected" {
		t.Fatalf("compact state = %q, want disconnected", got)
	}
}

func TestCompactNodeStateColorsConnectingUnhealthyRed(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = true
	defer func() { colorsEnabled = previousColorsEnabled }()

	status := control.NodeStatus{
		Session: &control.SessionStatus{State: control.SessionConnecting},
		Health:  &control.NodeHealthStatus{State: control.NodeHealthUnhealthy},
	}
	if got := compactNodeState(status); !strings.Contains(got, "\x1b[31m") {
		t.Fatalf("compact state = %q, want red connecting state", got)
	}
}

func TestCompactFailure(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = false
	defer func() { colorsEnabled = previousColorsEnabled }()

	now := time.Date(2026, time.August, 26, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		health *control.NodeHealthStatus
		want   string
	}{
		{name: "none", health: &control.NodeHealthStatus{UpRatio24h: 1}, want: "-"},
		{
			name: "recent episode",
			health: &control.NodeHealthStatus{
				State:      control.NodeHealthHealthy,
				UpRatio24h: 0.99,
				Failure: &control.FailureStatus{
					StartedAt:  now.Add(-10 * time.Minute),
					DurationMs: (2 * time.Minute).Milliseconds(),
				},
			},
			want: "10m0s/2m0s",
		},
		{
			name: "zero duration",
			health: &control.NodeHealthStatus{
				UpRatio24h: 1,
				Failure:    &control.FailureStatus{StartedAt: now.Add(-8 * time.Minute)},
			},
			want: "8m0s/0s",
		},
		{
			name: "failed checks without episode",
			health: &control.NodeHealthStatus{
				UpRatio24h:      1,
				ChecksFailed24h: 2,
			},
			want: "2chk",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compactFailure(tt.health, now); got != tt.want {
				t.Fatalf("compactFailure() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecentFailureEpisodeOverlap(t *testing.T) {
	now := time.Date(2026, time.August, 26, 12, 0, 0, 0, time.UTC)
	cutoff := now.Add(-24 * time.Hour)
	tests := []struct {
		name    string
		failure *control.FailureStatus
		want    bool
	}{
		{name: "point at cutoff", failure: &control.FailureStatus{StartedAt: cutoff}, want: true},
		{name: "point before cutoff", failure: &control.FailureStatus{StartedAt: cutoff.Add(-time.Nanosecond)}},
		{name: "episode overlaps cutoff", failure: &control.FailureStatus{StartedAt: cutoff.Add(-time.Hour), DurationMs: (2 * time.Hour).Milliseconds()}, want: true},
		{name: "episode ends at cutoff", failure: &control.FailureStatus{StartedAt: cutoff.Add(-time.Hour), DurationMs: time.Hour.Milliseconds()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			health := &control.NodeHealthStatus{UpRatio24h: 1, Failure: tt.failure}
			if got := recentFailureEpisode(health, now); got != tt.want {
				t.Fatalf("recentFailureEpisode() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestNodeStatusRowHighlightsAvg10Failure(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = true
	defer func() { colorsEnabled = previousColorsEnabled }()

	failedAt := time.Now()
	row := nodeStatusRow(control.NodeStatus{
		ID:   "node-a-id",
		Name: "node-a",
		Health: &control.NodeHealthStatus{
			State: control.NodeHealthHealthy,
			Latency: &control.LatencyStatus{
				LastMs:          42,
				Average10Ms:     60045,
				MovingAverageMs: 60045,
				Average10Failed: true,
			},
			Failure: &control.FailureStatus{StartedAt: failedAt, DurationMs: (2 * time.Minute).Milliseconds()},
		},
	}, 0, []control.NetworkStatus{
		{Network: "tcp4", Selected: &control.SelectedNodeStatus{Index: 0}},
	})
	tests := []struct {
		cell int
		ansi string
	}{
		{cell: 0, ansi: "\x1b[36m"},
		{cell: 4, ansi: "\x1b[32m"},
		{cell: 7, ansi: "\x1b[91;1m"},
	}
	for _, tt := range tests {
		if got := row[tt.cell].(string); !strings.Contains(got, tt.ansi) {
			t.Errorf("nodeStatusRow()[%d] = %q, want ANSI prefix %q", tt.cell, got, tt.ansi)
		}
	}
	if got := row[11].(string); strings.Contains(got, "\x1b[") {
		t.Errorf("completed failure episode should not inherit avg10 coloring: %q", got)
	}
}

func TestNodeStatusRowFormatsFailureEpisode(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = false
	defer func() { colorsEnabled = previousColorsEnabled }()

	startedAt := time.Now().Add(-10 * time.Minute)
	row := nodeStatusRow(control.NodeStatus{
		Name: "node-a",
		Health: &control.NodeHealthStatus{
			Failure: &control.FailureStatus{StartedAt: startedAt, DurationMs: (2 * time.Minute).Milliseconds()},
		},
	}, 0, nil)
	failure := row[11].(string)
	if !strings.Contains(failure, " / 2m0s") {
		t.Fatalf("failure episode = %q, want start and duration", failure)
	}
	if strings.Contains(failure, "chk") {
		t.Fatalf("failure episode should not associate sample count with its start: %q", failure)
	}

	row = nodeStatusRow(control.NodeStatus{
		Name:   "node-a",
		Health: &control.NodeHealthStatus{Failure: &control.FailureStatus{StartedAt: startedAt}},
	}, 0, nil)
	if got := row[11].(string); !strings.HasSuffix(got, " / 0s") {
		t.Fatalf("zero-duration failure episode = %q, want 0s", got)
	}
}

func TestNetworkStatusRowUnsupported(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = false
	defer func() { colorsEnabled = previousColorsEnabled }()

	row := networkStatusRow(control.NetworkStatus{
		Network:      "tcp6",
		SupportState: "unsupported",
		ActiveConns:  2,
		TotalConns:   10,
	}, nil)
	want := []string{"tcp6", "unsupported", "-", "2/10"}
	for i, expected := range want {
		if got := row[i].(string); got != expected {
			t.Errorf("networkStatusRow()[%d] = %q, want %q", i, got, expected)
		}
	}
}

func TestNetworkStatusRowLabelsUnnamedSelection(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = false
	defer func() { colorsEnabled = previousColorsEnabled }()

	row := networkStatusRow(control.NetworkStatus{
		Network:  "tcp4",
		Selected: &control.SelectedNodeStatus{Index: 0},
	}, []control.NodeStatus{{Address: "proxy.example:443"}})
	if got := row[2].(string); got != "proxy.example:443" {
		t.Fatalf("selected unnamed node = %q, want address", got)
	}
}

func TestStatusSummary(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = false
	defer func() { colorsEnabled = previousColorsEnabled }()

	tests := []struct {
		name     string
		snapshot control.StatusSnapshot
		want     string
	}{
		{
			name:     "healthy",
			snapshot: control.StatusSnapshot{Health: control.HealthHealthy},
			want:     "healthy",
		},
		{
			name: "warning",
			snapshot: control.StatusSnapshot{
				Health: control.HealthWarning,
				Groups: []control.GroupStatus{{Name: "optional", Health: control.HealthWarning}},
			},
			want: "warning (warning groups: optional)",
		},
		{
			name: "degraded with warnings",
			snapshot: control.StatusSnapshot{
				Health: control.HealthDegraded,
				Groups: []control.GroupStatus{
					{Name: "optional", Health: control.HealthWarning},
					{Name: "proxy-a", Health: control.HealthDegraded},
					{Name: "proxy-b", Health: control.HealthDegraded},
				},
			},
			want: "degraded (degraded groups: proxy-a, proxy-b; warning groups: optional)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := statusSummary(&tt.snapshot); got != tt.want {
				t.Fatalf("statusSummary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestColorHealth(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = true
	defer func() { colorsEnabled = previousColorsEnabled }()

	tests := []struct {
		health control.HealthStatus
		ansi   string
	}{
		{health: control.HealthHealthy, ansi: "\x1b[32m"},
		{health: control.HealthWarning, ansi: "\x1b[33m"},
		{health: control.HealthDegraded, ansi: "\x1b[31m"},
	}
	for _, tt := range tests {
		if got := colorHealth(tt.health); !strings.Contains(got, tt.ansi) {
			t.Errorf("colorHealth(%q) = %q, want ANSI prefix %q", tt.health, got, tt.ansi)
		}
	}
}

func TestColorNodeHealth(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = true
	defer func() { colorsEnabled = previousColorsEnabled }()

	tests := []struct {
		health control.NodeHealthState
		ansi   string
	}{
		{health: control.NodeHealthHealthy, ansi: "\x1b[32m"},
		{health: control.NodeHealthUnknown, ansi: "\x1b[33m"},
		{health: control.NodeHealthUnhealthy, ansi: "\x1b[31m"},
	}
	for _, tt := range tests {
		if got := colorNodeHealth(tt.health); !strings.Contains(got, tt.ansi) {
			t.Errorf("colorNodeHealth(%q) = %q, want ANSI prefix %q", tt.health, got, tt.ansi)
		}
	}
}

func TestDecodeStatusRejectsNonCurrentSchema(t *testing.T) {
	valid := `{
		"version":"test",
		"health":"healthy",
		"started_at":"2026-08-25T00:00:00Z",
		"active_conns":0,
		"total_conns":0,
		"networks":[
			{"network":"tcp4","active_conns":0,"total_conns":0},
			{"network":"tcp6","active_conns":0,"total_conns":0},
			{"network":"udp4","active_conns":0,"total_conns":0},
			{"network":"udp6","active_conns":0,"total_conns":0}
		],
		"tables":[],
		"groups":[]
	}`
	if _, err := decodeStatus(strings.NewReader(valid)); err != nil {
		t.Fatalf("decode current status: %v", err)
	}

	tests := map[string]string{
		"unknown field":  strings.Replace(valid, `"groups":[]`, `"extra":true,"groups":[]`, 1),
		"missing health": strings.Replace(valid, `"health":"healthy",`, "", 1),
		"invalid selection": strings.Replace(valid, `"groups":[]`, `"groups":[{
			"name":"group","policy":"fixed","health":"healthy",
			"networks":[{"network":"tcp4","support_state":"confirmed","selected":{"index":0},"active_conns":0,"total_conns":0}],
			"nodes":[]
		}]`, 1),
		"trailing value": valid + `{}`,
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeStatus(strings.NewReader(payload)); err == nil {
				t.Fatal("decodeStatus unexpectedly accepted invalid status")
			}
		})
	}
}
