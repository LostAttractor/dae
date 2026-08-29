/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/control"
)

func withoutStatusColors(t *testing.T) {
	t.Helper()
	previous := colorsEnabled
	colorsEnabled = false
	t.Cleanup(func() { colorsEnabled = previous })
}

func testNodeStatus(now time.Time) control.NodeStatus {
	priority := 2
	return control.NodeStatus{
		ID:                 "node-id",
		Name:               "node-a",
		Subtag:             "sub",
		Protocol:           "ss",
		Annotation:         &control.NodeAnnotationStatus{AddLatency: "30ms", Priority: &priority, PriorityConditional: true},
		ChecksConnectivity: true,
		CheckAsync:         true,
		Session:            "connected",
		Healthy:            true,
		Availability: stats.Availability{
			Seen:                 true,
			Alive:                true,
			AliveSince:           now.Add(-time.Hour),
			LastFailureStartedAt: now.Add(-2 * time.Hour),
			LastFailureDuration:  10 * time.Minute,
			LastCheckAt:          now.Add(-time.Minute),
			LastConnFailAt:       now.Add(-30 * time.Minute),
			UpRatio:              0.99,
			ChecksTotal:          20,
			ChecksFailed:         1,
			ChecksSinceAlive:     5,
			Recent24h: stats.AvailabilityWindow{
				UpRatio: 0.98, ChecksTotal: 10, ChecksFailed: 1,
			},
		},
		Latency: &dialer.LatencyStats{
			Last: 10 * time.Millisecond, Avg10: 20 * time.Millisecond, MovingAvg: 30 * time.Millisecond,
		},
		Support: control.NetworkValues[dialer.NetworkSupportState]{
			dialer.NetworkSupportConfirmed,
			dialer.NetworkSupportConfirmed,
			dialer.NetworkSupportUnsupported,
			dialer.NetworkSupportUnknown,
		},
		Stats: stats.PathStats{
			ActiveConnections: 2,
			TotalConnections:  3,
			TrafficCounters:   stats.TrafficCounters{UploadBytes: 1024, DownloadBytes: 2048},
			TrafficRate:       stats.TrafficRate{UploadBytesPerSecond: 100, DownloadBytesPerSecond: 200},
		},
	}
}

func TestTableUsageRow(t *testing.T) {
	withoutStatusColors(t)
	row := tableUsageRow(control.TableUsage{
		Name: "domain-history", Used: 32768, Limit: 60000,
		Breakdown: &control.TableUsageBreakdown{Live: 5536, Retained: 27232, LimitGC: 123},
	})
	want := []string{"domain-history", "32768 (LAZY)", "60000", "54.6%", "5536/27232", "123"}
	for index, expected := range want {
		if got := fmt.Sprint(row[index]); got != expected {
			t.Errorf("tableUsageRow()[%d] = %q, want %q", index, got, expected)
		}
	}
}

func TestNodeRowsUseRawState(t *testing.T) {
	withoutStatusColors(t)
	now := time.Now()
	node := testNodeStatus(now)
	selected := control.NetworkValues[string]{"node-id", "node-id", "", ""}

	verbose := nodeStatusRow(node, 0, selected)
	checks := map[int]string{
		0:  "node-a [p=2*,+30ms,async]",
		3:  "connected",
		4:  "healthy",
		5:  "all tcp",
		6:  "all tcp",
		7:  "10/20/30",
		14: "2/3",
		15: "100B/200B",
		16: "1.00K/2.00K",
	}
	for index, expected := range checks {
		if got := fmt.Sprint(verbose[index]); got != expected {
			t.Errorf("nodeStatusRow()[%d] = %q, want %q", index, got, expected)
		}
	}

	compact := compactNodeStatusRow(node, 0, selected)
	if got := fmt.Sprint(compact[2]); got != "healthy" {
		t.Fatalf("compact state = %q, want healthy", got)
	}
	if got := fmt.Sprint(compact[6]); got != "99.0/98.0%" {
		t.Fatalf("compact ratios = %q", got)
	}
}

func TestNodeStatePrefersSessionFailure(t *testing.T) {
	withoutStatusColors(t)
	node := testNodeStatus(time.Now())
	node.Healthy = false
	node.Session = "disconnected"
	if got := compactNodeState(node); got != "disconnected" {
		t.Fatalf("state = %q, want disconnected", got)
	}
	node.Session = "connecting"
	node.Healthy = true
	if got := compactNodeState(node); got != "connecting" {
		t.Fatalf("state = %q, want connecting", got)
	}
}

func TestNetworkStatusRowDerivesSupportAndSelection(t *testing.T) {
	withoutStatusColors(t)
	node := testNodeStatus(time.Now())
	group := control.GroupStatus{
		Nodes:           []control.NodeStatus{node},
		Networks:        make(control.NetworkValues[stats.PathStats], common.NetworkTypeCount),
		SelectedNodeIDs: make(control.NetworkValues[string], common.NetworkTypeCount),
	}
	group.SelectedNodeIDs[common.NetworkTCP4] = node.ID
	group.Networks[common.NetworkTCP4] = stats.PathStats{ActiveConnections: 2, TotalConnections: 5}
	row := networkStatusRow(group, common.NetworkTCP4)
	want := []string{"tcp4", "confirmed", "node-a", "2/5"}
	for index, expected := range want {
		if got := fmt.Sprint(row[index]); got != expected {
			t.Errorf("networkStatusRow()[%d] = %q, want %q", index, got, expected)
		}
	}
}

func TestHealthDerivedFromRawGroups(t *testing.T) {
	tests := []struct {
		group control.GroupStatus
		want  healthStatus
	}{
		{group: control.GroupStatus{}, want: healthHealthy},
		{group: control.GroupStatus{ChecksConnectivity: true, Critical: true, Connectivity: stats.GroupStateAvailable}, want: healthHealthy},
		{group: control.GroupStatus{ChecksConnectivity: true, Critical: true, Connectivity: stats.GroupStateChecking}, want: healthWarning},
		{group: control.GroupStatus{ChecksConnectivity: true, Connectivity: stats.GroupStateUnavailable}, want: healthWarning},
		{group: control.GroupStatus{ChecksConnectivity: true, Critical: true, Connectivity: stats.GroupStateUnavailable}, want: healthDegraded},
	}
	for _, test := range tests {
		if got := groupHealth(test.group); got != test.want {
			t.Errorf("groupHealth(%+v) = %q, want %q", test.group, got, test.want)
		}
	}
	if got := statusHealth([]control.GroupStatus{tests[2].group, tests[4].group}); got != healthDegraded {
		t.Fatalf("status health = %q, want degraded", got)
	}
}

func TestStatusSummaryListsAffectedGroups(t *testing.T) {
	withoutStatusColors(t)
	snapshot := &control.StatusSnapshot{Groups: []control.GroupStatus{
		{Name: "optional", ChecksConnectivity: true, Connectivity: stats.GroupStateUnavailable},
		{Name: "proxy", ChecksConnectivity: true, Critical: true, Connectivity: stats.GroupStateUnavailable},
	}}
	want := "degraded (degraded groups: proxy; warning groups: optional)"
	if got := statusSummary(snapshot); got != want {
		t.Fatalf("statusSummary() = %q, want %q", got, want)
	}
}

func TestRecentFailureUsesRawAvailability(t *testing.T) {
	now := time.Now()
	node := testNodeStatus(now)
	if !recentNodeFailure(node, now) {
		t.Fatal("recent failure was not detected")
	}
	node.Availability.Recent24h = stats.AvailabilityWindow{UpRatio: 1}
	node.Availability.LastFailureStartedAt = now.Add(-48 * time.Hour)
	node.Availability.LastFailureDuration = time.Minute
	if recentNodeFailure(node, now) {
		t.Fatal("old failure was reported as recent")
	}
}

func TestNetworkCompaction(t *testing.T) {
	tests := map[uint8]string{
		0: "-", 0b1111: "all", 0b0011: "all tcp", 0b1100: "all udp",
		0b0101: "all ipv4", 0b1010: "all ipv6", 0b1001: "tcp4,udp6",
	}
	for mask, want := range tests {
		if got := compactNetworks(mask); got != want {
			t.Errorf("compactNetworks(%04b) = %q, want %q", mask, got, want)
		}
	}
}

func TestTrafficFormatting(t *testing.T) {
	value := stats.PathStats{TrafficCounters: stats.TrafficCounters{UploadBytes: 3 * 1024, DownloadBytes: 5 * 1024}}
	if got, want := formatTrafficSummary(value), "rate - U/D, total 3.00K/5.00K U/D"; got != want {
		t.Fatalf("formatTrafficSummary() = %q, want %q", got, want)
	}
}

func validWireStatus() control.StatusSnapshot {
	return control.StatusSnapshot{
		Schema:    control.StatusSchemaVersion,
		Version:   "test",
		StartedAt: time.Now(),
		Networks:  make(control.NetworkValues[stats.PathStats], common.NetworkTypeCount),
		Groups: []control.GroupStatus{{
			Name:            "direct",
			TargetKind:      "builtin",
			Networks:        make(control.NetworkValues[stats.PathStats], common.NetworkTypeCount),
			SelectedNodeIDs: make(control.NetworkValues[string], common.NetworkTypeCount),
			Nodes: []control.NodeStatus{{
				ID:      "direct",
				Support: control.NetworkValues[dialer.NetworkSupportState]{"unknown", "unknown", "unknown", "unknown"},
			}},
		}},
	}
}

func TestDecodeStatusRejectsTrailingJSON(t *testing.T) {
	payload, err := json.Marshal(validWireStatus())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := decodeStatus(strings.NewReader(string(payload)))
	if err != nil || snapshot.Version != "test" {
		t.Fatalf("decodeStatus() = %+v, %v", snapshot, err)
	}
	if _, err := decodeStatus(strings.NewReader(`{} {}`)); err == nil {
		t.Fatal("decodeStatus accepted multiple JSON values")
	}
}

func TestValidateStatusRejectsInvalidNodeReferences(t *testing.T) {
	snapshot := validWireStatus()
	snapshot.Groups[0].SelectedNodeIDs[0] = "missing"
	if err := validateStatus(&snapshot); err == nil {
		t.Fatal("validateStatus accepted an unknown selected node")
	}

	snapshot = validWireStatus()
	snapshot.Groups[0].Nodes[0].ID = ""
	if err := validateStatus(&snapshot); err == nil {
		t.Fatal("validateStatus accepted an empty node id")
	}

	snapshot = validWireStatus()
	snapshot.Groups[0].Nodes[0].Support = snapshot.Groups[0].Nodes[0].Support[:3]
	if err := validateStatus(&snapshot); err == nil {
		t.Fatal("validateStatus accepted a short support list")
	}
}

func TestDecodeStatusRejectsInvalidSchema(t *testing.T) {
	for _, payload := range []string{
		`{"schema":1,"version":"test","started_at":"2026-01-01T00:00:00Z","networks":[],"groups":[]}`,
		`{"schema":1,"version":"test","started_at":"2026-01-01T00:00:00Z","networks":[{},{},{},{}],"groups":[],"typo":true}`,
		`{"version":"test"}`,
	} {
		if _, err := decodeStatus(strings.NewReader(payload)); err == nil {
			t.Fatalf("decodeStatus accepted invalid response %s", payload)
		}
	}
}

func TestDecodeStatusRejectsMissingRequiredFields(t *testing.T) {
	tests := map[string]func(map[string]any){
		"process stats": func(status map[string]any) {
			delete(status, "stats")
		},
		"group critical": func(status map[string]any) {
			delete(status["groups"].([]any)[0].(map[string]any), "critical")
		},
		"group checks": func(status map[string]any) {
			delete(status["groups"].([]any)[0].(map[string]any), "checks_connectivity")
		},
		"group stats": func(status map[string]any) {
			delete(status["groups"].([]any)[0].(map[string]any), "stats")
		},
		"node stats": func(status map[string]any) {
			group := status["groups"].([]any)[0].(map[string]any)
			delete(group["nodes"].([]any)[0].(map[string]any), "stats")
		},
		"node health": func(status map[string]any) {
			group := status["groups"].([]any)[0].(map[string]any)
			delete(group["nodes"].([]any)[0].(map[string]any), "healthy")
		},
		"stats field": func(status map[string]any) {
			delete(status["stats"].(map[string]any), "upload_bytes")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			payload, err := json.Marshal(validWireStatus())
			if err != nil {
				t.Fatal(err)
			}
			var status map[string]any
			if err := json.Unmarshal(payload, &status); err != nil {
				t.Fatal(err)
			}
			mutate(status)
			payload, err = json.Marshal(status)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeStatus(strings.NewReader(string(payload))); err == nil {
				t.Fatal("decodeStatus accepted a response with a missing required field")
			}
		})
	}
}
