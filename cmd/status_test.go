/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	jsonv1 "encoding/json"
	json "encoding/json/v2"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/control"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

func withoutStatusColors(t *testing.T) {
	t.Helper()
	previous := colorsEnabled
	colorsEnabled = false
	t.Cleanup(func() { colorsEnabled = previous })
}

func withStatusTerminalWidth(t *testing.T, width int) {
	t.Helper()
	previous := getStatusTerminalWidth
	getStatusTerminalWidth = func() int { return width }
	t.Cleanup(func() { getStatusTerminalWidth = previous })
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
			ActiveConnections:   2,
			TotalConnections:    3,
			FallbackConnections: 1,
			TrafficCounters:     stats.TrafficCounters{UploadBytes: 1024, DownloadBytes: 2048},
			History: stats.TrafficHistory{
				UploadBytesPerSecond: []uint64{100, 100}, DownloadBytesPerSecond: []uint64{200, 200},
			},
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

func TestStatusTableClipsRowsToFitTerminal(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 16)
	header := table.Row{"FIRST", "SECOND", "XYZ"}
	rows := []table.Row{{"a", "bb", "cc"}}
	rendered := renderStatusTable(header, rows, nil)
	lines := strings.Split(rendered, "\n")
	if len(lines) != 2 {
		t.Fatalf("adaptive table wrapped into %d lines:\n%s", len(lines), rendered)
	}
	if firstLine := lines[0]; firstLine != "FIRST  SECOND  X" {
		t.Fatalf("adaptive table did not use the full terminal width: %q", firstLine)
	}
	for line := range strings.SplitSeq(rendered, "\n") {
		line = strings.TrimRight(line, " ")
		if width := text.StringWidth(line); width > 16 {
			t.Fatalf("rendered line width = %d, want <= 16: %q", width, line)
		}
	}
	getStatusTerminalWidth = func() int { return 5 }
	rendered = renderStatusTable(table.Row{"LONG HEADER"}, nil, nil)
	if rendered != "LONG" {
		t.Fatalf("single wide column was not clipped to the terminal: %q", rendered)
	}

	colorsEnabled = true
	if got := truncateStatusCell(colorize("网络节点", text.FgGreen), 5); text.StringWidthWithoutEscSequences(got) != 5 || text.StripEscape(got) != "网络…" {
		t.Fatalf("ANSI/CJK truncation = %q", got)
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
		5:  "all tcp(*)",
		6:  "10/20/30",
		13: "2/3 (fb 1)",
		14: "↑..........▅▅ 800/800bps ↓..........██ 1.60/1.60Kbps",
		15: "↑1.00K ↓2.00K",
	}
	for index, expected := range checks {
		if got := fmt.Sprint(verbose[index]); got != expected {
			t.Errorf("nodeStatusRow()[%d] = %q, want %q", index, got, expected)
		}
	}

	compact := compactNodeStatusRow(node, 0, selected, false, now)
	if got := fmt.Sprint(compact[2]); got != "healthy" {
		t.Fatalf("compact state = %q, want healthy", got)
	}
	if got := fmt.Sprint(compact[5]); got != "99.0/98.0%" {
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
		Nodes: []control.NodeStatus{node},
	}
	group.SelectedNodeIDs[common.NetworkTCP4] = node.ID
	group.Networks[common.NetworkTCP4] = stats.PathStats{ActiveConnections: 2, TotalConnections: 5}
	row := networkStatusRow(group, common.NetworkTCP4)
	want := []string{"tcp4", "node-a", "2/5"}
	for index, expected := range want {
		if got := fmt.Sprint(row[index]); got != expected {
			t.Errorf("networkStatusRow()[%d] = %q, want %q", index, got, expected)
		}
	}
}

func TestNetworkStatusRowExplainsMissingSelection(t *testing.T) {
	withoutStatusColors(t)
	node := testNodeStatus(time.Now())
	group := control.GroupStatus{
		Policy: "random",
		Nodes:  []control.NodeStatus{node},
	}
	if got := fmt.Sprint(networkStatusRow(group, common.NetworkTCP4)[1]); got != "available" {
		t.Fatalf("usable route = %q, want available", got)
	}
	group.Policy = "fixed"
	nonCandidate := testNodeStatus(time.Now())
	nonCandidate.ID = "non-candidate"
	group.Nodes = append(group.Nodes, nonCandidate)
	group.Nodes[0].Healthy = false
	if got := fmt.Sprint(networkStatusRow(group, common.NetworkTCP4)[1]); got != "down" {
		t.Fatalf("fixed route with usable non-candidate = %q, want down", got)
	}
	group.Policy = "random"
	group.Nodes[1].Healthy = false
	if got := fmt.Sprint(networkStatusRow(group, common.NetworkTCP4)[1]); got != "down" {
		t.Fatalf("unusable dynamic route = %q, want down", got)
	}
	if got := len(checkedNetworkRows(group, false)); got != 2 {
		t.Fatalf("compact network rows = %d, want two confirmed networks", got)
	}
	if got := len(checkedNetworkRows(group, true)); got != common.NetworkTypeCount {
		t.Fatalf("verbose network rows = %d, want %d", got, common.NetworkTypeCount)
	}
}

func TestHealthDerivedFromRawGroups(t *testing.T) {
	available := testNodeStatus(time.Now())
	available.Support[common.NetworkTCP6] = dialer.NetworkSupportUnsupported
	down := testNodeStatus(time.Now())
	down.ID = "down"
	down.Healthy = false
	down.Support[common.NetworkTCP4] = dialer.NetworkSupportUnsupported
	tests := []struct {
		group control.GroupStatus
		want  healthStatus
	}{
		{group: control.GroupStatus{}, want: healthHealthy},
		{group: control.GroupStatus{ChecksConnectivity: true, Critical: true, Connectivity: stats.GroupStateAvailable}, want: healthHealthy},
		{group: control.GroupStatus{ChecksConnectivity: true, Critical: true, Connectivity: stats.GroupStateChecking}, want: healthWarning},
		{group: control.GroupStatus{ChecksConnectivity: true, Connectivity: stats.GroupStateUnavailable}, want: healthWarning},
		{group: control.GroupStatus{ChecksConnectivity: true, Critical: true, Connectivity: stats.GroupStateUnavailable}, want: healthDegraded},
		{group: control.GroupStatus{ChecksConnectivity: true, Connectivity: stats.GroupStateAvailable, Nodes: []control.NodeStatus{available, down}, SelectedNodeIDs: control.NetworkValues[string]{available.ID}}, want: healthWarning},
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

func TestCompactFailureFollowsAvailability(t *testing.T) {
	withoutStatusColors(t)
	now := time.Now()
	node := testNodeStatus(now)
	group := control.GroupStatus{
		Nodes:           []control.NodeStatus{node},
		SelectedNodeIDs: control.NetworkValues[string]{node.ID, node.ID, "", ""},
	}
	header, rows := nodeTable(group, false, now)
	if got := fmt.Sprint(header[6]); got != "FAIL A/D" {
		t.Fatalf("column after UP/24H = %q, want FAIL A/D", got)
	}
	if len(rows) != 1 || len(rows[0]) != len(header) {
		t.Fatalf("compact table dimensions = header %d, rows %+v", len(header), rows)
	}
	if got := fmt.Sprint(rows[0][6]); got == "-" {
		t.Fatalf("failure cell = %q, want recent failure", got)
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
	if got, want := formatTrafficSummary(value), "total ↑3.00K ↓5.00K"; got != want {
		t.Fatalf("formatTrafficSummary() = %q, want %q", got, want)
	}
	if got, want := formatBitRatePair(1_250_000, 12_500_000), "10.0/100Mbps"; got != want {
		t.Fatalf("rate threshold pair = %q, want %q", got, want)
	}
	if got, want := formatBitRatePair(100, 110), "800/880bps"; got != want {
		t.Fatalf("same-unit rate pair = %q, want %q", got, want)
	}
	if got, want := formatBitRatePair(100, 1_250_000), "800bps/10.0Mbps"; got != want {
		t.Fatalf("mixed-unit rate pair = %q, want %q", got, want)
	}
	maximum := ^uint64(0)
	if got := trafficAverage([]uint64{maximum, maximum}); got != maximum {
		t.Fatalf("overflow-safe average = %d, want %d", got, maximum)
	}
}

func TestTrafficAndNetworkColorsCoverTheirCells(t *testing.T) {
	previous := colorsEnabled
	colorsEnabled = true
	t.Cleanup(func() { colorsEnabled = previous })

	traffic := trafficSparkline([]uint64{0, 1, 1_250_000, 12_500_000}, 12_500_000)
	if !strings.Contains(traffic, "\x1b[90m▁") || !strings.Contains(traffic, "\x1b[32m▂") ||
		!strings.Contains(traffic, "\x1b[33m▂") || !strings.Contains(traffic, "\x1b[31m█") {
		t.Fatalf("traffic speed levels are not colored independently: %q", traffic)
	}

	node := testNodeStatus(time.Now())
	networks, selected := nodeNetworks(node, control.NetworkValues[string]{node.ID, node.ID, "", ""})
	if !selected || !strings.HasPrefix(networks, "\x1b[") || text.StripEscape(networks) != "all tcp(*)" {
		t.Fatalf("NETWORKS cell is not fully colored: %q", networks)
	}
}

func TestNodeNetworksMergesSupportAndSelection(t *testing.T) {
	withoutStatusColors(t)
	node := testNodeStatus(time.Now())
	for _, test := range []struct {
		support  control.NetworkValues[dialer.NetworkSupportState]
		selected control.NetworkValues[string]
		want     string
	}{
		{
			support: control.NetworkValues[dialer.NetworkSupportState]{
				dialer.NetworkSupportConfirmed, dialer.NetworkSupportConfirmed,
				dialer.NetworkSupportConfirmed, dialer.NetworkSupportConfirmed,
			},
			selected: control.NetworkValues[string]{"node-id", "node-id", "node-id", "node-id"},
			want:     "all(*)",
		},
		{selected: control.NetworkValues[string]{"node-id", "node-id", "", ""}, want: "all tcp(*)"},
		{selected: control.NetworkValues[string]{"node-id", "", "", ""}, want: "all tcp(tcp4*)"},
		{selected: control.NetworkValues[string]{"", "node-id", "", ""}, want: "all tcp(tcp6*)"},
		{selected: control.NetworkValues[string]{}, want: "all tcp"},
	} {
		if test.support == (control.NetworkValues[dialer.NetworkSupportState]{}) {
			node.Support = testNodeStatus(time.Now()).Support
		} else {
			node.Support = test.support
		}
		if got, _ := nodeNetworks(node, test.selected); got != test.want {
			t.Errorf("nodeNetworks() = %q, want %q", got, test.want)
		}
	}
}

func validWireStatus() control.StatusSnapshot {
	return control.StatusSnapshot{
		Schema:    control.StatusSchemaVersion,
		Version:   "test",
		StartedAt: time.Now(),
		Groups: []control.GroupStatus{{
			Name:       "direct",
			TargetKind: "builtin",
			Nodes: []control.NodeStatus{{
				ID:      "direct",
				Support: control.NetworkValues[dialer.NetworkSupportState]{"unknown", "unknown", "unknown", "unknown"},
			}},
		}},
	}
}

func TestDecodeStatusRejectsUnknownAndTrailingJSON(t *testing.T) {
	want := validWireStatus()
	want.Groups[0].Nodes[0].Latency = &dialer.LatencyStats{Last: time.Second}
	payload, err := json.Marshal(want, jsonv1.FormatDurationAsNano(true))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"last":1000000000`) {
		t.Fatalf("duration is not encoded in nanoseconds: %s", payload)
	}
	snapshot, err := decodeStatus(strings.NewReader(string(payload)))
	if err != nil || snapshot.Version != "test" || snapshot.Groups[0].Nodes[0].Latency.Last != time.Second {
		t.Fatalf("decodeStatus() = %+v, %v", snapshot, err)
	}
	unknownPayload := append([]byte(`{"unknown":true,`), payload[1:]...)
	if _, err := decodeStatus(strings.NewReader(string(unknownPayload))); err == nil {
		t.Fatal("decodeStatus accepted an unknown field")
	}
	duplicatePayload := append([]byte(`{"schema":99,`), payload[1:]...)
	if _, err := decodeStatus(strings.NewReader(string(duplicatePayload))); err == nil {
		t.Fatal("decodeStatus accepted a duplicate field")
	}
	caseAliasPayload := strings.Replace(string(payload), `"schema":`, `"Schema":`, 1)
	if _, err := decodeStatus(strings.NewReader(caseAliasPayload)); err == nil {
		t.Fatal("decodeStatus accepted a case-insensitive field alias")
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
	node := &snapshot.Groups[0].Nodes[0]
	node.Support[common.NetworkTCP4] = dialer.NetworkSupportConfirmed
	snapshot.Groups[0].SelectedNodeIDs[common.NetworkTCP4] = node.ID
	if err := validateStatus(&snapshot); err == nil {
		t.Fatal("validateStatus accepted an unusable selected node")
	}
}

func TestDecodeStatusRejectsInvalidSchema(t *testing.T) {
	for _, payload := range []string{
		`{"schema":1,"version":"test","started_at":"2026-01-01T00:00:00Z","networks":[],"groups":[]}`,
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
			payload, err := json.Marshal(validWireStatus(), jsonv1.FormatDurationAsNano(true))
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
