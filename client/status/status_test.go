/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package status

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
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

func testNodeStatus(now time.Time) api.NodeStatus {
	priority := 2
	return api.NodeStatus{
		ID:                 "node-id",
		Name:               "node-a",
		Subtag:             "sub",
		Protocol:           "ss",
		Annotation:         &api.NodeAnnotationStatus{AddLatency: "30ms", Priority: &priority, PriorityConditional: true},
		ChecksConnectivity: true,
		SessionDetail:      &api.SessionStatus{State: "connected"},
		Healthy:            true,
		Availability: api.Availability{
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
			Recent24h: api.AvailabilityWindow{
				UpRatio: 0.98, ChecksTotal: 10, ChecksFailed: 1,
			},
		},
		Latency: &api.LatencyStats{
			Last: 10 * time.Millisecond, Avg10: 20 * time.Millisecond, MovingAvg: 30 * time.Millisecond,
		},
		Support: api.NetworkValues[api.NetworkSupportState]{
			api.NetworkSupportConfirmed,
			api.NetworkSupportConfirmed,
			api.NetworkSupportUnsupported,
			api.NetworkSupportUnknown,
		},
		Stats: api.PathStats{
			ActiveConnections:   2,
			TotalConnections:    3,
			FallbackConnections: 1,
			TrafficCounters:     api.TrafficCounters{UploadBytes: 1024, DownloadBytes: 2048},
			History: api.TrafficHistory{
				UploadBytesPerSecond: []uint64{100, 100}, DownloadBytesPerSecond: []uint64{200, 200},
			},
		},
	}
}

func TestTableUsageRow(t *testing.T) {
	withoutStatusColors(t)
	row := tableUsageRow(api.TableUsage{
		Name: "domain-kernel", Used: 2, Limit: 4, Candidates: 3,
	})
	want := []string{"domain-kernel", "2", "4", "50.0%", "3", "1"}
	for index, expected := range want {
		if got := fmt.Sprint(row[index]); got != expected {
			t.Errorf("tableUsageRow()[%d] = %q, want %q", index, got, expected)
		}
	}
}

func TestDomainTableDetailsFitTerminal(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 80)
	var out strings.Builder
	Print(&out, &api.StatusSnapshot{StartedAt: time.Now(), Tables: []api.TableUsage{
		{Name: "domain-kernel", Used: 161, Limit: 65536, Candidates: 163},
		{Name: "domain-registry", Used: 6896, Breakdown: &api.TableUsageBreakdown{Domains: 2000, IPs: 5000, IPv4: 4000, IPv6: 1000, GC: 123}},
	}}, false)
	output := out.String()
	for _, label := range []string{"USED (IPs)", "CANDIDATES", "OMITTED", "domain-registry (unlimited):", "DOMAINS", "GC (PAIRS)"} {
		if !strings.Contains(output, label) {
			t.Fatalf("missing %q:\n%s", label, output)
		}
	}
	kernel, registry := false, false
	for _, line := range strings.Split(output, "\n") {
		cells := strings.Join(strings.Fields(line), " ")
		kernel = kernel || cells == "domain-kernel 161 65536 0.2% 163 2"
		registry = registry || cells == "6896 2000 5000 4000 1000 123"
	}
	if !kernel || !registry {
		t.Fatalf("domain statistics were clipped or mislabeled:\n%s", output)
	}
	// Empty registries report real zeros. The cumulative GC counter retains its
	// full uint64 precision and remains visible in an 80-column terminal.
	for _, gc := range []uint64{0, ^uint64(0)} {
		out.Reset()
		Print(&out, &api.StatusSnapshot{StartedAt: time.Now(), Tables: []api.TableUsage{
			{Name: "domain-kernel", Limit: 65536},
			{Name: "domain-registry", Breakdown: &api.TableUsageBreakdown{GC: gc}},
		}}, false)
		found := false
		for _, line := range strings.Split(out.String(), "\n") {
			found = found || strings.Join(strings.Fields(line), " ") == fmt.Sprintf("0 0 0 0 0 %d", gc)
		}
		if !found {
			t.Fatalf("empty registry/GC count changed:\n%s", out.String())
		}
	}
}

func TestStatusTableClipsRowsToFitTerminal(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 16)
	header := table.Row{"FIRST", "SECOND", "XYZ"}
	rows := []table.Row{{"a", "bb", "cc"}}
	rendered := renderStatusTable(header, rows, nil, getStatusTerminalWidth())
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
	rendered = renderStatusTable(table.Row{"LONG HEADER"}, nil, nil, getStatusTerminalWidth())
	if rendered != "LONG" {
		t.Fatalf("single wide column was not clipped to the terminal: %q", rendered)
	}

	colorsEnabled = true
	if got := truncateStatusCell(colorize("网络节点", text.FgGreen), 5); text.StringWidthWithoutEscSequences(got) != 5 || text.StripEscape(got) != "网络…" {
		t.Fatalf("ANSI/CJK truncation = %q", got)
	}
}

func TestStartupNodeLogOnlyIncludesCompletedChecks(t *testing.T) {
	withoutStatusColors(t)
	colorsEnabled = true
	withStatusTerminalWidth(t, 16)
	ready := testNodeStatus(time.Now())
	ready.Name = strings.Repeat("香港节点", 40)
	ready.InitialCheckDone = true
	pending, retained, failed := ready, ready, ready
	pending.Name, pending.ID, pending.InitialCheckDone = "pending-path", "pending", false
	pending.Availability.Seen = false
	retained.Name, retained.ID, retained.InitialCheckDone = "retained-path", "retained", false
	failed.Name, failed.ID, failed.Healthy = "failed-path", "failed", false
	groups := []api.GroupStatus{
		{Name: "proxy", CheckAsync: true, Nodes: []api.NodeStatus{pending, retained, ready, failed},
			SelectedNodeIDs: api.NetworkValues[string]{ready.ID, ready.ID}},
		{Name: "direct", Nodes: []api.NodeStatus{{Name: "direct-path", InitialCheckDone: true, Availability: ready.Availability}}},
		{Name: "pending-only", Nodes: []api.NodeStatus{pending}},
	}
	got := RenderStartupNodes(groups)
	for _, want := range []string{ready.Name, failed.Name, "fail", "10/20/30", "all tcp(*)", "p=2*", "+30ms", "check: async"} {
		if !strings.Contains(got, want) {
			t.Errorf("startup log is missing %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{pending.Name, retained.Name, "direct", "pending-only", "unknown", "UP/24H", "FAIL A/D", "CONNS", "TRAFFIC", "TOTAL", "\x1b"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("startup log contains %q:\n%s", unwanted, got)
		}
	}
	for line := range strings.SplitSeq(got, "\n") {
		if strings.Contains(line, failed.Name) && strings.Contains(line, "10/20/30") {
			t.Errorf("startup log displays stale latency for a failed path: %s", line)
		}
	}
}

func TestNodeRowsUseRawState(t *testing.T) {
	withoutStatusColors(t)
	now := time.Now()
	node := testNodeStatus(now)
	selected := api.NetworkValues[string]{"node-id", "node-id", "", ""}

	verbose := nodeStatusRow(node, 0, selected, now)
	checks := map[int]string{
		0:  "node-a [p=2*,+30ms]",
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

func TestNodeStateUsesHealthWhenChecksEnabled(t *testing.T) {
	withoutStatusColors(t)
	node := testNodeStatus(time.Now())
	node.Healthy = false
	node.SessionDetail.State = "disconnected"
	if got := compactNodeState(node, time.Now()); got != "fail" {
		t.Fatalf("state = %q, want fail", got)
	}
	node.ChecksConnectivity = false
	if got := compactNodeState(node, time.Now()); got != "disconnected" {
		t.Fatalf("unchecked state = %q, want disconnected", got)
	}
	node.SessionDetail.State = "connecting"
	node.Healthy = true
	if got := compactNodeState(node, time.Now()); got != "connecting" {
		t.Fatalf("state = %q, want connecting", got)
	}
	node.SessionDetail.State = "connected"
	node.Recovery = api.RecoverySnapshot{Phase: api.RecoveryConnecting, Action: "replenish", Attempt: 1}
	if got := compactNodeState(node, time.Now()); got != "connected (replenishing capacity #1)" {
		t.Fatalf("unchecked capacity state = %q", got)
	}
}

func TestNetworkStatusRowDerivesSupportAndSelection(t *testing.T) {
	withoutStatusColors(t)
	node := testNodeStatus(time.Now())
	group := api.GroupStatus{
		Nodes: []api.NodeStatus{node},
	}
	group.SelectedNodeIDs[api.NetworkTCP4] = node.ID
	group.Networks[api.NetworkTCP4] = api.PathStats{ActiveConnections: 2, TotalConnections: 5}
	row := networkStatusRow(group, api.NetworkTCP4)
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
	group := api.GroupStatus{
		Policy: "random",
		Nodes:  []api.NodeStatus{node},
	}
	if got := fmt.Sprint(networkStatusRow(group, api.NetworkTCP4)[1]); got != "available" {
		t.Fatalf("usable route = %q, want available", got)
	}
	group.Policy = "fixed"
	nonCandidate := testNodeStatus(time.Now())
	nonCandidate.ID = "non-candidate"
	group.Nodes = append(group.Nodes, nonCandidate)
	group.Nodes[0].Healthy = false
	if got := fmt.Sprint(networkStatusRow(group, api.NetworkTCP4)[1]); got != "down" {
		t.Fatalf("fixed route with usable non-candidate = %q, want down", got)
	}
	group.Policy = "random"
	group.Nodes[1].Healthy = false
	if got := fmt.Sprint(networkStatusRow(group, api.NetworkTCP4)[1]); got != "down" {
		t.Fatalf("unusable dynamic route = %q, want down", got)
	}
	if got := len(checkedNetworkRows(group, false)); got != 2 {
		t.Fatalf("compact network rows = %d, want two confirmed networks", got)
	}
	if got := len(checkedNetworkRows(group, true)); got != api.NetworkTypeCount {
		t.Fatalf("verbose network rows = %d, want %d", got, api.NetworkTypeCount)
	}
}

func TestHealthDerivedFromRawGroups(t *testing.T) {
	available := testNodeStatus(time.Now())
	available.Support[api.NetworkTCP6] = api.NetworkSupportUnsupported
	down := testNodeStatus(time.Now())
	down.ID = "down"
	down.Healthy = false
	down.Support[api.NetworkTCP4] = api.NetworkSupportUnsupported
	tests := []struct {
		group api.GroupStatus
		want  healthStatus
	}{
		{group: api.GroupStatus{}, want: healthHealthy},
		{group: api.GroupStatus{ChecksConnectivity: true, Critical: true, Connectivity: api.GroupStateAvailable}, want: healthHealthy},
		{group: api.GroupStatus{ChecksConnectivity: true, Critical: true, Connectivity: api.GroupStateChecking}, want: healthWarning},
		{group: api.GroupStatus{ChecksConnectivity: true, Connectivity: api.GroupStateUnavailable}, want: healthWarning},
		{group: api.GroupStatus{ChecksConnectivity: true, Critical: true, Connectivity: api.GroupStateUnavailable}, want: healthDegraded},
		{group: api.GroupStatus{ChecksConnectivity: true, Connectivity: api.GroupStateAvailable, Nodes: []api.NodeStatus{available, down}, SelectedNodeIDs: api.NetworkValues[string]{available.ID}}, want: healthWarning},
	}
	for _, test := range tests {
		if got := groupHealth(test.group); got != test.want {
			t.Errorf("groupHealth(%+v) = %q, want %q", test.group, got, test.want)
		}
	}
	if got := statusHealth([]api.GroupStatus{tests[2].group, tests[4].group}); got != healthDegraded {
		t.Fatalf("status health = %q, want degraded", got)
	}
}

func TestStatusSummaryListsAffectedGroups(t *testing.T) {
	withoutStatusColors(t)
	snapshot := &api.StatusSnapshot{Groups: []api.GroupStatus{
		{Name: "optional", ChecksConnectivity: true, Connectivity: api.GroupStateUnavailable},
		{Name: "proxy", ChecksConnectivity: true, Critical: true, Connectivity: api.GroupStateUnavailable},
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
	node.Availability.Recent24h = api.AvailabilityWindow{UpRatio: 1}
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
	group := api.GroupStatus{
		Nodes:           []api.NodeStatus{node},
		SelectedNodeIDs: api.NetworkValues[string]{node.ID, node.ID, "", ""},
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
	value := api.PathStats{TrafficCounters: api.TrafficCounters{UploadBytes: 3 * 1024, DownloadBytes: 5 * 1024}}
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
	networks, selected := nodeNetworks(node, api.NetworkValues[string]{node.ID, node.ID, "", ""})
	if !selected || !strings.HasPrefix(networks, "\x1b[") || text.StripEscape(networks) != "all tcp(*)" {
		t.Fatalf("NETWORKS cell is not fully colored: %q", networks)
	}
}

func TestNodeNetworksMergesSupportAndSelection(t *testing.T) {
	withoutStatusColors(t)
	node := testNodeStatus(time.Now())
	for _, test := range []struct {
		support  api.NetworkValues[api.NetworkSupportState]
		selected api.NetworkValues[string]
		want     string
	}{
		{
			support: api.NetworkValues[api.NetworkSupportState]{
				api.NetworkSupportConfirmed, api.NetworkSupportConfirmed,
				api.NetworkSupportConfirmed, api.NetworkSupportConfirmed,
			},
			selected: api.NetworkValues[string]{"node-id", "node-id", "node-id", "node-id"},
			want:     "all(*)",
		},
		{selected: api.NetworkValues[string]{"node-id", "node-id", "", ""}, want: "all tcp(*)"},
		{selected: api.NetworkValues[string]{"node-id", "", "", ""}, want: "all tcp(tcp4*)"},
		{selected: api.NetworkValues[string]{"", "node-id", "", ""}, want: "all tcp(tcp6*)"},
		{selected: api.NetworkValues[string]{}, want: "all tcp"},
	} {
		if test.support == (api.NetworkValues[api.NetworkSupportState]{}) {
			node.Support = testNodeStatus(time.Now()).Support
		} else {
			node.Support = test.support
		}
		if got, _ := nodeNetworks(node, test.selected); got != test.want {
			t.Errorf("nodeNetworks() = %q, want %q", got, test.want)
		}
	}
}
