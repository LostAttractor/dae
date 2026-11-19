/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package status

import (
	"fmt"
	"io"
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
		Health:             api.NodeHealthHealthy,
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
			ActiveConnections: 2,
			TotalConnections:  3,
			TrafficCounters:   api.TrafficCounters{UploadBytes: 1024, DownloadBytes: 2048},
			History: api.TrafficHistory{
				UploadBytesPerSecond: []uint64{100, 100}, DownloadBytesPerSecond: []uint64{200, 200},
			},
		},
	}
}

func TestStatusUsesServerUptime(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 120)
	snapshot := &api.StatusSnapshot{StartedAt: time.Now().Add(time.Hour), Uptime: 2*time.Hour + 3*time.Minute}
	for _, recent := range []bool{false, true} {
		var out strings.Builder
		if recent {
			PrintRecent(&out, snapshot)
		} else {
			Print(&out, snapshot, false)
		}
		if !strings.Contains(out.String(), "up "+formatUptime(snapshot.Uptime)) {
			t.Fatalf("recent=%v: status ignored server uptime with a skewed client clock:\n%s", recent, out.String())
		}
	}
}

func TestTableUsageRow(t *testing.T) {
	withoutStatusColors(t)
	for _, test := range []struct {
		name, onFull, usageError string
		used, limit              int64
		want                     []string
	}{
		{"bounded", "omit", "", 2, 4, []string{"bounded", "2", "4", "50.0%", "omit"}},
		{"unlimited", "unlimited", "", 8, 0, []string{"unlimited", "8", "unlimited", "-", "unlimited"}},
		{"failed", "evict", "read map failed", 0, 16, []string{"failed", "unavailable", "16", "-", "evict"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			row := tableUsageRow(api.TableUsage{Name: test.name, OnFull: test.onFull, Used: test.used, Limit: test.limit, Error: test.usageError})
			for index, expected := range test.want {
				if got := fmt.Sprint(row[index]); got != expected {
					t.Errorf("tableUsageRow()[%d] = %q, want %q", index, got, expected)
				}
			}
		})
	}
	colorsEnabled = true
	for _, test := range []struct {
		full  string
		alert *api.TableAlert
		want  string
	}{
		{"evict", nil, "table"},
		{"reject", nil, "table"},
		{"reject", new(api.TableAlert{Level: healthWarning, Message: "attention"}), colorize("table", text.FgYellow)},
		{"omit", new(api.TableAlert{Level: healthDegraded, Message: "attention"}), colorize("table", text.FgRed)},
	} {
		row := tableUsageRow(api.TableUsage{Name: "table", Used: 4, Limit: 4, OnFull: test.full, Alert: test.alert})
		if row[0] != test.want || row[3] != "100.0%" {
			t.Errorf("full %s usage = %v, want name %q and plain usage", test.full, row, test.want)
		}
	}
}

func TestDomainTableDetailsFitTerminal(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 80)
	var out strings.Builder
	Print(&out, &api.StatusSnapshot{StartedAt: time.Now(), Tables: []api.TableUsage{
		{Name: "domain-kernel", Scope: "kernel", OnFull: "omit", Used: 161, Limit: 162, Candidates: 163, Pending: 3},
		{Name: "domain-registry", Scope: "userspace", OnFull: "omit", Used: 1 << 20, Limit: 64 << 20, Breakdown: &api.TableUsageBreakdown{Pairs: 6896, Domains: 2000, IPs: 5000, IPv4: 4000, IPv6: 1000, GC: 123, IncompleteBuckets: 2, OmittedPairs: 5}},
	}}, true)
	output := out.String()
	for _, label := range []string{"Kernel tables:", "NAME", "USED", "LIMIT", "USAGE%", "ON FULL", "domain-kernel: CANDIDATES 163; OMITTED 1; PENDING 3", "domain-registry (on full: omit):", "ESTIMATED MEMORY: 1 MiB / 64 MiB", "DOMAINS", "GC (PAIRS)", "INCOMPLETE BUCKETS: 2; PAIR OMISSIONS: 5"} {
		if !strings.Contains(output, label) {
			t.Fatalf("missing %q:\n%s", label, output)
		}
	}
	if strings.Index(output, "domain-registry (on full:") > strings.Index(output, "Kernel tables:") {
		t.Fatalf("kernel projection appeared before registry evidence:\n%s", output)
	}
	kernel, registry := false, false
	for _, line := range strings.Split(output, "\n") {
		cells := strings.Join(strings.Fields(line), " ")
		kernel = kernel || cells == "domain-kernel 161 162 99.4% omit"
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
			{Name: "domain-kernel", Scope: "kernel", OnFull: "omit", Limit: 65536},
			{Name: "domain-registry", Scope: "userspace", OnFull: "omit", Limit: 64 << 20, Breakdown: &api.TableUsageBreakdown{GC: gc}},
		}}, true)
		found := false
		for _, line := range strings.Split(out.String(), "\n") {
			found = found || strings.Join(strings.Fields(line), " ") == fmt.Sprintf("0 0 0 0 0 %d", gc)
		}
		if !found {
			t.Fatalf("empty registry/GC count changed:\n%s", out.String())
		}
	}
}

func TestCapacityTablesSharedAcrossStatusModes(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 80)
	snapshot := &api.StatusSnapshot{StartedAt: time.Now(), Tables: []api.TableUsage{
		{Name: "tcp_flow_map", Scope: "kernel", OnFull: "evict", Used: 16, Limit: 16},
		{Name: "domain-kernel", Scope: "kernel", OnFull: "omit", Limit: 16, Candidates: 3, Pending: 2, Error: "read map: permission denied", Alert: new(api.TableAlert{Level: healthWarning, Message: "usage unavailable"})},
		{Name: "udp-sources", Scope: "userspace", OnFull: "reject", Used: 4, Limit: 8},
		{Name: "udp-reply-sockets", Scope: "userspace", OnFull: "reject", Used: 7, Limit: 10, Alert: new(api.TableAlert{Level: healthWarning, Message: "capacity pressure"})},
		{Name: "domain-registry", Scope: "userspace", OnFull: "omit", Limit: 4096, Error: "registry unavailable", Alert: new(api.TableAlert{Level: healthWarning, Message: "usage unavailable"}), Breakdown: &api.TableUsageBreakdown{Pairs: 8, Domains: 3, IPs: 5, IPv4: 4, IPv6: 1, GC: 2}},
	}}
	render := func(verbose bool) string {
		var tables strings.Builder
		printTables(&tables, snapshot.Tables, verbose)
		return tables.String()
	}
	all, attention := render(true), render(false)
	for _, mode := range []struct {
		tables string
		print  func(io.Writer)
	}{
		{attention, func(out io.Writer) { Print(out, snapshot, false) }},
		{all, func(out io.Writer) { Print(out, snapshot, true) }},
		{attention, func(out io.Writer) { PrintRecent(out, snapshot) }},
	} {
		var out strings.Builder
		mode.print(&out)
		if strings.Count(out.String(), mode.tables) != 1 {
			t.Fatalf("status did not share the table rendering:\n%s", out.String())
		}
	}
	// Healthy LRU and pool usage stays out of ordinary views.
	brief := strings.Join(strings.Fields(attention), " ")
	for _, want := range []string{
		"domain-kernel unavailable 16 - omit", "udp-reply-sockets 7 10 70.0% reject",
		"domain-kernel: CANDIDATES 3; OMITTED unavailable; PENDING 2",
		"domain-registry: unavailable: registry unavailable",
	} {
		if !strings.Contains(brief, want) {
			t.Errorf("ordinary view missing %q:\n%s", want, attention)
		}
	}
	if strings.Contains(brief, "tcp_flow_map") || strings.Contains(brief, "udp-sources") {
		t.Fatalf("ordinary view listed healthy tables:\n%s", attention)
	}
	// Past omissions alone do not require attention once capacity has recovered.
	registry := api.TableUsage{Name: "domain-registry", Scope: "userspace", OnFull: "omit", Used: 2048, Limit: 4096, Breakdown: &api.TableUsageBreakdown{Pairs: 8, Domains: 3, IPs: 5, OmittedPairs: 7}}
	var healthy strings.Builder
	printTables(&healthy, []api.TableUsage{snapshot.Tables[0], registry}, false)
	if healthy.Len() != 0 {
		t.Fatalf("healthy tables printed a section:\n%s", healthy.String())
	}
	tables := all
	output := strings.Join(strings.Fields(tables), " ")
	for _, want := range []string{
		"tcp_flow_map 16 16 100.0% evict", "domain-kernel unavailable 16 - omit",
		"Userspace tables:", "udp-sources 4 8 50.0% reject",
		"domain-kernel: unavailable: read map: permission denied",
		"domain-kernel: CANDIDATES 3; OMITTED unavailable; PENDING 2",
		"ESTIMATED MEMORY: unavailable / 4 KiB", "8 3 5 4 1 2", "domain-registry: unavailable: registry unavailable",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("missing %q:\n%s", want, tables)
		}
	}
	if strings.Contains(output, " 0.0% ") || strings.Index(output, "Kernel tables:") > strings.Index(output, "Userspace tables:") {
		t.Fatalf("unavailable usage shown as zero or scopes mixed:\n%s", tables)
	}
	if text.LongestLineLen(tables) > 80 {
		t.Fatalf("capacity tables overflowed:\n%s", tables)
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
	pending.Health = api.NodeHealthUnknown
	retained.Name, retained.ID, retained.InitialCheckDone = "retained-path", "retained", false
	failed.Name, failed.ID, failed.Healthy, failed.Health = "failed-path", "failed", false, api.NodeHealthUnhealthy
	groups := []api.GroupStatus{
		{Name: "proxy", CheckAsync: true, Nodes: []api.NodeStatus{pending, retained, ready, failed},
			SelectedNodeIDs: api.NetworkValues[string]{ready.ID, ready.ID}},
		{Name: "direct", Nodes: []api.NodeStatus{{Name: "direct-path", InitialCheckDone: true, Availability: ready.Availability}}},
		{Name: "pending-only", Nodes: []api.NodeStatus{pending}},
	}
	got := RenderStartupNodes(groups)
	for _, want := range []string{ready.Name, failed.Name, "unavailable", "10/20/30", "all tcp(*)", "p=2*", "+30ms", "check: async"} {
		if !strings.Contains(got, want) {
			t.Errorf("startup log is missing %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{pending.Name, retained.Name, "direct", "pending-only", "not tested", "UP/24H", "FAIL A/D", "CONNS", "TRAFFIC", "TOTAL", "\x1b"} {
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
		13: "2/3",
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
	node.Health = api.NodeHealthUnhealthy
	node.SessionDetail.State = "disconnected"
	if got := compactNodeState(node, time.Now()); got != "unavailable" {
		t.Fatalf("state = %q, want fail", got)
	}
	node.ChecksConnectivity = false
	node.Health = api.NodeHealthUnknown
	if got := compactNodeState(node, time.Now()); got != "disconnected" {
		t.Fatalf("unchecked state = %q, want disconnected", got)
	}
	node.SessionDetail.State = "connecting"
	node.Healthy = true
	node.Health = api.NodeHealthHealthy
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

func TestHealthUsesServerState(t *testing.T) {
	groups := []api.GroupStatus{
		{Health: api.GroupHealthWarning},
		{Health: api.GroupHealthDegraded, Connectivity: api.GroupStateAvailable},
	}
	if got := statusHealth(groups); got != healthDegraded {
		t.Fatalf("health = %q, want server-provided degraded", got)
	}
	if got := nodeHealth(api.NodeStatus{Health: api.NodeHealthUnknown, Healthy: true}); got != nodeHealthUnknown {
		t.Fatalf("client overrode server observation: %q", got)
	}
}

func TestStatusModesUseServerTableAlerts(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 80)
	for _, tt := range []struct {
		name    string
		tables  []api.TableUsage
		groups  []api.GroupStatus
		want    healthStatus
		reasons []string
	}{
		{
			name: "no inferred alerts",
			tables: []api.TableUsage{
				{Name: "domain-registry", Scope: "userspace", Used: 91, Limit: 100, Breakdown: &api.TableUsageBreakdown{OmittedPairs: 100}},
				{Name: "tcp_flow_map", Scope: "kernel", OnFull: "evict", Used: 5, Limit: 5},
				{Name: "domain-kernel", Scope: "kernel", Error: "read failed"},
			},
			want: healthHealthy,
		},
		{
			name: "server policy and reasons",
			tables: []api.TableUsage{
				{Name: "domain-kernel", Scope: "kernel", Limit: 4, Candidates: 5, Error: "read failed", Alert: new(api.TableAlert{Level: healthWarning, Message: "check kernel"})},
				{Name: "domain-registry", Scope: "userspace", Used: 1, Limit: 100, Alert: new(api.TableAlert{Level: healthDegraded, Message: "check domain coverage"})},
			},
			want:    healthDegraded,
			reasons: []string{"domain-kernel: check kernel", "domain-registry: check domain coverage"},
		},
		{
			name:    "degraded group outranks a warning",
			tables:  []api.TableUsage{{Name: "tcp_flow_map", Scope: "kernel", Error: "read failed", Alert: new(api.TableAlert{Level: healthWarning, Message: "check flow table"})}},
			groups:  []api.GroupStatus{{Name: "proxy", Health: healthDegraded}},
			want:    healthDegraded,
			reasons: []string{"tcp_flow_map: check flow table"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			snapshot := &api.StatusSnapshot{Version: "test", StartedAt: time.Now(), Tables: tt.tables, Groups: tt.groups}
			for _, mode := range []struct {
				verbose bool
				render  func(io.Writer)
			}{
				{false, func(out io.Writer) { Print(out, snapshot, false) }},
				{true, func(out io.Writer) { Print(out, snapshot, true) }},
				{false, func(out io.Writer) { PrintRecent(out, snapshot) }},
			} {
				var out strings.Builder
				mode.render(&out)
				output := out.String()
				head, _, _ := strings.Cut(output, "\n\n")
				if !strings.Contains(strings.ToLower(head), string(tt.want)) {
					t.Fatalf("expected %s in summary:\n%s", tt.want, head)
				}
				for _, reason := range tt.reasons {
					if strings.Count(output, reason) != 1 || !strings.Contains(head, reason) {
						t.Fatalf("expected one %q in summary:\n%s", reason, output)
					}
				}
				if want := len(tt.reasons) != 0 || mode.verbose; strings.Contains(output, "read failed") != want {
					t.Fatalf("raw error visibility = %t, want %t:\n%s", !want, want, output)
				}
			}
		})
	}
}

func TestDomainRegistryErrorWithoutBreakdownUsesIEC(t *testing.T) {
	var out strings.Builder
	printTables(&out, []api.TableUsage{{Name: "domain-registry", Scope: "userspace", Limit: 64 << 20, Error: "read failed", Alert: new(api.TableAlert{Level: healthWarning, Message: "usage unavailable"})}}, false)
	if output := out.String(); !strings.Contains(output, "ESTIMATED MEMORY: unavailable / 64 MiB") || strings.Contains(output, "GC (PAIRS)") {
		t.Fatalf("registry read error lost its byte unit or rendered missing details:\n%s", output)
	}
}

func TestStatusSummaryListsAffectedGroups(t *testing.T) {
	withoutStatusColors(t)
	snapshot := &api.StatusSnapshot{Groups: []api.GroupStatus{
		{Name: "optional", Health: api.GroupHealthWarning, ChecksConnectivity: true, Connectivity: api.GroupStateUnavailable},
		{Name: "proxy", Health: api.GroupHealthDegraded, ChecksConnectivity: true, Critical: true, Connectivity: api.GroupStateUnavailable},
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
	if row := trafficRow("", value); row[5] != "3.00K" || row[6] != "5.00K" {
		t.Fatalf("traffic totals: %v", row)
	}
	if got, want := trafficRateCell(1_250_000, 12_500_000).String(), "10.0/100Mbps"; got != want {
		t.Fatalf("rate threshold pair = %q, want %q", got, want)
	}
	if got, want := trafficRateCell(100, 110).String(), "800/880bps"; got != want {
		t.Fatalf("same-unit rate pair = %q, want %q", got, want)
	}
	if got, want := trafficRateCell(100, 1_250_000).String(), "800bps/10.0Mbps"; got != want {
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

// A failing network keeps its capability but drops out of the served set.
func TestFailingNetworksServeNothing(t *testing.T) {
	withoutStatusColors(t)
	node := testNodeStatus(time.Now())
	node.Support = api.NetworkValues[api.NetworkSupportState]{
		api.NetworkSupportConfirmed, api.NetworkSupportConfirmed,
		api.NetworkSupportConfirmed, api.NetworkSupportConfirmed,
	}
	node.Failing = api.NetworkValues[bool]{false, true, false, true}
	if got, _ := nodeNetworks(node, api.NetworkValues[string]{}); got != "all ipv4" {
		t.Fatalf("nodeNetworks() = %q, want all ipv4", got)
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
