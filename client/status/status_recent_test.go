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
	"github.com/jedib0t/go-pretty/v6/text"
)

func recentTestGroup() api.GroupStatus {
	support := api.NetworkValues[api.NetworkSupportState]{api.NetworkSupportConfirmed, api.NetworkSupportConfirmed, api.NetworkSupportConfirmed, api.NetworkSupportConfirmed}
	states := make([]api.GroupHistoryState, api.GroupStateBucketCount)
	states[0] = api.GroupHistoryAvailable
	states[1] = api.GroupHistoryUnknown
	states[2] = api.GroupHistoryUnavailable
	return api.GroupStatus{
		Name:               "proxy",
		Policy:             "min_moving_avg",
		ChecksConnectivity: true,
		Connectivity:       api.GroupStateAvailable,
		SelectedNodeIDs:    api.NetworkValues[string]{"hk", "hk", "hk", "hk"},
		Nodes:              []api.NodeStatus{{ID: "hk", Name: "HK-01", Support: support}, {ID: "sg", Name: "SG-02", Support: support}},
		Availability: api.GroupAvailability{
			Seen: true, Recent24h: api.AvailabilityWindow{UpRatio: 0.9992},
			Recent: api.GroupStateWindow{States: states},
		},
		Stats: api.PathStats{
			ActiveConnections: 31,
			UploadBytes:       3000,
			DownloadBytes:     4000,
			History: api.TrafficHistory{
				UploadBytesPerSecond: []uint64{100}, DownloadBytesPerSecond: []uint64{200},
			},
		},
	}
}

func TestRecentGroupOverviewAndTrends(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 96)
	got := renderRecentGroups([]api.GroupStatus{recentTestGroup()})
	lines := strings.Split(got, "\n")
	if len(lines) != 2 {
		t.Fatalf("want a header and one single-line group row:\n%s", got)
	}
	if header := strings.Join(strings.Fields(lines[0]), " "); header != "GROUP STATE 24H 1H SELECTED ACTIVE" {
		t.Fatalf("unclear column labels: %s", header)
	}
	if overview := strings.Join(strings.Fields(lines[1]), " "); overview != "proxy UP 99.92% [+.x.......] HK-01 31" {
		t.Fatalf("selection or counters missing: %s", overview)
	}
	if text.StringWidthWithoutEscSequences(lines[1]) > 96 {
		t.Fatalf("ordinary group does not fit 96 columns:\n%s", got)
	}
}

func TestRecentColumnsAlignAcrossGroups(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 160)
	var groups []api.GroupStatus
	for _, tc := range []struct {
		name, node string
		active     int64
		ratio      float64
	}{
		{"proxy_hk", "香港高级 IEPL 专线 3", 0, 1},
		{"proxy_jp", "lightsail", 162, 1},
		{"tor", "tor", 9, .5538},
		{"busy", "busy", 1234567, .9},
	} {
		group := recentTestGroup()
		group.Name = tc.name
		group.Availability.Recent24h.UpRatio = tc.ratio
		group.Stats.ActiveConnections = tc.active
		group.Nodes = []api.NodeStatus{{ID: "node", Name: tc.node, Support: api.NetworkValues[api.NetworkSupportState]{
			api.NetworkSupportConfirmed, api.NetworkSupportUnknown, api.NetworkSupportConfirmed, api.NetworkSupportUnknown,
		}}}
		group.SelectedNodeIDs = api.NetworkValues[string]{"node", "", "node", ""}
		if tc.name == "tor" {
			group.Nodes[0].Support[api.NetworkUDP4] = api.NetworkSupportUnsupported
			group.SelectedNodeIDs[api.NetworkUDP4] = ""
		}
		groups = append(groups, group)
	}
	for _, color := range []bool{false, true} {
		t.Run(fmt.Sprint("color=", color), func(t *testing.T) {
			colorsEnabled = color
			got := text.StripEscape(renderRecentGroups(groups))
			lines := strings.Split(got, "\n")
			if len(lines) != len(groups)+1 {
				t.Fatalf("groups gained blank or continuation rows:\n%s", got)
			}
			header := lines[0]
			column := func(line string, position int) int {
				if position < 0 {
					t.Fatalf("missing column in %q", line)
				}
				return text.StringWidthWithoutEscSequences(line[:position])
			}
			for i, line := range lines[1:] {
				if groups[i].ChecksConnectivity {
					ratio := fmt.Sprintf("%.2f%%", groups[i].Availability.Recent24h.UpRatio*100)
					if column(line, strings.Index(line, ratio)) != column(header, strings.Index(header, "24H")) ||
						column(line, strings.Index(line, "[")) != column(header, strings.Index(header, "1H")) {
						t.Fatalf("percentages or history shifted between groups:\n%s", got)
					}
				}
				if column(line, strings.LastIndex(line, groups[i].Nodes[0].Name)) != column(header, strings.Index(header, "SELECTED")) {
					t.Fatalf("node names shifted between groups:\n%s", got)
				}
				active := fmt.Sprint(groups[i].Stats.ActiveConnections)
				if strings.Contains(line, " / ") || !strings.HasSuffix(line, active) ||
					column(line, strings.LastIndex(line, active)) != column(header, strings.Index(header, "ACTIVE")) {
					t.Fatalf("active counts shifted or gained fallback fields:\n%s", got)
				}
			}
			if strings.Contains(got, "ipv6:") || strings.Contains(got, "tcp6:") || strings.Contains(got, "ipv4:") {
				t.Fatalf("unknown routes added placeholders or redundant labels:\n%s", got)
			}
		})
	}
}

func TestRecentSelections(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 120)
	for _, tc := range []struct {
		name   string
		ids    api.NetworkValues[string]
		policy string
		want   []string
	}{
		{"all", api.NetworkValues[string]{"hk", "hk", "hk", "hk"}, "fixed", []string{"HK-01"}},
		{"families", api.NetworkValues[string]{"hk", "sg", "hk", "sg"}, "min_avg10", []string{"ipv4: HK-01", "ipv6: SG-02"}},
		{"protocols", api.NetworkValues[string]{"hk", "hk", "sg", "sg"}, "selector", []string{"tcp: HK-01", "udp: SG-02"}},
		{"partial", api.NetworkValues[string]{"hk", "", "sg", ""}, "min_moving_avg", []string{"tcp4: HK-01", "ipv6: -", "udp4: SG-02"}},
		{"none", api.NetworkValues[string]{}, "fixed", []string{"-"}},
		{"random", api.NetworkValues[string]{}, "random", []string{"random"}},
		{"unresolved ID", api.NetworkValues[string]{"missing", "missing", "missing", "missing"}, "fixed", []string{"missing"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			group := recentTestGroup()
			group.SelectedNodeIDs, group.Policy = tc.ids, tc.policy
			got := renderRecentGroups([]api.GroupStatus{group})
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Fatalf("missing route %q:\n%s", want, got)
				}
			}
			if len(strings.Split(got, "\n")) != 2 {
				t.Fatalf("network selections introduced continuation rows:\n%s", got)
			}
		})
	}
	group := recentTestGroup()
	group.Nodes[1].Name = group.Nodes[0].Name
	group.SelectedNodeIDs = api.NetworkValues[string]{"hk", "sg", "hk", "sg"}
	got := renderRecentGroups([]api.GroupStatus{group})
	if !strings.Contains(got, "ipv4: HK-01") || !strings.Contains(got, "ipv6: HK-01") {
		t.Fatalf("distinct nodes with the same name were merged:\n%s", got)
	}
}

func TestRecentEmptyAndLongSelections(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 160)
	if got := renderRecentGroups(nil); got != "" {
		t.Fatalf("empty groups gained a table: %q", got)
	}
	group := recentTestGroup()
	group.Nodes[0].Name = strings.Repeat("香港节点", 100)
	group.SelectedNodeIDs = api.NetworkValues[string]{"hk", "sg", "hk", "sg"}
	got := renderRecentGroups([]api.GroupStatus{group})
	if !strings.Contains(got, "ipv6: SG-02") || !strings.Contains(got, "…") {
		t.Fatalf("one long choice consumed a later choice:\n%s", got)
	}
}

func TestRecentUncheckedAndUnobservedGroups(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 80)
	group := api.GroupStatus{Name: "direct", TargetKind: "builtin", Stats: api.PathStats{ActiveConnections: 3},
		SelectedNodeIDs: api.NetworkValues[string]{"direct", "direct", "direct", "direct"},
		Nodes:           []api.NodeStatus{{ID: "direct", Name: "direct"}}}
	got := renderRecentGroups([]api.GroupStatus{group})
	if got != "" {
		t.Fatalf("direct appeared in the connectivity table:\n%s", got)
	}
	group = recentTestGroup()
	group.Availability.Seen = false
	group.Connectivity = api.GroupStateChecking
	group.SelectedNodeIDs = api.NetworkValues[string]{}
	got = renderRecentGroups([]api.GroupStatus{group})
	if !strings.Contains(strings.Join(strings.Fields(got), " "), "CHECKING -") || strings.Contains(got, "99.92%") {
		t.Fatalf("unobserved group shows stale availability:\n%s", got)
	}
}

func TestRecentSelectionsOmitUnconfirmedNetworks(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 120)
	for _, tc := range []struct {
		name string
		mask uint8
		ids  api.NetworkValues[string]
		want []string
	}{
		{"IPv4 only", 0b0101, api.NetworkValues[string]{"hk", "", "hk", ""}, []string{"HK-01"}},
		{"TCP only", 0b0011, api.NetworkValues[string]{"hk", "hk", "", ""}, []string{"HK-01"}},
		{"UDP6 only", 0b1000, api.NetworkValues[string]{"", "", "", "sg"}, []string{"SG-02"}},
		{"split IPv4", 0b0101, api.NetworkValues[string]{"hk", "", "sg", ""}, []string{"tcp4: HK-01", "udp4: SG-02"}},
		{"all unavailable", 0b0101, api.NetworkValues[string]{}, []string{"-"}},
	} {
		for _, unconfirmed := range []api.NetworkSupportState{api.NetworkSupportUnsupported, api.NetworkSupportUnknown} {
			t.Run(tc.name+"/"+string(unconfirmed), func(t *testing.T) {
				group := recentTestGroup()
				group.SelectedNodeIDs = tc.ids
				for i := range group.Nodes {
					for network := range group.Nodes[i].Support {
						group.Nodes[i].Support[network] = unconfirmed
						if tc.mask&(1<<network) != 0 {
							group.Nodes[i].Support[network] = api.NetworkSupportConfirmed
						}
					}
				}
				selections := recentSelections(group)
				if strings.Join(selections, "\n") != strings.Join(tc.want, "\n") {
					t.Fatalf("unexpected network entries: got %q, want %q", selections, tc.want)
				}
				got := renderRecentGroups([]api.GroupStatus{group})
				for network := range api.NetworkTypeCount {
					if tc.mask&(1<<network) == 0 && strings.Contains(got, api.NetworkIndex(network).String()) {
						t.Fatalf("unsupported network appears in output:\n%s", got)
					}
				}
				if len(tc.want) == 1 && (strings.Contains(got, "all →") || strings.Contains(got, "ipv4:") || strings.Contains(got, "ipv6:") || strings.Contains(got, "tcp:") || strings.Contains(got, "udp:")) {
					t.Fatalf("unanimous selection has redundant network labels:\n%s", got)
				}
			})
		}
	}
	// Live selections still win over asynchronous support updates, while unknown
	// networks with no selection add no labels or empty placeholders.
	group := recentTestGroup()
	group.SelectedNodeIDs = api.NetworkValues[string]{"hk", "", "hk", ""}
	for i := range group.Nodes {
		group.Nodes[i].Support = api.NetworkValues[api.NetworkSupportState]{api.NetworkSupportUnsupported, api.NetworkSupportUnknown, api.NetworkSupportUnsupported, api.NetworkSupportUnknown}
	}
	got := renderRecentGroups([]api.GroupStatus{group})
	if !strings.Contains(got, "HK-01") || strings.Contains(got, "ipv4:") || strings.Contains(got, "ipv6:") {
		t.Fatalf("unknown routes introduced placeholders or hid the live choice:\n%s", got)
	}
}

func TestRecentGroupColors(t *testing.T) {
	previous := colorsEnabled
	colorsEnabled = true
	t.Cleanup(func() { colorsEnabled = previous })
	withStatusTerminalWidth(t, 80)
	group := recentTestGroup()
	group.Connectivity = api.GroupStateChecking
	got := renderRecentGroups([]api.GroupStatus{group})
	for _, want := range []string{colorize("CHECKING", text.FgYellow), colorSelected("HK-01", true), "●", "○"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing colored state %q:\n%s", want, got)
		}
	}
	for _, tc := range []struct {
		state api.GroupState
		label string
		color text.Color
	}{
		{api.GroupStateAvailable, "HEALTHY", text.FgGreen},
		{api.GroupStateChecking, "WARNING", text.FgYellow},
		{api.GroupStateUnavailable, "DEGRADED", text.FgRed},
	} {
		group.Connectivity, group.Critical = tc.state, true
		var out strings.Builder
		PrintRecent(&out, &api.StatusSnapshot{StartedAt: time.Now(), Groups: []api.GroupStatus{group}})
		first, _, _ := strings.Cut(out.String(), "\n")
		if !strings.Contains(first, colorize(tc.label, tc.color)) {
			t.Fatalf("summary lost its health label/color: %q", first)
		}
	}
}

func TestRecentNarrowLayoutClipsWithoutWrapping(t *testing.T) {
	withoutStatusColors(t)
	for _, width := range []int{40, 64, 80, 120} {
		for _, color := range []bool{false, true} {
			t.Run(fmt.Sprintf("width=%d/color=%v", width, color), func(t *testing.T) {
				withStatusTerminalWidth(t, width)
				colorsEnabled = color
				group := recentTestGroup()
				group.Name = strings.Repeat("香港出口", 8)
				group.Nodes[0].Name = strings.Repeat("香港节点🇭🇰", 12)
				group.SelectedNodeIDs = api.NetworkValues[string]{"hk", "sg", "hk", "sg"}
				group.Stats.ActiveConnections = 1234567
				got := renderRecentGroups([]api.GroupStatus{group})
				if len(strings.Split(got, "\n")) != 2 {
					t.Fatalf("narrow output expanded a group into multiple rows:\n%s", got)
				}
				for line := range strings.SplitSeq(got, "\n") {
					if actual := text.StringWidthWithoutEscSequences(line); actual > width {
						t.Fatalf("line width %d exceeds terminal width %d: %q", actual, width, line)
					}
				}
				plain := text.StripEscape(got)
				if !strings.Contains(plain, "…") {
					t.Fatalf("long group name was not elided:\n%s", plain)
				}
				if strings.Contains(plain, "TRAFFIC") || strings.ContainsAny(plain, "↑↓") {
					t.Fatalf("overview retained inline traffic:\n%s", plain)
				}
			})
		}
	}
}

func TestPrintRecentSummaryFitsTerminal(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 64)
	var out strings.Builder
	PrintRecent(&out, &api.StatusSnapshot{Version: "unstable-20260913.r1231.4b60aea0", StartedAt: time.Now(),
		Stats: recentTestGroup().Stats, Groups: []api.GroupStatus{recentTestGroup()}})
	if lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n"); len(lines) != 9 {
		t.Fatalf("summary or group gained continuation lines:\n%s", out.String())
	}
	for line := range strings.SplitSeq(out.String(), "\n") {
		if text.StringWidthWithoutEscSequences(line) > 64 {
			t.Fatalf("recent summary overflows: %q", line)
		}
	}
	for _, want := range []string{"HK-01", "Traffic:", "TOTAL ↑", "TOTAL ↓"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("summary lost %q:\n%s", want, out.String())
		}
	}
}
