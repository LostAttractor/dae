// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/jedib0t/go-pretty/v6/text"
)

func TestBuiltinStatusHasDedicatedConnectionSummary(t *testing.T) {
	withoutStatusColors(t)
	group := recentTestGroup()
	direct := api.GroupStatus{Name: "direct", TargetKind: "builtin",
		Stats:           api.PathStats{ActiveConnections: 6, TotalConnections: 20},
		Nodes:           []api.NodeStatus{{ID: "direct", Name: "direct"}},
		SelectedNodeIDs: api.NetworkValues[string]{"direct", "direct", "direct", "direct"}}
	direct.Networks[api.NetworkTCP4] = direct.Stats
	snapshot := &api.StatusSnapshot{StartedAt: time.Now(), DirectFallbackConnections: 2,
		Groups: []api.GroupStatus{direct, group}}
	for _, recent := range []bool{false, true} {
		for _, verbose := range []bool{false, true} {
			for _, color := range []bool{false, true} {
				t.Run(fmt.Sprintf("recent=%v/verbose=%v/color=%v", recent, verbose, color), func(t *testing.T) {
					withStatusTerminalWidth(t, 0)
					colorsEnabled = color
					var out strings.Builder
					if recent {
						PrintRecent(&out, snapshot)
					} else {
						Print(&out, snapshot, verbose)
					}
					got := text.StripEscape(out.String())
					if !strings.Contains(got, "direct: 6 active · 20 total · Fallback Total 2\n") || strings.Count(got, "Fallback Total") != 1 {
						t.Fatalf("lost or duplicated direct fallback summary:\n%s", got)
					}
					if strings.Contains(got, "Group 'direct'") || strings.Contains(got, "N/A") || strings.Contains(got, "FALLBACK TOTAL") || strings.Contains(got, "(fb ") {
						t.Fatalf("builtin retained ordinary health or per-node fallback fields:\n%s", got)
					}
					if recent && !strings.Contains(got, "GROUP") {
						t.Fatalf("proxy overview missing:\n%s", got)
					}
				})
			}
		}
	}
	for _, width := range []int{24, 40, 80} {
		withStatusTerminalWidth(t, width)
		var out strings.Builder
		printBuiltinStatus(&out, snapshot, false)
		if len(strings.Split(strings.TrimSuffix(out.String(), "\n\n"), "\n")) != 1 || text.LongestLineLen(out.String()) > width {
			t.Fatalf("builtin summary wrapped or exceeded %d columns: %q", width, out.String())
		}
	}
}

func TestBuiltinStatusOmitsZeroFallbackAndBlockHealth(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 0)
	snapshot := &api.StatusSnapshot{Groups: []api.GroupStatus{
		{Name: "direct", TargetKind: "builtin"}, {Name: "block", TargetKind: "builtin"},
	}}
	var out strings.Builder
	printBuiltinStatus(&out, snapshot, false)
	if got := out.String(); got != "direct: 0 active · 0 total\n\nblock: 0 active · 0 total\n\n" {
		t.Fatalf("unexpected builtin summary: %q", got)
	}
	if got := renderRecentGroups(snapshot.Groups); got != "" {
		t.Fatalf("builtins gained an empty health table: %q", got)
	}
	snapshot.DirectFallbackConnections = 7
	snapshot.Groups = snapshot.Groups[1:]
	out.Reset()
	printBuiltinStatus(&out, snapshot, true)
	if strings.Contains(out.String(), "Fallback") || strings.Contains(out.String(), "N/A") {
		t.Fatalf("block gained direct counters or health: %q", out.String())
	}
}

func TestBuiltinTrafficUsesOnlyGroupTotals(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 0)
	snapshot := &api.StatusSnapshot{Groups: []api.GroupStatus{{Name: "direct", TargetKind: "builtin",
		Stats: api.PathStats{UploadBytes: 4096, History: api.TrafficHistory{
			UploadBytesPerSecond: []uint64{1}, DownloadBytesPerSecond: []uint64{0}}},
		Nodes: []api.NodeStatus{{ID: "direct", Name: "direct", Stats: api.PathStats{UploadBytes: 1024}}},
	}}}
	for _, mode := range []trafficMode{trafficOrdinary, trafficRecent, trafficVerbose} {
		got := renderTraffic(snapshot, mode)
		if len(strings.Split(got, "\n")) != 3 || strings.Count(got, "direct") != 1 || !strings.Contains(got, "4.00K") || strings.Contains(got, "(direct)") {
			t.Fatalf("mode=%v: builtin duplicated a node or lost group totals:\n%s", mode, got)
		}
	}
}
