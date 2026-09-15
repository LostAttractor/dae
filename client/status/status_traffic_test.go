// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/jedib0t/go-pretty/v6/text"
)

func trafficTestSnapshot() *api.StatusSnapshot {
	first := recentTestGroup()
	first.Name = "proxy_jp"
	first.Nodes[0].Name = "日本高级 IEPL 专线 1"
	first.Nodes[0].Stats = api.PathStats{ActiveConnections: 2, UploadBytes: 512, DownloadBytes: 2048,
		History: api.TrafficHistory{UploadBytesPerSecond: []uint64{100, 300}, DownloadBytesPerSecond: []uint64{500, 1500}}}
	first.Nodes[1].Name = "idle-node"
	first.Nodes[1].Stats.History = api.TrafficHistory{UploadBytesPerSecond: []uint64{0, 0}, DownloadBytesPerSecond: []uint64{0, 0}}
	second := api.GroupStatus{Name: "proxy_hk", Stats: api.PathStats{UploadBytes: 16384, DownloadBytes: 8192}, Nodes: []api.NodeStatus{
		{ID: "hk", Name: "日本高级 IEPL 专线 1", Stats: api.PathStats{DownloadBytes: 4096}},
	}}
	return &api.StatusSnapshot{StartedAt: time.Now(),
		Stats:  api.PathStats{UploadBytes: 65536, DownloadBytes: 131072},
		Groups: []api.GroupStatus{first, second, {Name: "idle-group"}},
	}
}

func TestTrafficTableRowsAndTotals(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 0)
	snapshot := trafficTestSnapshot()
	colorsEnabled = true
	rendered := renderTraffic(snapshot, trafficOrdinary)
	if !strings.Contains(rendered, colorSelected(snapshot.Groups[0].Nodes[0].Name, true)) {
		t.Fatalf("collapsed selection lost styling:\n%s", rendered)
	}
	got := text.StripEscape(rendered)
	lines := strings.Split(got, "\n")
	if len(lines) != 4 || strings.Contains(got, "idle-") {
		t.Fatalf("want header, daemon and two collapsed groups:\n%s", got)
	}
	for i, want := range map[int][]string{
		1: {"ALL", "64.0K", "128K"},
		2: {"proxy_jp(日本高级 IEPL 专线 1)", "2.93K", "3.91K"},
		3: {"proxy_hk(日本高级 IEPL 专线 1)", "16.0K", "8.00K"},
	} {
		for _, label := range want {
			if !strings.Contains(lines[i], label) {
				t.Fatalf("row %d lost %q or recomputed totals:\n%s", i, label, got)
			}
		}
	}
	verbose := text.StripEscape(renderTraffic(snapshot, trafficVerbose))
	if len(strings.Split(verbose, "\n")) != 8 || strings.Contains(verbose, "proxy_jp(") ||
		!strings.Contains(verbose, "proxy_jp (total)") || !strings.Contains(verbose, "idle-node") || !strings.Contains(verbose, "idle-group") {
		t.Fatalf("verbose lost expanded or idle traffic rows:\n%s", verbose)
	}
}

func TestTrafficColumnsAlignAcrossScopes(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 0)
	snapshot := trafficTestSnapshot()
	// Keep the first group expanded while the second is collapsed.
	snapshot.Groups[0].Nodes[1].Stats.UploadBytes = 1
	// Distinct rates and totals let the assertions locate each field in the
	// rendered output, independent of byte offsets in CJK/colored names.
	snapshot.Stats = api.PathStats{UploadBytes: 4096, DownloadBytes: 8192,
		History: api.TrafficHistory{UploadBytesPerSecond: []uint64{100000}, DownloadBytesPerSecond: []uint64{200000}}}
	for _, color := range []bool{false, true} {
		colorsEnabled = color
		got := text.StripEscape(renderTraffic(snapshot, trafficOrdinary))
		lines := strings.Split(got, "\n")
		column := func(line, label string) int {
			position := strings.Index(line, label)
			if position < 0 {
				t.Fatalf("missing %q in %q", label, line)
			}
			return text.StringWidthWithoutEscSequences(line[:position])
		}
		if column(lines[0], "MAX ↓") >= column(lines[0], "TOTAL ↑") || !strings.HasSuffix(lines[0], "TOTAL ↓") {
			t.Fatalf("totals did not follow both rate columns:\n%s", got)
		}
		for _, tc := range []struct {
			row              int
			upload, download string
		}{{1, "4.00K", "8.00K"}, {2, "2.93K", "3.91K"}, {3, "512", "2.00K"}, {5, "16.0K", "8.00K"}} {
			if column(lines[tc.row], tc.upload) != column(lines[0], "TOTAL ↑") || column(lines[tc.row], tc.download) != column(lines[0], "TOTAL ↓") {
				t.Fatalf("scope totals shifted:\n%s", got)
			}
		}
		var slashes []int
		metricsStart := column(lines[0], "AVG")
		for i, line := range lines[:4] {
			var current []int
			for pos, r := range line {
				if r == '/' && text.StringWidthWithoutEscSequences(line[:pos]) >= metricsStart {
					current = append(current, text.StringWidthWithoutEscSequences(line[:pos]))
				}
			}
			if i == 0 {
				slashes = current
			} else if !slices.Equal(current, slashes) {
				t.Fatalf("rate subfields shifted:\n%s", got)
			}
		}
	}
}

func TestTrafficTableSingleLineNamesAndNarrowWidths(t *testing.T) {
	withoutStatusColors(t)
	snapshot := trafficTestSnapshot()
	snapshot.Groups[0].Name = "proxy\n jp"
	snapshot.Groups[0].Nodes[0].Name = "香港\t节点\n" + strings.Repeat("香港节点", 20)
	for _, width := range []int{40, 64, 80, 120} {
		for _, color := range []bool{false, true} {
			withStatusTerminalWidth(t, width)
			colorsEnabled = color
			for _, mode := range []trafficMode{trafficOrdinary, trafficRecent, trafficVerbose} {
				got := renderTraffic(snapshot, mode)
				wantRows := 4
				if mode == trafficRecent {
					wantRows = 3
				} else if mode == trafficVerbose {
					wantRows = 8
				}
				if len(strings.Split(got, "\n")) != wantRows || text.LongestLineLen(got) > width {
					t.Fatalf("width=%d color=%v mode=%v: dialers wrapped or overflowed:\n%s", width, color, mode, got)
				}
			}
		}
	}
}

func TestTrafficIsOneSharedBottomTable(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 0)
	snapshot := trafficTestSnapshot()
	for _, mode := range []trafficMode{trafficRecent, trafficOrdinary, trafficVerbose} {
		var out strings.Builder
		if mode == trafficRecent {
			PrintRecent(&out, snapshot)
		} else {
			Print(&out, snapshot, mode == trafficVerbose)
		}
		before, after, found := strings.Cut(out.String(), "\nTraffic:\n")
		if !found || strings.Contains(after, "Traffic:") || strings.Contains(before, "bps") || strings.Contains(before, "Total:") || strings.Contains(before, "TOTAL ↑") {
			t.Fatalf("mode=%v: traffic remained scattered:\n%s", mode, out.String())
		}
		if !strings.Contains(before, "idle-group") || !strings.Contains(after, "ALL") || !strings.Contains(after, "proxy_jp") || !strings.Contains(after, "日本高级 IEPL 专线 1") {
			t.Fatalf("mode=%v: lost overview or per-dialer traffic:\n%s", mode, out.String())
		}
		if after != renderTraffic(snapshot, mode)+"\n" {
			t.Fatalf("mode=%v: traffic did not use the shared renderer", mode)
		}
		if strings.Contains(after, "proxy_hk") == (mode == trafficRecent) {
			t.Fatalf("mode=%v: wrong visibility for historical-only group:\n%s", mode, after)
		}
	}
}

func TestTrafficDetailsFitActualWidth(t *testing.T) {
	withoutStatusColors(t)
	groups := []api.GroupStatus{recentTestGroup(), recentTestGroup()}
	groups[0].Name = "香港出口"
	groups[0].Stats.History = api.TrafficHistory{
		UploadBytesPerSecond: []uint64{100, 300}, DownloadBytesPerSecond: []uint64{500, 1500},
	}
	groups[1].Name = "idle"
	groups[1].Stats.History = api.TrafficHistory{}
	for _, color := range []bool{false, true} {
		t.Run(fmt.Sprint("color=", color), func(t *testing.T) {
			colorsEnabled = color
			withStatusTerminalWidth(t, 0)
			snapshot := &api.StatusSnapshot{Groups: groups}
			wide := renderTraffic(snapshot, trafficOrdinary)
			for _, want := range []string{"AVG", "MAX", "1.60/2.40Kbps", "8.00/12.0Kbps"} {
				if !strings.Contains(text.StripEscape(wide), want) {
					t.Fatalf("wide table lost %q:\n%s", want, wide)
				}
			}
			width := text.LongestLineLen(wide)
			withStatusTerminalWidth(t, width)
			if got := renderTraffic(snapshot, trafficOrdinary); got != wide {
				t.Fatalf("exact-fit table lost details:\n%s", got)
			}
			withStatusTerminalWidth(t, width-1)
			compact := renderTraffic(snapshot, trafficOrdinary)
			if strings.Contains(compact, "AVG") || strings.Contains(compact, "bps") {
				t.Fatalf("non-fitting details were partially displayed:\n%s", compact)
			}
			plain := text.StripEscape(compact)
			if !strings.Contains(plain, "..........▂▃") || !strings.Contains(plain, "..........▄█") {
				t.Fatalf("compact table lost either graph:\n%s", compact)
			}
			if lines := strings.Split(compact, "\n"); len(lines) != len(groups)+2 || !strings.HasSuffix(lines[3], formatBytes(groups[1].Stats.DownloadBytes)) {
				t.Fatalf("groups wrapped or absent history gained data:\n%s", compact)
			}
			for line := range strings.SplitSeq(compact, "\n") {
				if text.StringWidthWithoutEscSequences(line) > width-1 {
					t.Fatalf("line exceeds terminal width: %q", line)
				}
			}
		})
	}
}

func TestTrafficKeepsActiveAndHistoricalDialers(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 0)
	snapshot := &api.StatusSnapshot{Stats: api.PathStats{UploadBytes: 32768}, Groups: []api.GroupStatus{{Name: "proxy",
		SelectedNodeIDs: api.NetworkValues[string]{"waiting", "zero"},
		Stats: api.PathStats{ActiveConnections: 2, UploadBytes: 4096, DownloadBytes: 8192,
			History: api.TrafficHistory{UploadBytesPerSecond: []uint64{1, 0}, DownloadBytesPerSecond: []uint64{0, 1}}}, Nodes: []api.NodeStatus{
			{ID: "waiting", Name: "waiting", Stats: api.PathStats{ActiveConnections: 1}},
			{ID: "recent", Name: "recent", Stats: api.PathStats{UploadBytes: 100, History: api.TrafficHistory{UploadBytesPerSecond: []uint64{1, 0}, DownloadBytesPerSecond: []uint64{0, 0}}}},
			{ID: "past", Name: "past-only", Stats: api.PathStats{DownloadBytes: 100}},
			{ID: "zero", Name: "zero-selected", Stats: api.PathStats{ActiveConnections: 1, UploadBytes: 1024,
				History: api.TrafficHistory{UploadBytesPerSecond: []uint64{0, 0}, DownloadBytesPerSecond: []uint64{0, 0}}}},
			{ID: "download", Name: "download-only", Stats: api.PathStats{DownloadBytes: 100,
				History: api.TrafficHistory{UploadBytesPerSecond: []uint64{0, 0}, DownloadBytesPerSecond: []uint64{0, 1}}}},
			{ID: "empty", Name: "empty"},
		}}}}
	got := renderTraffic(snapshot, trafficOrdinary)
	for _, want := range []string{"proxy", "waiting", "recent", "past-only", "zero-selected", "download-only"} {
		if !strings.Contains(got, want) {
			t.Fatalf("lost %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "empty") || len(strings.Split(got, "\n")) != 8 {
		t.Fatalf("unexpected traffic rows:\n%s", got)
	}
	// Both directions count, even when a small nonzero maximum has a zero average.
	recent := renderTraffic(snapshot, trafficRecent)
	for _, hidden := range []string{"waiting", "past-only", "zero-selected", "empty"} {
		if strings.Contains(recent, hidden) {
			t.Fatalf("recent retained zero-rate dialer %q:\n%s", hidden, recent)
		}
	}
	if len(strings.Split(recent, "\n")) != 5 || !strings.Contains(recent, "proxy (total)") ||
		!strings.Contains(recent, "  recent") || !strings.Contains(recent, "  download-only") {
		t.Fatalf("recent lost nonzero upload/download samples:\n%s", recent)
	}
	group := &snapshot.Groups[0]
	clear(group.Nodes[4].Stats.History.DownloadBytesPerSecond)
	clear(group.Stats.History.DownloadBytesPerSecond)
	recent = renderTraffic(snapshot, trafficRecent)
	if len(strings.Split(recent, "\n")) != 3 || !strings.Contains(recent, "proxy(recent)") ||
		!strings.Contains(recent, "4.00K") || !strings.Contains(recent, "8.00K") {
		t.Fatalf("recent did not collapse the filtered singleton with group totals:\n%s", recent)
	}
	clear(group.Nodes[1].Stats.History.UploadBytesPerSecond)
	clear(group.Stats.History.UploadBytesPerSecond)
	if got := renderTraffic(snapshot, trafficRecent); len(strings.Split(got, "\n")) != 2 || !strings.Contains(got, "32.0K") {
		t.Fatalf("zero-rate group was retained or ALL totals were lost:\n%s", got)
	}
}

func TestTrafficCollapsesUniqueRelevantDialer(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 0)
	for _, tc := range []struct {
		name       string
		selected   api.NetworkValues[string]
		firstBytes uint64
		otherBytes uint64
		sameName   bool
		collapsed  bool
	}{
		{"selected and data", api.NetworkValues[string]{"a", "a", "a", "a"}, 100, 0, false, true},
		{"data only", api.NetworkValues[string]{}, 100, 0, false, true},
		{"selected only with group history", api.NetworkValues[string]{"a", "", "a", ""}, 0, 0, false, true},
		{"selected differs from data", api.NetworkValues[string]{"a"}, 0, 100, false, false},
		{"split selections", api.NetworkValues[string]{"a", "b", "a", "b"}, 0, 0, false, false},
		{"same label distinct IDs", api.NetworkValues[string]{"a"}, 100, 100, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			group := api.GroupStatus{Name: "proxy_jp", SelectedNodeIDs: tc.selected,
				Stats: api.PathStats{UploadBytes: 4096, DownloadBytes: 8192},
				Nodes: []api.NodeStatus{
					{ID: "a", Name: "lightsail", Stats: api.PathStats{UploadBytes: tc.firstBytes}},
					{ID: "b", Name: "backup", Stats: api.PathStats{UploadBytes: tc.otherBytes}},
				},
			}
			if tc.sameName {
				group.Nodes[1].Name = group.Nodes[0].Name
			}
			snapshot := &api.StatusSnapshot{Groups: []api.GroupStatus{group}}
			got := renderTraffic(snapshot, trafficOrdinary)
			lines := strings.Split(got, "\n")
			wantRows := 5
			if tc.collapsed {
				wantRows = 3
			}
			if len(lines) != wantRows || strings.Contains(got, "proxy_jp(lightsail)") != tc.collapsed {
				t.Fatalf("wrong singleton decision:\n%s", got)
			}
			if !strings.Contains(lines[2], "4.00K") || !strings.Contains(lines[2], "8.00K") {
				t.Fatalf("group history replaced by dialer counters:\n%s", got)
			}
			if !tc.collapsed && (!strings.Contains(lines[2], "proxy_jp (total)") || !strings.HasPrefix(lines[3], "  ")) {
				t.Fatalf("expanded hierarchy missing:\n%s", got)
			}
		})
	}
	// A selection alone does not add a completely idle group to the traffic view.
	idle := &api.StatusSnapshot{Groups: []api.GroupStatus{{Name: "unused", SelectedNodeIDs: api.NetworkValues[string]{"a"}, Nodes: []api.NodeStatus{{ID: "a", Name: "lightsail"}}}}}
	if got := renderTraffic(idle, trafficOrdinary); strings.Contains(got, "unused") {
		t.Fatalf("selection added an idle group:\n%s", got)
	}
}
