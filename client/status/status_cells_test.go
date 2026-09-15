// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/pkg/clitable"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

func metricAnchors(line string) []int {
	var positions []int
	line = text.StripEscape(line)
	for offset, r := range line {
		if r == '/' || r == '↑' || r == '↓' {
			positions = append(positions, text.StringWidthWithoutEscSequences(line[:offset]))
		}
	}
	return positions
}

func TestStatusCompositeMetricsAlign(t *testing.T) {
	withoutStatusColors(t)
	now := time.Now()
	first, second := testNodeStatus(now), testNodeStatus(now)
	first.Name, second.Name = "日本节点", "short"
	first.Stats.ActiveConnections, first.Stats.TotalConnections, first.Stats.FallbackConnections = 47, 89296, 0
	second.Stats.ActiveConnections, second.Stats.TotalConnections, second.Stats.FallbackConnections = 8, 402, 12
	first.Availability.LastFailureStartedAt, first.Availability.LastFailureDuration = now.Add(-31*time.Second), 0
	second.Availability.LastFailureStartedAt, second.Availability.LastFailureDuration = now.Add(-85*time.Second), 85*time.Second
	first.Latency.Last, first.Latency.Avg10, first.Latency.MovingAvg = 9*time.Millisecond, 1020*time.Millisecond, 40*time.Millisecond
	first.Availability.UpRatio = 1
	first.Availability.ChecksFailed, first.Availability.ChecksTotal = 1, 20000
	second.Availability.ChecksFailed, second.Availability.ChecksTotal = 12, 999
	first.Stats.History = api.TrafficHistory{UploadBytesPerSecond: []uint64{0, 1250000}, DownloadBytesPerSecond: []uint64{100, 100}}
	second.Stats.History = api.TrafficHistory{UploadBytesPerSecond: []uint64{10, 110}, DownloadBytesPerSecond: []uint64{0, 12500000}}
	first.Stats.UploadBytes, first.Stats.DownloadBytes = 8800000, 270000000
	second.Stats.UploadBytes, second.Stats.DownloadBytes = 0, 1
	group := api.GroupStatus{Nodes: []api.NodeStatus{first, second}}
	for _, verbose := range []bool{false, true} {
		for _, color := range []bool{false, true} {
			colorsEnabled = color
			header, rows := nodeTable(group, verbose, now)
			rendered := renderStatusTable(header, rows, nil, 0)
			lines := strings.Split(rendered, "\n")
			if len(lines) != 3 {
				t.Fatalf("unexpected table lines: %s", rendered)
			}
			a, b := metricAnchors(lines[1]), metricAnchors(lines[2])
			if len(a) < 7 || !reflect.DeepEqual(a, b) {
				t.Fatalf("verbose=%t color=%t metrics shifted: %v vs %v\n%s", verbose, color, a, b, rendered)
			}
			if !verbose {
				column := func(line, label string) int {
					line = text.StripEscape(line)
					position := strings.Index(line, label)
					if position < 0 {
						t.Fatalf("missing %q in %q", label, line)
					}
					return text.StringWidthWithoutEscSequences(line[:position])
				}
				for i, node := range group.Nodes {
					if column(lines[0], "UP") != column(lines[i+1], fmt.Sprintf("%.1f", node.Availability.UpRatio*100)) ||
						column(lines[0], "24H") != column(lines[i+1], fmt.Sprintf("%.1f%%", node.Availability.Recent24h.UpRatio*100)) {
						t.Fatalf("availability subheaders shifted:\n%s", rendered)
					}
				}
			}
		}
	}
}

func TestNetworkConnectionsAndUsageAlignParts(t *testing.T) {
	withoutStatusColors(t)
	group := api.GroupStatus{}
	group.Networks[0] = api.PathStats{ActiveConnections: 47, TotalConnections: 89296}
	group.Networks[1] = api.PathStats{ActiveConnections: 8, TotalConnections: 402}
	rows := clitable.AlignRows(uncheckedNetworkRows(group))
	if rows[0][1] != "47/89296" || rows[1][1] != "8 /402  " {
		t.Fatalf("network counts: %+v", rows)
	}
	usage := []table.Row{
		tableUsageRow(api.TableUsage{Name: "one", Breakdown: &api.TableUsageBreakdown{Live: 1, Retained: 20000}}),
		tableUsageRow(api.TableUsage{Name: "two", Breakdown: &api.TableUsageBreakdown{Live: 300, Retained: 4}}),
	}
	got := clitable.AlignRows(usage)
	if got[0][4] != "1  /20000" || got[1][4] != "300/4    " {
		t.Fatalf("usage counts: %+v", got)
	}
}
