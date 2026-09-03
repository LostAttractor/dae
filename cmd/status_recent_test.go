/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/control"
	"github.com/jedib0t/go-pretty/v6/text"
)

func recentTestGroup() control.GroupStatus {
	states := make([]stats.GroupHistoryState, stats.GroupStateBucketCount)
	states[0] = stats.GroupHistoryAvailable
	states[1] = stats.GroupHistoryUnknown
	states[2] = stats.GroupHistoryUnavailable
	return control.GroupStatus{
		Name:               "proxy",
		ChecksConnectivity: true,
		Connectivity:       stats.GroupStateAvailable,
		Availability: stats.GroupAvailability{
			Availability: stats.Availability{Seen: true, Recent24h: stats.AvailabilityWindow{UpRatio: 0.9992}},
			Recent:       stats.GroupStateWindow{States: states},
		},
		Stats: stats.PathStats{
			ActiveConnections:   31,
			FallbackConnections: 2,
			TrafficCounters:     stats.TrafficCounters{UploadBytes: 3000, DownloadBytes: 4000},
			History: stats.TrafficHistory{
				UploadBytesPerSecond: []uint64{100}, DownloadBytesPerSecond: []uint64{200},
			},
		},
	}
}

func TestRecentGroupRow(t *testing.T) {
	withoutStatusColors(t)
	row := recentGroupRow(recentTestGroup(), 2)
	want := []string{
		"proxy", "UP", "[+.x.......] / 1H", "99.92% / 24H", "31 active · 2 fallback total",
		"↑...........▅ ↓...........█",
	}
	if len(row) != len(want) {
		t.Fatalf("recentGroupRow() has %d columns, want %d: %+v", len(row), len(want), row)
	}
	for index, expected := range want {
		if got := fmt.Sprint(row[index]); got != expected {
			t.Errorf("recentGroupRow()[%d] = %q, want %q", index, got, expected)
		}
	}
}

func TestRecentUncheckedGroupRow(t *testing.T) {
	withoutStatusColors(t)
	group := control.GroupStatus{Name: "direct", Stats: stats.PathStats{ActiveConnections: 3}}
	row := recentGroupRow(group, 1)
	if got := fmt.Sprint(row[1]); got != "" {
		t.Fatalf("unchecked state = %q, want blank", got)
	}
	if got := fmt.Sprint(row[4]); got != "3 active" {
		t.Fatalf("activity = %q", got)
	}
}

func TestRecentGroupColor(t *testing.T) {
	previous := colorsEnabled
	colorsEnabled = true
	t.Cleanup(func() { colorsEnabled = previous })
	group := recentTestGroup()
	group.Connectivity = stats.GroupStateChecking
	row := recentGroupRow(group, 2)
	if got := row[1].(string); !strings.Contains(got, "\x1b[33m") {
		t.Fatalf("checking state lacks yellow ANSI: %q", got)
	}
	timeline := row[2].(string)
	if !strings.Contains(timeline, "●") || !strings.Contains(timeline, "○") {
		t.Fatalf("colored timeline = %q", timeline)
	}
}

func TestRenderRecentGroupsTruncatesWideNames(t *testing.T) {
	withoutStatusColors(t)
	groups := []control.GroupStatus{recentTestGroup()}
	groups[0].Name = "a very long outbound group name"
	rendered := renderRecentGroups(groups)
	if !strings.Contains(rendered, "…") {
		t.Fatalf("long group name was not truncated:\n%s", rendered)
	}
}

func TestRenderRecentGroupsFitsTerminal(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 80)
	rendered := renderRecentGroups([]control.GroupStatus{recentTestGroup()})
	if strings.Contains(rendered, "\n") {
		t.Fatalf("recent group wrapped:\n%s", rendered)
	}
	if width := text.StringWidthWithoutEscSequences(rendered); width > 80 {
		t.Fatalf("rendered line width = %d, want <= 80: %q", width, rendered)
	}
	fullTraffic := "↑...........▅ ↓...........█"
	if !strings.Contains(rendered, "↑") || strings.Contains(rendered, fullTraffic) {
		t.Fatalf("traffic column was not partially clipped:\n%s", rendered)
	}
}
