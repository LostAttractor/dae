/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package status

import (
	"fmt"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/jedib0t/go-pretty/v6/text"
)

func recentTestGroup() api.GroupStatus {
	states := make([]api.GroupHistoryState, api.GroupStateBucketCount)
	states[0] = api.GroupHistoryAvailable
	states[1] = api.GroupHistoryUnknown
	states[2] = api.GroupHistoryUnavailable
	return api.GroupStatus{
		Name:               "proxy",
		ChecksConnectivity: true,
		Connectivity:       api.GroupStateAvailable,
		Availability: api.GroupAvailability{
			Availability: api.Availability{Seen: true, Recent24h: api.AvailabilityWindow{UpRatio: 0.9992}},
			Recent:       api.GroupStateWindow{States: states},
		},
		Stats: api.PathStats{
			ActiveConnections:   31,
			FallbackConnections: 2,
			TrafficCounters:     api.TrafficCounters{UploadBytes: 3000, DownloadBytes: 4000},
			History: api.TrafficHistory{
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
	group := api.GroupStatus{Name: "direct", Stats: api.PathStats{ActiveConnections: 3}}
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
	group.Connectivity = api.GroupStateChecking
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
	groups := []api.GroupStatus{recentTestGroup()}
	groups[0].Name = "a very long outbound group name"
	rendered := renderRecentGroups(groups)
	if !strings.Contains(rendered, "…") {
		t.Fatalf("long group name was not truncated:\n%s", rendered)
	}
}

func TestRenderRecentGroupsFitsTerminal(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 80)
	rendered := renderRecentGroups([]api.GroupStatus{recentTestGroup()})
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
