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
	states := []stats.GroupHistoryState{
		stats.GroupHistoryAvailable,
		stats.GroupHistoryUnknown,
		stats.GroupHistoryUnavailable,
	}
	return control.GroupStatus{
		Name:               "proxy",
		ChecksConnectivity: true,
		Connectivity:       stats.GroupStateAvailable,
		Availability: stats.GroupAvailability{
			Availability: stats.Availability{Seen: true, Recent24h: stats.AvailabilityWindow{UpRatio: 0.9992}},
			Recent:       stats.GroupStateWindow{States: states},
		},
		Stats: stats.PathStats{
			ActiveConnections: 31,
			TrafficCounters:   stats.TrafficCounters{UploadBytes: 3000, DownloadBytes: 4000},
			TrafficRate:       stats.TrafficRate{UploadBytesPerSecond: 100, DownloadBytesPerSecond: 200},
		},
	}
}

func TestRecentGroupRow(t *testing.T) {
	withoutStatusColors(t)
	row := recentGroupRow(recentTestGroup(), 2)
	want := []string{
		"proxy", "UP", "[+.x.......] / 1H", "99.92% / 24H", "31 active",
		"100B/200B", "U/D rate", "2.93K/3.91K", "U/D total",
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

func TestRecentTimelinePadsUnknownBuckets(t *testing.T) {
	withoutStatusColors(t)
	group := recentTestGroup()
	if got := recentTimeline(group); got != "[+.x.......] / 1H" {
		t.Fatalf("recentTimeline() = %q", got)
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
	if text.StringWidth(rendered) == 0 {
		t.Fatal("rendered table is empty")
	}
}
