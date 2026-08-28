/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/control"
	"github.com/jedib0t/go-pretty/v6/text"
)

func TestRecentGroupRow(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = false
	defer func() { colorsEnabled = previousColorsEnabled }()

	ratio := 0.9992
	row := recentGroupRow(control.GroupStatus{
		Name:        "proxy",
		ActiveConns: 31,
		Connectivity: &control.GroupConnectivityStatus{
			State:      control.GroupConnectivityAvailable,
			UpRatio24h: &ratio,
			Recent: control.GroupRecentStatus{
				WindowSeconds: 3600,
				Buckets: []control.GroupConnectivityState{
					control.GroupConnectivityAvailable,
					control.GroupConnectivityChecking,
					control.GroupConnectivityUnavailable,
				},
			},
		},
	})
	want := []string{"proxy", "UP", "[+?x.......] / 1H", "99.92% / 24H", "31 active"}
	for i, expected := range want {
		if got := fmt.Sprint(row[i]); got != expected {
			t.Errorf("recentGroupRow()[%d] = %q, want %q", i, got, expected)
		}
	}
}

func TestRecentGroupRowWithoutConnectivity(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = false
	defer func() { colorsEnabled = previousColorsEnabled }()

	row := recentGroupRow(control.GroupStatus{Name: "direct"})
	want := []string{"direct", "N/A", "[..........] / 1H", "- / 24H", "0 active"}
	for i, expected := range want {
		if got := fmt.Sprint(row[i]); got != expected {
			t.Errorf("recentGroupRow()[%d] = %q, want %q", i, got, expected)
		}
	}
}

func TestRecentGroupRowColors(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = true
	defer func() { colorsEnabled = previousColorsEnabled }()

	row := recentGroupRow(control.GroupStatus{
		Connectivity: &control.GroupConnectivityStatus{
			State: control.GroupConnectivityChecking,
			Recent: control.GroupRecentStatus{Buckets: []control.GroupConnectivityState{
				control.GroupConnectivityAvailable,
				control.GroupConnectivityChecking,
				control.GroupConnectivityUnavailable,
			}},
		},
	})
	if got := row[1].(string); !strings.Contains(got, "\x1b[33m") {
		t.Fatalf("checking state = %q, want yellow", got)
	}
	timeline := row[2].(string)
	for _, ansi := range []string{"\x1b[32m", "\x1b[33m", "\x1b[31m"} {
		if !strings.Contains(timeline, ansi) {
			t.Errorf("timeline = %q, want ANSI prefix %q", timeline, ansi)
		}
	}
}

func TestTruncateRecentGroupNameUsesDisplayWidth(t *testing.T) {
	if got := truncateRecentGroupName("香港节点-very-long-name", 12); text.StringWidth(got) > 12 || !strings.HasSuffix(got, "…") {
		t.Fatalf("truncated group name = %q (width %d), want ellipsis within 12 columns", got, text.StringWidth(got))
	}
}
