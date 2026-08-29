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
		Traffic: control.TrafficStatus{
			WindowSeconds: 1, UploadBytesPerSecond: 1536, DownloadBytesPerSecond: 2 * 1024 * 1024,
			UploadBytes: 3 * 1024 * 1024 * 1024, DownloadBytes: 5 * 1024 * 1024,
		},
		Connectivity: &control.GroupConnectivityStatus{
			State:      control.GroupConnectivityAvailable,
			UpRatio24h: &ratio,
			Recent: control.GroupRecentStatus{
				WindowSeconds: 3600,
				Buckets: []control.GroupBucketState{
					control.GroupBucketAvailable,
					control.GroupBucketUnknown,
					control.GroupBucketUnavailable,
				},
			},
		},
	}, 2)
	want := []string{
		"proxy", "UP", "[+.x.......] / 1H", "99.92% / 24H", "31 active",
		"1.50K/2.00M", "U/D rate", "3.00G/5.00M", "U/D total",
	}
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

	row := recentGroupRow(control.GroupStatus{Name: "direct", ActiveConns: 3}, 1)
	want := []string{"direct", "", "", "", "3 active", "-", "U/D rate", "-", "U/D total"}
	if len(row) != len(want) {
		t.Fatalf("recentGroupRow() has %d cells, want %d", len(row), len(want))
	}
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
			Recent: control.GroupRecentStatus{Buckets: []control.GroupBucketState{
				control.GroupBucketAvailable,
				control.GroupBucketUnknown,
				control.GroupBucketUnavailable,
			}},
		},
	}, 1)
	if got := row[1].(string); !strings.Contains(got, "\x1b[33m") {
		t.Fatalf("checking state = %q, want yellow", got)
	}
	timeline := row[2].(string)
	for _, ansi := range []string{"\x1b[32m", "\x1b[31m"} {
		if !strings.Contains(timeline, ansi) {
			t.Errorf("timeline = %q, want ANSI prefix %q", timeline, ansi)
		}
	}
	if strings.Contains(timeline, "\x1b[33m") {
		t.Fatalf("timeline = %q, checking must not be rendered yellow", timeline)
	}
}

func TestTruncateRecentGroupNameUsesDisplayWidth(t *testing.T) {
	if got := truncateRecentGroupName("香港节点-very-long-name", 12); text.StringWidth(got) > 12 || !strings.HasSuffix(got, "…") {
		t.Fatalf("truncated group name = %q (width %d), want ellipsis within 12 columns", got, text.StringWidth(got))
	}
}

func TestRecentTableAlignsActiveLabel(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = false
	defer func() { colorsEnabled = previousColorsEnabled }()

	connectivity := &control.GroupConnectivityStatus{
		State: control.GroupConnectivityAvailable,
		Recent: control.GroupRecentStatus{
			WindowSeconds: recentWindowSeconds,
			Buckets:       make([]control.GroupBucketState, control.GroupRecentBucketCount),
		},
	}
	groups := []control.GroupStatus{
		{Name: "direct"},
		{
			Name: "proxy", ActiveConns: 278, Connectivity: connectivity,
			Traffic: control.TrafficStatus{
				WindowSeconds: 1, UploadBytesPerSecond: 105 * 1024, DownloadBytesPerSecond: 9340,
				UploadBytes: 12 * 1024 * 1024 * 1024, DownloadBytes: 640 * 1024 * 1024,
			},
		},
	}
	rendered := renderRecentGroups(groups)
	lines := strings.Split(rendered, "\n")
	if len(lines) != 2 {
		t.Fatalf("rendered recent table = %q", rendered)
	}
	wantColumn := -1
	wantRateLabelColumn := -1
	wantRateValueColumn := -1
	wantTotalLabelColumn := -1
	wantTotalValueColumn := -1
	for i, line := range lines {
		index := strings.Index(line, "active")
		if index < 0 {
			t.Fatalf("recent row omits active label: %q", line)
		}
		column := text.StringWidth(line[:index])
		if strings.Contains(line, "0  active") || strings.Contains(line, "278  active") {
			t.Fatalf("active label has more than one separator: %q", line)
		}
		if wantColumn < 0 {
			wantColumn = column
		} else if column != wantColumn {
			t.Fatalf("active columns differ: %q", rendered)
		}
		rateLabelIndex := strings.Index(line, "U/D rate")
		if rateLabelIndex < 0 {
			t.Fatalf("recent row omits rate label: %q", line)
		}
		rateLabelColumn := text.StringWidth(line[:rateLabelIndex])
		if wantRateLabelColumn < 0 {
			wantRateLabelColumn = rateLabelColumn
		} else if rateLabelColumn != wantRateLabelColumn {
			t.Fatalf("rate label columns differ: %q", rendered)
		}
		rateValue := "-"
		if i == 1 {
			rateValue = "105K"
		}
		rateValueIndex := strings.Index(line, rateValue)
		if rateValueIndex < 0 {
			t.Fatalf("recent row omits rate value: %q", line)
		}
		rateValueColumn := text.StringWidth(line[:rateValueIndex])
		if wantRateValueColumn < 0 {
			wantRateValueColumn = rateValueColumn
		} else if rateValueColumn != wantRateValueColumn {
			t.Fatalf("rate values are not left-aligned: %q", rendered)
		}

		totalLabelIndex := strings.Index(line, "U/D total")
		if totalLabelIndex < 0 {
			t.Fatalf("recent row omits total label: %q", line)
		}
		totalLabelColumn := text.StringWidth(line[:totalLabelIndex])
		if wantTotalLabelColumn < 0 {
			wantTotalLabelColumn = totalLabelColumn
		} else if totalLabelColumn != wantTotalLabelColumn {
			t.Fatalf("total label columns differ: %q", rendered)
		}
		totalValueIndex := strings.LastIndex(line[:totalLabelIndex], "-")
		if i == 1 {
			totalValueIndex = strings.Index(line, "12.0G")
		}
		if totalValueIndex < 0 {
			t.Fatalf("recent row omits total value: %q", line)
		}
		totalValueColumn := text.StringWidth(line[:totalValueIndex])
		if wantTotalValueColumn < 0 {
			wantTotalValueColumn = totalValueColumn
		} else if totalValueColumn != wantTotalValueColumn {
			t.Fatalf("total values are not left-aligned: %q", rendered)
		}
	}
}
