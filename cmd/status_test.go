/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/control"
)

func TestHasRecentFailure(t *testing.T) {
	failedAt := time.Now()
	tests := []struct {
		name            string
		lastFailAt      *time.Time
		checksSinceFail int64
		want            bool
	}{
		{name: "never failed", checksSinceFail: 2},
		{name: "missing counter", lastFailAt: &failedAt},
		{name: "latest check failed", lastFailAt: &failedAt, checksSinceFail: 1, want: true},
		{name: "failure at window edge", lastFailAt: &failedAt, checksSinceFail: avgLatencyWindowChecks, want: true},
		{name: "failure outside window", lastFailAt: &failedAt, checksSinceFail: avgLatencyWindowChecks + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasRecentFailure(tt.lastFailAt, tt.checksSinceFail); got != tt.want {
				t.Fatalf("hasRecentFailure() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNodeStatusRow(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = false
	defer func() { colorsEnabled = previousColorsEnabled }()

	row := nodeStatusRow(control.NodeStatus{
		Name:               "node-a",
		Protocol:           "vless",
		Alive:              true,
		Supported:          [4]bool{true, true, true, true},
		Selected:           [4]bool{true, false, false, false},
		HasLatency:         true,
		LastLatencyMs:      42,
		Avg10LatencyMs:     45,
		MovingAvgLatencyMs: 50,
		UpRatio:            0.998,
		ChecksTotal:        1000,
		ChecksFailed:       2,
		UpRatio24h:         0.995,
		ChecksTotal24h:     100,
		ChecksFailed24h:    1,
		ActiveConns:        2,
		TotalConns:         9000,
	})
	want := []string{
		"node-a", "-", "vless", "yes", "tcp4,tcp6,udp4,udp6", "tcp4",
		"42/45/50", "99.8% (2/1000)", "99.5% (1/100)", "-", "-", "-", "-", "2/9000",
	}
	if len(row) != len(want) {
		t.Fatalf("nodeStatusRow() has %d cells, want %d", len(row), len(want))
	}
	for i, expected := range want {
		if got := row[i].(string); got != expected {
			t.Errorf("nodeStatusRow()[%d] = %q, want %q", i, got, expected)
		}
	}
}

func TestNodeStatusRowHighlightsRecentFailure(t *testing.T) {
	previousColorsEnabled := colorsEnabled
	colorsEnabled = true
	defer func() { colorsEnabled = previousColorsEnabled }()

	failedAt := time.Now()
	row := nodeStatusRow(control.NodeStatus{
		Name:               "node-a",
		Alive:              true,
		Selected:           [4]bool{true, false, false, false},
		HasLatency:         true,
		LastLatencyMs:      42,
		Avg10LatencyMs:     60045,
		MovingAvgLatencyMs: 60045,
		LastFailAt:         &failedAt,
		ChecksSinceFail:    avgLatencyWindowChecks,
	})
	tests := []struct {
		cell int
		ansi string
	}{
		{cell: 0, ansi: "\x1b[36m"},
		{cell: 6, ansi: "\x1b[91;1m"},
		{cell: 10, ansi: "\x1b[31m"},
	}
	for _, tt := range tests {
		if got := row[tt.cell].(string); !strings.Contains(got, tt.ansi) {
			t.Errorf("nodeStatusRow()[%d] = %q, want ANSI prefix %q", tt.cell, got, tt.ansi)
		}
	}
}
