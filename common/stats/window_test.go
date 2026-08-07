/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"math"
	"testing"
	"time"
)

func TestRecentAvailabilityTrailing24Hours(t *testing.T) {
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	firstSeen := now.Add(-30 * time.Hour)
	var recent recentAvailability

	recent.record(firstSeen, true, false)
	recent.record(now.Add(-25*time.Hour), true, true)  // outside the window
	recent.record(now.Add(-24*time.Hour), true, true)  // inclusive boundary
	recent.record(now.Add(-18*time.Hour), false, true) // down for six hours
	recent.record(now.Add(-12*time.Hour), true, true)  // up for eleven hours
	recent.record(now.Add(-time.Hour), false, true)

	got := recent.snapshot(firstSeen, now)
	wantRatio := 17.0 / 24.0
	if math.Abs(got.UpRatio-wantRatio) > 1e-9 {
		t.Fatalf("UpRatio = %v, want %v", got.UpRatio, wantRatio)
	}
	if got.ChecksTotal != 4 || got.ChecksFailed != 2 {
		t.Fatalf("checks = %d/%d, want failures/total 2/4", got.ChecksFailed, got.ChecksTotal)
	}
}

func TestRecentAvailabilityUsesObservedDurationForYoungNode(t *testing.T) {
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	firstSeen := now.Add(-6 * time.Hour)
	var recent recentAvailability

	recent.record(firstSeen, false, false)
	recent.record(now.Add(-4*time.Hour), true, true)
	recent.record(now.Add(-time.Hour), true, true)

	got := recent.snapshot(firstSeen, now)
	wantRatio := 4.0 / 6.0
	if math.Abs(got.UpRatio-wantRatio) > 1e-9 {
		t.Fatalf("UpRatio = %v, want %v", got.UpRatio, wantRatio)
	}
	if got.ChecksTotal != 2 || got.ChecksFailed != 0 {
		t.Fatalf("checks = %d/%d, want failures/total 0/2", got.ChecksFailed, got.ChecksTotal)
	}
}

func TestRecentAvailabilityKeepsCheckAtFirstObservation(t *testing.T) {
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	var recent recentAvailability
	recent.record(now, false, true)

	got := recent.snapshot(now, now)
	if got.ChecksTotal != 1 || got.ChecksFailed != 1 {
		t.Fatalf("checks = %d/%d, want failures/total 1/1", got.ChecksFailed, got.ChecksTotal)
	}
}
