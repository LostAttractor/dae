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

func recordAvailability(recent *recentAvailability, at time.Time, alive, checked bool) {
	recent.record(at, at, alive, checked)
}

func TestRecentAvailabilityTrailing24Hours(t *testing.T) {
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	firstSeen := now.Add(-30 * time.Hour)
	var recent recentAvailability

	recordAvailability(&recent, firstSeen, true, false)
	recordAvailability(&recent, now.Add(-25*time.Hour), true, true)  // outside the window
	recordAvailability(&recent, now.Add(-24*time.Hour), true, true)  // inclusive boundary
	recordAvailability(&recent, now.Add(-18*time.Hour), false, true) // down for six hours
	recordAvailability(&recent, now.Add(-12*time.Hour), true, true)  // up for eleven hours
	recordAvailability(&recent, now.Add(-time.Hour), false, true)

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

	recordAvailability(&recent, firstSeen, false, false)
	recordAvailability(&recent, now.Add(-4*time.Hour), true, true)
	recordAvailability(&recent, now.Add(-time.Hour), true, true)

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
	recordAvailability(&recent, now, false, true)

	got := recent.snapshot(now, now)
	if got.ChecksTotal != 1 || got.ChecksFailed != 1 {
		t.Fatalf("checks = %d/%d, want failures/total 1/1", got.ChecksFailed, got.ChecksTotal)
	}
}
