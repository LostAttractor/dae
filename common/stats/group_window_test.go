/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"slices"
	"testing"
	"time"
)

func TestRecentGroupStatesBucketsWorstState(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	var recent recentGroupStates
	recent.record(now.Add(-70*time.Minute), GroupStateAvailable)
	recent.record(now.Add(-50*time.Minute), GroupStateChecking)
	recent.record(now.Add(-49*time.Minute), GroupStateAvailable)
	recent.record(now.Add(-20*time.Minute), GroupStateUnavailable)
	recent.record(now.Add(-19*time.Minute), GroupStateAvailable)

	current, window := recent.snapshot(now)
	if current != GroupStateAvailable {
		t.Fatalf("current state = %q, want available", current)
	}
	want := []GroupState{
		GroupStateAvailable,
		GroupStateChecking,
		GroupStateAvailable,
		GroupStateAvailable,
		GroupStateAvailable,
		GroupStateAvailable,
		GroupStateUnavailable,
		GroupStateAvailable,
		GroupStateAvailable,
		GroupStateAvailable,
	}
	if !slices.Equal(window.States, want) {
		t.Fatalf("bucket states = %q, want %q", window.States, want)
	}
}

func TestRecentGroupStatesUsesNewerBucketAtBoundary(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	var recent recentGroupStates
	recent.record(now.Add(-70*time.Minute), GroupStateAvailable)
	recent.record(now.Add(-54*time.Minute), GroupStateUnavailable)

	_, window := recent.snapshot(now)
	if window.States[0] != GroupStateAvailable || window.States[1] != GroupStateUnavailable {
		t.Fatalf("boundary buckets = %q/%q, want available/unavailable", window.States[0], window.States[1])
	}
}

func TestRecentGroupStatesRecoveryAtBoundaryDoesNotPolluteNewBucket(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	var recent recentGroupStates
	recent.record(now.Add(-70*time.Minute), GroupStateUnavailable)
	recent.record(now.Add(-54*time.Minute), GroupStateAvailable)

	_, window := recent.snapshot(now)
	if window.States[0] != GroupStateUnavailable || window.States[1] != GroupStateAvailable {
		t.Fatalf("boundary buckets = %q/%q, want unavailable/available", window.States[0], window.States[1])
	}
}

func TestRecentGroupStatesMarksPartialObservationChecking(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	var recent recentGroupStates
	recent.record(now.Add(-57*time.Minute), GroupStateAvailable)

	_, window := recent.snapshot(now)
	if window.States[0] != GroupStateChecking {
		t.Fatalf("partially observed bucket = %q, want checking", window.States[0])
	}
	for i, state := range window.States[1:] {
		if state != GroupStateAvailable {
			t.Fatalf("bucket %d = %q, want available", i+1, state)
		}
	}
}

func TestRecentGroupStatesCoalescesRepeatedState(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	var recent recentGroupStates
	for i := 0; i < 100; i++ {
		recent.record(now.Add(time.Duration(i)*time.Second), GroupStateChecking)
	}
	if len(recent.transitions) != 1 {
		t.Fatalf("transition count = %d, want 1", len(recent.transitions))
	}
}
