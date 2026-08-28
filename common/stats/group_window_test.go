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
	recent.record(now.Add(-70*time.Minute), true)
	recent.record(now.Add(-50*time.Minute), false)
	recent.record(now.Add(-49*time.Minute), true)
	recent.record(now.Add(-20*time.Minute), false)
	recent.record(now.Add(-19*time.Minute), true)

	window := recent.snapshot(now)
	want := []GroupHistoryState{
		GroupHistoryAvailable,
		GroupHistoryUnavailable,
		GroupHistoryAvailable,
		GroupHistoryAvailable,
		GroupHistoryAvailable,
		GroupHistoryAvailable,
		GroupHistoryUnavailable,
		GroupHistoryAvailable,
		GroupHistoryAvailable,
		GroupHistoryAvailable,
	}
	if !slices.Equal(window.States, want) {
		t.Fatalf("bucket states = %q, want %q", window.States, want)
	}
}

func TestRecentGroupStatesUsesNewerBucketAtBoundary(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	var recent recentGroupStates
	recent.record(now.Add(-70*time.Minute), true)
	recent.record(now.Add(-54*time.Minute), false)

	window := recent.snapshot(now)
	if window.States[0] != GroupHistoryAvailable || window.States[1] != GroupHistoryUnavailable {
		t.Fatalf("boundary buckets = %q/%q, want available/unavailable", window.States[0], window.States[1])
	}
}

func TestRecentGroupStatesRecoveryAtBoundaryDoesNotPolluteNewBucket(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	var recent recentGroupStates
	recent.record(now.Add(-70*time.Minute), false)
	recent.record(now.Add(-54*time.Minute), true)

	window := recent.snapshot(now)
	if window.States[0] != GroupHistoryUnavailable || window.States[1] != GroupHistoryAvailable {
		t.Fatalf("boundary buckets = %q/%q, want unavailable/available", window.States[0], window.States[1])
	}
}

func TestRecentGroupStatesUsesFirstObservedStateForPartialBucket(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	var recent recentGroupStates
	recent.record(now.Add(-57*time.Minute), true)

	window := recent.snapshot(now)
	if window.States[0] != GroupHistoryAvailable {
		t.Fatalf("partially observed bucket = %q, want available", window.States[0])
	}
	for i, state := range window.States[1:] {
		if state != GroupHistoryAvailable {
			t.Fatalf("bucket %d = %q, want available", i+1, state)
		}
	}
}

func TestRecentGroupStatesCoalescesRepeatedState(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	var recent recentGroupStates
	for i := 0; i < 100; i++ {
		recent.record(now.Add(time.Duration(i)*time.Second), true)
	}
	if len(recent.transitions) != 1 {
		t.Fatalf("transition count = %d, want 1", len(recent.transitions))
	}
}
