/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"time"

	"github.com/daeuniverse/dae/api"
)

type groupStateTransition struct {
	at    time.Time
	state api.GroupHistoryState
}

// recentGroupStates retains state changes rather than periodic samples. A
// snapshot projects them into fixed-width buckets, so repeated check requests
// cannot push useful history out of the window.
type recentGroupStates struct {
	transitions []groupStateTransition
}

func emptyGroupStateWindow() api.GroupStateWindow {
	window := api.GroupStateWindow{
		States: make([]api.GroupHistoryState, api.GroupStateBucketCount),
	}
	for i := range window.States {
		window.States[i] = api.GroupHistoryUnknown
	}
	return window
}

func (r *recentGroupStates) record(now time.Time, available bool) {
	state := api.GroupHistoryUnavailable
	if available {
		state = api.GroupHistoryAvailable
	}
	if len(r.transitions) == 0 || r.transitions[len(r.transitions)-1].state != state {
		r.transitions = append(r.transitions, groupStateTransition{at: now, state: state})
	}
	r.prune(now.Add(-api.GroupStateWindowDuration))
}

func (r *recentGroupStates) snapshot(now time.Time) api.GroupStateWindow {
	r.prune(now.Add(-api.GroupStateWindowDuration))
	window := emptyGroupStateWindow()
	if len(r.transitions) == 0 {
		return window
	}

	windowStart := now.Add(-api.GroupStateWindowDuration)
	bucketDuration := api.GroupStateWindowDuration / api.GroupStateBucketCount
	transitionIndex := 0
	current := api.GroupHistoryUnknown
	for transitionIndex < len(r.transitions) && !r.transitions[transitionIndex].at.After(windowStart) {
		current = r.transitions[transitionIndex].state
		transitionIndex++
	}

	for bucketIndex := range window.States {
		bucketStart := windowStart.Add(time.Duration(bucketIndex) * bucketDuration)
		bucketEnd := bucketStart.Add(bucketDuration)
		for transitionIndex < len(r.transitions) && r.transitions[transitionIndex].at.Equal(bucketStart) {
			current = r.transitions[transitionIndex].state
			transitionIndex++
		}
		worst := current
		for transitionIndex < len(r.transitions) {
			transition := r.transitions[transitionIndex]
			inside := transition.at.Before(bucketEnd)
			if bucketIndex == len(window.States)-1 {
				inside = !transition.at.After(bucketEnd)
			}
			if !inside {
				break
			}
			current = transition.state
			worst = worseGroupState(worst, current)
			transitionIndex++
		}
		window.States[bucketIndex] = worst
	}

	return window
}

func worseGroupState(current, next api.GroupHistoryState) api.GroupHistoryState {
	if current == api.GroupHistoryUnavailable || next == api.GroupHistoryUnavailable {
		return api.GroupHistoryUnavailable
	}
	if current == api.GroupHistoryAvailable || next == api.GroupHistoryAvailable {
		return api.GroupHistoryAvailable
	}
	return api.GroupHistoryUnknown
}

func (r *recentGroupStates) prune(cutoff time.Time) {
	firstInside := 0
	for firstInside < len(r.transitions) && r.transitions[firstInside].at.Before(cutoff) {
		firstInside++
	}
	keepFrom := firstInside
	if keepFrom > 0 {
		keepFrom--
	}
	if keepFrom > 0 {
		copy(r.transitions, r.transitions[keepFrom:])
		r.transitions = r.transitions[:len(r.transitions)-keepFrom]
	}
}
