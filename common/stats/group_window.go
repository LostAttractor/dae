/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import "time"

const (
	GroupStateWindowDuration = time.Hour
	GroupStateBucketCount    = 10
)

// GroupState describes the aggregate connectivity of a checked outbound group.
type GroupState string

const (
	GroupStateAvailable   GroupState = "available"
	GroupStateChecking    GroupState = "checking"
	GroupStateUnavailable GroupState = "unavailable"
)

type GroupHistoryState string

const (
	GroupHistoryUnknown     GroupHistoryState = "unknown"
	GroupHistoryAvailable   GroupHistoryState = "available"
	GroupHistoryUnavailable GroupHistoryState = "unavailable"
)

type GroupStateWindow struct {
	Duration time.Duration
	States   []GroupHistoryState
}

type groupStateTransition struct {
	at    time.Time
	state GroupHistoryState
}

// recentGroupStates retains state changes rather than periodic samples. A
// snapshot projects them into fixed-width buckets, so repeated check requests
// cannot push useful history out of the window.
type recentGroupStates struct {
	transitions []groupStateTransition
}

func emptyGroupStateWindow() GroupStateWindow {
	window := GroupStateWindow{
		Duration: GroupStateWindowDuration,
		States:   make([]GroupHistoryState, GroupStateBucketCount),
	}
	for i := range window.States {
		window.States[i] = GroupHistoryUnknown
	}
	return window
}

func (r *recentGroupStates) record(now time.Time, available bool) {
	state := GroupHistoryUnavailable
	if available {
		state = GroupHistoryAvailable
	}
	if len(r.transitions) == 0 || r.transitions[len(r.transitions)-1].state != state {
		r.transitions = append(r.transitions, groupStateTransition{at: now, state: state})
	}
	r.prune(now.Add(-GroupStateWindowDuration))
}

func (r *recentGroupStates) snapshot(now time.Time) GroupStateWindow {
	r.prune(now.Add(-GroupStateWindowDuration))
	window := emptyGroupStateWindow()
	if len(r.transitions) == 0 {
		return window
	}

	windowStart := now.Add(-GroupStateWindowDuration)
	bucketDuration := GroupStateWindowDuration / GroupStateBucketCount
	transitionIndex := 0
	current := GroupHistoryUnknown
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

func worseGroupState(current, next GroupHistoryState) GroupHistoryState {
	severity := func(state GroupHistoryState) int {
		switch state {
		case GroupHistoryAvailable:
			return 1
		case GroupHistoryUnavailable:
			return 2
		default:
			return 0
		}
	}
	if severity(next) > severity(current) {
		return next
	}
	return current
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
