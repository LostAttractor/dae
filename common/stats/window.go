/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import "time"

const recentAvailabilityDuration = 24 * time.Hour

// AvailabilityWindow summarizes availability over a bounded observation
// window. UpRatio is time-weighted, while check counters count discrete health
// checks in the same window.
type AvailabilityWindow struct {
	UpRatio      float64
	ChecksTotal  int64
	ChecksFailed int64
}

type availabilityTransition struct {
	at    time.Time
	alive bool
}

// recentAvailability stores exact check timestamps plus state transitions.
// With the default 30-second check interval, this is about 2,880 timestamps
// per node; transitions are only appended when aliveness changes.
//
// Its owner, availability, serializes all access with availability.mu.
type recentAvailability struct {
	transitions  []availabilityTransition
	checkTimes   []time.Time
	failureTimes []time.Time
}

func (r *recentAvailability) record(now time.Time, alive, checked bool, transitionAt ...time.Time) {
	at := now
	if len(transitionAt) != 0 {
		at = transitionAt[0]
	}
	if len(r.transitions) == 0 || r.transitions[len(r.transitions)-1].alive != alive {
		r.transitions = append(r.transitions, availabilityTransition{at: at, alive: alive})
	}
	if checked {
		r.checkTimes = append(r.checkTimes, now)
		if !alive {
			r.failureTimes = append(r.failureTimes, now)
		}
	}
	r.prune(now.Add(-recentAvailabilityDuration))
}

func (r *recentAvailability) snapshot(firstSeen, now time.Time) AvailabilityWindow {
	if firstSeen.IsZero() {
		return AvailabilityWindow{}
	}

	cutoff := now.Add(-recentAvailabilityDuration)
	r.prune(cutoff)
	window := AvailabilityWindow{
		ChecksTotal:  int64(len(r.checkTimes)),
		ChecksFailed: int64(len(r.failureTimes)),
	}
	start := cutoff
	if firstSeen.After(start) {
		start = firstSeen
	}
	if !now.After(start) {
		return window
	}

	// record always creates an initial transition, and prune retains the last
	// transition before the cutoff as the state at the window boundary.
	if len(r.transitions) == 0 {
		return window
	}
	alive := r.transitions[0].alive
	cursor := start
	var up time.Duration
	for _, transition := range r.transitions[1:] {
		if transition.at.After(now) {
			break
		}
		if !transition.at.After(start) {
			alive = transition.alive
			continue
		}
		if alive {
			up += transition.at.Sub(cursor)
		}
		cursor = transition.at
		alive = transition.alive
	}
	if alive {
		up += now.Sub(cursor)
	}

	observed := now.Sub(start)
	if up < 0 {
		up = 0
	} else if up > observed {
		up = observed
	}
	window.UpRatio = float64(up) / float64(observed)
	return window
}

func (r *recentAvailability) prune(cutoff time.Time) {
	r.checkTimes = trimTimePoints(r.checkTimes, cutoff)
	r.failureTimes = trimTimePoints(r.failureTimes, cutoff)

	firstInside := 0
	for firstInside < len(r.transitions) && r.transitions[firstInside].at.Before(cutoff) {
		firstInside++
	}
	// Keep the last transition before the cutoff as the state at the start of
	// the window. All earlier transitions can no longer affect a snapshot.
	keepFrom := firstInside
	if keepFrom > 0 {
		keepFrom--
	}
	if keepFrom > 0 {
		copy(r.transitions, r.transitions[keepFrom:])
		r.transitions = r.transitions[:len(r.transitions)-keepFrom]
	}
}

func trimTimePoints(points []time.Time, cutoff time.Time) []time.Time {
	firstInside := 0
	for firstInside < len(points) && points[firstInside].Before(cutoff) {
		firstInside++
	}
	if firstInside == len(points) {
		return nil
	}
	points = points[firstInside:]
	// Periodically detach from a much larger backing array after old samples
	// have expired. Normally this copies at most once per window.
	if cap(points) > len(points)*2+64 {
		compacted := make([]time.Time, len(points))
		copy(compacted, points)
		return compacted
	}
	return points
}
