/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"time"

	"github.com/daeuniverse/dae/api"
)

// latencyWindow stores successful samples; failed probes do not affect latency.
// Its owner supplies synchronization and the group's smoothing factor.
type latencyWindow struct {
	samples       [10]time.Duration
	next, count   int
	movingAverage time.Duration
	alpha         float64
}

func (g *latencyWindow) record(latency time.Duration) {
	if g.count == 0 {
		g.movingAverage = latency
	} else {
		g.movingAverage = time.Duration(float64(g.movingAverage)*(1-g.alpha) + float64(latency)*g.alpha)
	}
	g.samples[g.next] = latency
	g.next = (g.next + 1) % len(g.samples)
	g.count = min(g.count+1, len(g.samples))
}

func (g *latencyWindow) snapshot() (lat api.LatencyStats, ok bool) {
	if g.count == 0 {
		return api.LatencyStats{}, false
	}
	lat.Last = g.samples[(g.next+len(g.samples)-1)%len(g.samples)]
	// Quotients and remainders avoid overflowing on large successful samples.
	var remainder time.Duration
	for _, sample := range g.samples[:g.count] {
		lat.Avg10 += sample / time.Duration(g.count)
		remainder += sample % time.Duration(g.count)
	}
	lat.Avg10 += remainder / time.Duration(g.count)
	lat.MovingAvg = g.movingAverage
	return lat, true
}

func (d *Dialer) latencyStats() (lat api.LatencyStats, ok bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.latencyStatsLocked()
}

func (d *Dialer) latencyStatsLocked() (api.LatencyStats, bool) {
	if d.group == nil {
		return api.LatencyStats{}, false
	}
	return d.group.latency.snapshot()
}

func (d *pathRuntime) recordLatencyLocked(latency time.Duration, success bool) {
	if !success {
		return
	}
	d.health.measuredAt = time.Now()
	d.health.lastLatency = latency
	for member := range d.members {
		if member.active && member.group != nil {
			member.group.latency.record(latency)
		}
	}
}
