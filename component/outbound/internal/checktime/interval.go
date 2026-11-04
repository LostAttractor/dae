// SPDX-License-Identifier: AGPL-3.0-only

// Package checktime supplies the scheduling bounds shared by health checks and
// automatic path discovery. Retry multipliers remain with each owning policy.
package checktime

import (
	"math"
	"math/rand/v2"
	"time"
)

// Bounds applies a twenty-percent spread without exceeding the configured cap
// or overflowing a duration. Intervals below five nanoseconds have no spread.
func Bounds(interval, maximum time.Duration) (low, high time.Duration) {
	maximum = max(maximum, 0)
	interval = min(max(interval, 0), maximum)
	spread := interval / 5
	low = interval - spread
	high = interval + min(spread, time.Duration(math.MaxInt64)-interval)
	return low, min(high, maximum)
}

func Jitter(interval, maximum time.Duration) time.Duration {
	low, high := Bounds(interval, maximum)
	if high <= low {
		return low
	}
	return low + time.Duration(rand.Int64N(int64(high-low+1)))
}

// Retry spaces attempts to clear a condition by a quarter of how long it has
// lasted, at least one second and at most maximum, with jitter. Its end is
// noticed within about 25% of its duration, while a lasting condition costs
// only logarithmically many attempts before reaching maximum.
func Retry(lasted, maximum time.Duration) time.Duration {
	return Jitter(min(max(lasted/4, time.Second), maximum), maximum)
}
