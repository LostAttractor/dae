// SPDX-License-Identifier: AGPL-3.0-only

package checktime

import (
	"math"
	"testing"
	"time"
)

func TestJitterBounds(t *testing.T) {
	for _, test := range []struct{ interval, cap, low, high time.Duration }{
		{time.Nanosecond, time.Second, time.Nanosecond, time.Nanosecond},
		{10 * time.Second, time.Minute, 8 * time.Second, 12 * time.Second},
		{time.Hour, time.Hour, 48 * time.Minute, time.Hour},
		{2 * time.Hour, time.Hour, 48 * time.Minute, time.Hour},
		{math.MaxInt64, math.MaxInt64, math.MaxInt64 - math.MaxInt64/5, math.MaxInt64},
		{time.Second, 0, 0, 0},
	} {
		low, high := Bounds(test.interval, test.cap)
		if low != test.low || high != test.high {
			t.Fatalf("bounds for %v capped at %v: %v..%v", test.interval, test.cap, low, high)
		}
		if got := Jitter(test.interval, test.cap); got < low || got > high {
			t.Fatalf("jitter %v outside %v..%v", got, low, high)
		}
	}
}
