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

func TestRetryFollowsHowLongTheConditionLasted(t *testing.T) {
	for _, test := range []struct{ lasted, maximum, want time.Duration }{
		{0, time.Hour, time.Second},
		{2 * time.Second, time.Hour, time.Second},
		{time.Minute, time.Hour, 15 * time.Second},
		{20 * time.Minute, time.Hour, 5 * time.Minute},
		{10 * time.Hour, time.Hour, time.Hour},
		{time.Minute, 25 * time.Millisecond, 25 * time.Millisecond},
	} {
		low, high := Bounds(test.want, test.maximum)
		if got := Retry(test.lasted, test.maximum); got < low || got > high {
			t.Fatalf("retry after %v capped at %v = %v, want %v..%v", test.lasted, test.maximum, got, low, high)
		}
	}
}
