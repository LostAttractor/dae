package common

import (
	"math"
	"testing"
	"time"

	"github.com/daeuniverse/quic-go/congestion"
)

func TestBytesForIntervalDoesNotOverflow(t *testing.T) {
	for _, tc := range []struct {
		rate     congestion.ByteCount
		interval time.Duration
		want     congestion.ByteCount
	}{
		{1_000_000_000, 500 * time.Nanosecond, 500},
		{5_000_000_000, 5 * time.Second, 25_000_000_000},
		{math.MaxInt64, time.Nanosecond, math.MaxInt64 / 1_000_000_000},
		{math.MaxInt64, time.Second, math.MaxInt64},
		{math.MaxInt64, time.Duration(math.MaxInt64), math.MaxInt64},
		{1_000, -time.Second, 0},
	} {
		if got := bytesForInterval(tc.rate, tc.interval); got != tc.want {
			t.Errorf("rate %d over %v: got %d, want %d", tc.rate, tc.interval, got, tc.want)
		}
	}
}

func TestPacerRefillsWithoutWrapping(t *testing.T) {
	for _, rate := range []congestion.ByteCount{1_000_000, math.MaxInt64} {
		pacer := NewPacer(func() congestion.ByteCount { return rate })
		now := time.Unix(1_000, 0)
		full := pacer.Budget(now)
		pacer.SentPacket(now, full)
		previous := congestion.ByteCount(0)
		for _, elapsed := range []time.Duration{0, time.Nanosecond, time.Microsecond, time.Millisecond, time.Second, time.Hour} {
			budget := pacer.Budget(now.Add(elapsed))
			if budget < previous || budget > full {
				t.Fatalf("rate %d after %v: budget %d outside [%d, %d]", rate, elapsed, budget, previous, full)
			}
			previous = budget
		}
		if rate == 1_000_000 && pacer.Budget(now.Add(time.Millisecond)) != 1_000 {
			t.Fatal("ordinary pacing rate changed")
		}
	}
}
