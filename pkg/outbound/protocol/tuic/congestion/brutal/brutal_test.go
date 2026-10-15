package brutal

import (
	"math"
	"testing"
	"time"

	"github.com/daeuniverse/quic-go/congestion"
)

func TestBandwidthDoesNotBecomeNegative(t *testing.T) {
	for _, bandwidth := range []uint64{0, math.MaxInt64 + 1, math.MaxUint64} {
		if sender, err := NewBrutalSender(bandwidth); err == nil || sender != nil {
			t.Fatalf("accepted invalid bandwidth %d: %v", bandwidth, err)
		}
	}
}

type testRTT struct {
	congestion.RTTStatsProvider
	rtt time.Duration
}

func (r testRTT) SmoothedRTT() time.Duration { return r.rtt }

func TestLargeBandwidthKeepsPositiveBudgets(t *testing.T) {
	for _, bandwidth := range []uint64{1, 125_000_000, math.MaxInt64} {
		sender, err := NewBrutalSender(bandwidth)
		if err != nil {
			t.Fatal(err)
		}
		sender.ackRate = minAckRate
		sender.SetRTTStatsProvider(testRTT{rtt: time.Second})
		if window := sender.GetCongestionWindow(); window < sender.maxDatagramSize {
			t.Fatalf("invalid congestion window %d for bandwidth %d", window, bandwidth)
		}
		now := time.Unix(1_000, 0)
		sender.OnPacketSent(now, 0, 1, sender.maxDatagramSize, true)
		if !sender.HasPacingBudget(now.Add(time.Hour)) {
			t.Fatalf("idle sender lost pacing budget for bandwidth %d", bandwidth)
		}
	}
}
