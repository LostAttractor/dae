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

func TestCongestionSamplesExcludeUntrackedPacketsAndMTUProbeLoss(t *testing.T) {
	sender, err := NewBrutalSender(1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_000, 0)
	acked := make([]congestion.AckedPacketInfo, 49)
	for i := range acked {
		acked[i] = congestion.AckedPacketInfo{PacketNumber: congestion.PacketNumber(i), BytesAcked: 1200}
	}
	acked = append(acked, congestion.AckedPacketInfo{PacketNumber: congestion.InvalidPacketNumber, BytesAcked: 1200})
	sender.OnCongestionEventEx(0, now, acked, []congestion.LostPacketInfo{
		{PacketNumber: 49, BytesLost: 1400, IsPathMTUProbe: true},
		{PacketNumber: congestion.InvalidPacketNumber, BytesLost: 1200},
	})
	if got := sender.pktInfoSlots[now.Unix()%pktInfoSlotCount]; got.AckCount != 49 || got.LossCount != 0 || sender.ackRate != 1 {
		t.Fatalf("non-congestion samples counted: slot=%+v ackRate=%v", got, sender.ackRate)
	}
	// Actual loss must still contribute, including another event in this slot.
	sender.OnCongestionEventEx(1200, now, nil, []congestion.LostPacketInfo{{PacketNumber: 50, BytesLost: 1200}})
	if sender.ackRate != 0.98 {
		t.Fatalf("real loss ignored: ackRate=%v", sender.ackRate)
	}
	sender.OnCongestionEventEx(0, now.Add(pktInfoSlotCount*time.Second), nil, nil)
	if sender.ackRate != 1 {
		t.Fatal("expired loss retained")
	}
}
