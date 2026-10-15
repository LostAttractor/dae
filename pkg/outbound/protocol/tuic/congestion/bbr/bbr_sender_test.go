package bbr

import (
	"fmt"
	"math"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/daeuniverse/quic-go/congestion"
)

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }

type testRTT struct {
	congestion.RTTStatsProvider
	rtt time.Duration
}

func (r testRTT) SmoothedRTT() time.Duration { return r.rtt }

func testSender() (*bbrSender, *testClock) {
	c := &testClock{now: time.Unix(1000, 0)}
	b := NewBBRv3Sender(c, 1200)
	b.random = rand.New(rand.NewPCG(1, 2))
	b.SetRTTStatsProvider(testRTT{rtt: 50 * time.Millisecond})
	return b, c
}

func TestBBRv3PacingControlsDeparture(t *testing.T) {
	b, c := testSender()
	b.fullBandwidthReached = true
	b.maxBwFilter[1] = 800_000 // 100 kB/s
	var upDelay, downDelay time.Duration
	for _, mode := range []bbrMode{bbrModeProbeBwUp, bbrModeProbeBwDown} {
		b.mode = mode
		b.updateControl(0)
		b.pacer = pacer{sender: b}
		for b.HasPacingBudget(c.now) {
			b.OnPacketSent(c.now, 0, 1, 1200, false)
		}
		deadline := b.TimeUntilSend(0)
		if !deadline.After(c.now) || !b.HasPacingBudget(deadline) {
			t.Fatalf("mode %d: inconsistent pacing deadline %v", mode, deadline)
		}
		if b.HasPacingBudget(deadline.Add(-time.Microsecond)) {
			t.Fatalf("mode %d: sends before the pacing deadline", mode)
		}
		if mode == bbrModeProbeBwUp {
			upDelay = deadline.Sub(c.now)
		} else {
			downDelay = deadline.Sub(c.now)
		}
	}
	if downDelay <= upDelay {
		t.Fatalf("Drain did not slow departures: UP %v, DOWN %v", upDelay, downDelay)
	}
	// Low bandwidth must not be overridden by the old 64 kB/s floor.
	b.maxBwFilter = [2]Bandwidth{8000, 0}
	b.updateControl(0)
	if b.PacingRate() >= 8000 {
		t.Fatal("DOWN failed to pace below the bottleneck rate")
	}
	if got := bytesFromBandwidthAndTimeDelta(Bandwidth(100_000_000_000), time.Second); got != 12_500_000_000 {
		t.Fatalf("high-bandwidth BDP overflow: %d", got)
	}
	if got := b.pacer.Budget(c.now.Add(24 * time.Hour)); got != b.pacer.maxBurstSize() {
		t.Fatalf("idle pacing budget = %d", got)
	}
}

func TestBBRv3TimerDrivenPacingRate(t *testing.T) {
	for _, rate := range []Bandwidth{1_000_000, 100_000_000, 1_000_000_000, 10_000_000_000} {
		t.Run(fmt.Sprint(rate), func(t *testing.T) {
			b, c := testSender()
			b.pacingRate = rate
			start := c.now
			var sent congestion.ByteCount
			for c.now.Before(start.Add(time.Second)) {
				for b.HasPacingBudget(c.now) {
					b.pacer.SentPacket(c.now, 1200)
					sent += 1200
				}
				next := b.TimeUntilSend(0)
				if !next.After(c.now) {
					t.Fatal("pacing deadline did not advance")
				}
				c.now = next
			}
			// Allow the initial quantum and sub-packet rounding, but require
			// timer-only departures to achieve the modeled rate within 2%.
			got := BandwidthFromDelta(sent, time.Second)
			if ratio := float64(got) / float64(rate); ratio < 0.98 || ratio > 1.02 {
				t.Fatalf("timer-driven rate = %d, model = %d", got, rate)
			}
			if quantum := b.pacer.sendQuantum(); quantum > 64*1024 {
				t.Fatalf("high rate increased send quantum: %d", quantum)
			}
		})
	}
}

func TestBBRv3DiscardedPacketDoesNotPinSampler(t *testing.T) {
	b, c := testSender()
	for pn := range congestion.PacketNumber(8) {
		b.OnPacketSent(c.now, congestion.ByteCount(pn)*1200, pn, 1200, true)
	}
	// A PTO retires the oldest packet while other packets remain in flight.
	b.OnPacketDiscarded(0, 8400)
	b.OnPacketDiscarded(0, 8400) // Duplicate and unknown notifications are harmless.
	b.OnPacketDiscarded(congestion.InvalidPacketNumber, 8400)
	if b.bytesInFlight != 8400 || b.sampler.TotalBytesAcked() != 0 || b.sampler.TotalBytesLost() != 0 || b.InRecovery() {
		t.Fatal("discard was counted as delivery or congestion loss")
	}
	for pn := congestion.PacketNumber(8); pn < 10_008; pn++ {
		c.now = c.now.Add(time.Millisecond)
		b.OnPacketSent(c.now, 8400, pn, 1200, true)
		b.OnCongestionEventEx(9600, c.now, []congestion.AckedPacketInfo{{PacketNumber: pn - 7, BytesAcked: 1200}}, nil)
	}
	queue := b.sampler.connectionStateMap
	if slots := len(queue.entries.ring); slots > defaultConnectionStateMapQueueSize {
		t.Fatalf("7 packets in flight pinned %d sampler slots", slots)
	}
	if queue.numberOfPresentEntries != 7 || b.sampler.TotalBytesLost() != 0 || b.sampler.TotalBytesAcked() != 10_000*1200 {
		t.Fatal("discarded packet affected subsequent sampling")
	}
}

func TestBBRv3LossOnlyAndMTUProbe(t *testing.T) {
	for _, mtuProbe := range []bool{false, true} {
		b, c := testSender()
		b.mode, b.fullBandwidthReached, b.bwProbeSamples = bbrModeProbeBwUp, true, true
		b.maxBwFilter[1] = 8_000_000
		b.congestionWindow = 100_000
		for i := range 10 {
			b.OnPacketSent(c.now, congestion.ByteCount(i)*1200, congestion.PacketNumber(i), 1200, true)
		}
		b.OnCongestionEventEx(12_000, c.now.Add(50*time.Millisecond), nil, []congestion.LostPacketInfo{{
			PacketNumber: 9, BytesLost: 1200, IsPathMTUProbe: mtuProbe,
		}})
		if b.bytesInFlight != 10_800 || b.roundCount != 0 {
			t.Fatalf("loss-only event changed round or flight incorrectly: %+v", b)
		}
		if mtuProbe {
			if b.InRecovery() || b.mode != bbrModeProbeBwUp || b.sampler.TotalBytesLost() != 0 {
				t.Fatal("MTU probe loss was treated as congestion")
			}
		} else if !b.InRecovery() || b.mode != bbrModeProbeBwDown || b.inflightLongterm == unlimitedInflight {
			t.Fatal("probing loss did not constrain inflight and enter DOWN")
		}
		b.OnCongestionEventEx(10_800, c.now, nil, nil) // empty callbacks are harmless
		if !mtuProbe {
			b.OnCongestionEventEx(10_800, c.now.Add(51*time.Millisecond),
				[]congestion.AckedPacketInfo{{PacketNumber: 8, BytesAcked: 1200}}, nil)
			if b.phase != acksProbeStopping {
				t.Fatal("ACK of pre-DOWN data prematurely ended probe feedback")
			}
		}
	}
}

func TestBBRv3DiscardBeforeInstallationPreservesApplicationSample(t *testing.T) {
	b, clock := testSender()
	// A 900-byte handshake packet predates controller installation. The first
	// application packet is sampled as 0 while that handshake remains in flight.
	b.OnPacketSent(clock.now, 900, 0, 1200, true)
	b.OnPacketDiscarded(congestion.InvalidPacketNumber, 1200)
	if b.bytesInFlight != 1200 || b.sampler.connectionStateMap.GetEntry(0) == nil {
		t.Fatal("old handshake discard changed the application sample or flight")
	}
	before := b.GetCongestionWindow()
	b.OnCongestionEventEx(1200, clock.now.Add(50*time.Millisecond), []congestion.AckedPacketInfo{{PacketNumber: 0, BytesAcked: 1200}}, nil)
	if b.sampler.TotalBytesAcked() != 1200 || b.GetCongestionWindow() <= before || b.bytesInFlight != 0 {
		t.Fatal("application ACK lost delivery accounting or STARTUP growth")
	}
}

func TestBBRv3SamplerRetainsReorderedPackets(t *testing.T) {
	b, c := testSender()
	for i := range 6 {
		b.OnPacketSent(c.now.Add(time.Duration(i)*time.Millisecond), congestion.ByteCount(i)*1200, congestion.PacketNumber(i), 1200, true)
	}
	b.OnCongestionEventEx(7200, c.now.Add(50*time.Millisecond), []congestion.AckedPacketInfo{{PacketNumber: 5, BytesAcked: 1200}}, nil)
	// The previous largest-ACK-minus-two heuristic discarded these samples.
	b.OnCongestionEventEx(6000, c.now.Add(51*time.Millisecond), []congestion.AckedPacketInfo{{PacketNumber: 0, BytesAcked: 1200}}, nil)
	if b.sampler.TotalBytesAcked() != 2400 {
		t.Fatal("reordered ACK lost its delivery sample")
	}
	lost := make([]congestion.LostPacketInfo, 0, 4)
	for i := range 4 {
		lost = append(lost, congestion.LostPacketInfo{PacketNumber: congestion.PacketNumber(i + 1), BytesLost: 1200})
	}
	b.OnCongestionEventEx(4800, c.now.Add(52*time.Millisecond), nil, lost)
	if !b.sampler.connectionStateMap.IsEmpty() {
		t.Fatal("acknowledged / lost packet samples leaked")
	}
	// Duplicate or pre-installation ACK/loss must not count bytes twice.
	b.OnCongestionEventEx(0, c.now.Add(time.Second), []congestion.AckedPacketInfo{{PacketNumber: 0, BytesAcked: 1200}}, lost)
	if b.sampler.TotalBytesAcked() != 2400 || b.sampler.TotalBytesLost() != 4800 {
		t.Fatal("unknown packet counted as delivered or lost")
	}
}

func TestBBRv3ProbeRttNeedsTimeAndDeliveredRound(t *testing.T) {
	b, c := testSender()
	b.mode, b.fullBandwidthReached = bbrModeProbeBwCruise, true
	b.maxBwFilter[1], b.congestionWindow = 8_000_000, 100_000
	c.now = c.now.Add(6 * time.Second)
	b.OnPacketSent(c.now, 0, 0, 1200, true)
	c.now = c.now.Add(60 * time.Millisecond)
	b.OnCongestionEventEx(1200, c.now, []congestion.AckedPacketInfo{{PacketNumber: 0, BytesAcked: 1200}}, nil)
	if b.mode != bbrModeProbeRtt || b.GetCongestionWindow() != 25_000 {
		t.Fatalf("expected half-BDP ProbeRTT window, got mode %d cwnd %d", b.mode, b.GetCongestionWindow())
	}
	c.now = c.now.Add(300 * time.Millisecond)
	b.OnCongestionEventEx(0, c.now, nil, []congestion.LostPacketInfo{{PacketNumber: 999, BytesLost: 1200}})
	if b.mode != bbrModeProbeRtt {
		t.Fatal("loss-only event completed an RTT probe")
	}
	// Keep a packet in flight so restarting from idle doesn't shortcut the probe.
	b.OnPacketSent(c.now, 1200, 1, 1200, true)
	c.now = c.now.Add(50 * time.Millisecond)
	b.OnCongestionEventEx(2400, c.now, []congestion.AckedPacketInfo{{PacketNumber: 1, BytesAcked: 1200}}, nil)
	if b.mode != bbrModeProbeBwCruise || b.GetCongestionWindow() <= 25_000 {
		t.Fatal("ProbeRTT did not restore the window after time and a delivered round")
	}
}

func TestBBRv3AppLimitedAndIdleRestart(t *testing.T) {
	b, c := testSender()
	b.mode, b.fullBandwidthReached = bbrModeProbeBwCruise, true
	b.maxBwFilter[1] = 8_000_000
	b.OnApplicationLimited()
	c.now = c.now.Add(6 * time.Second)
	b.OnPacketSent(c.now, 0, 0, 1200, true)
	if !b.idleRestart {
		t.Fatal("app-limited idle restart was not recognized")
	}
	c.now = c.now.Add(50 * time.Millisecond)
	b.OnCongestionEventEx(1200, c.now, []congestion.AckedPacketInfo{{PacketNumber: 0, BytesAcked: 1200}}, nil)
	if b.mode == bbrModeProbeRtt || b.maxBandwidth() != 8_000_000 {
		t.Fatal("idle traffic forced ProbeRTT or erased a valid bandwidth estimate")
	}
	if b.fullBandwidthCount != 0 {
		t.Fatal("app-limited sample advanced plateau detection")
	}
}

func TestBBRv3ECNAndDatagramSize(t *testing.T) {
	b, _ := testSender()
	b.mode, b.fullBandwidthReached = bbrModeProbeBwCruise, true
	b.maxBwFilter[1], b.congestionWindow, b.lastSentPacket = 8_000_000, 100_000, 20
	b.OnCongestionEvent(10, 0, 100_000)
	if b.GetCongestionWindow() > 70_000 || b.PacingRate() >= 8_000_000 {
		t.Fatal("ECN did not reduce the window and pacing rate")
	}
	window := b.GetCongestionWindow()
	b.OnCongestionEvent(11, 0, window)
	if b.GetCongestionWindow() != window || b.sampler.TotalBytesLost() != 0 {
		t.Fatal("ECN reduced twice in one flight or created fictitious packet loss")
	}
	b.congestionWindow = b.minimumWindow()
	b.SetMaxDatagramSize(1500)
	if b.GetCongestionWindow() != 6000 || b.initialCongestionWindow != 32*1500 {
		t.Fatal("MTU change did not update packet-based window limits")
	}
}

func TestBBRv3StartupLossWhileApplicationLimited(t *testing.T) {
	for _, burst := range []bool{false, true} {
		b, c := testSender()
		for round := range 2 {
			b.OnApplicationLimited()
			var acked []congestion.AckedPacketInfo
			var lost []congestion.LostPacketInfo
			for i := range 32 {
				number := congestion.PacketNumber(round*32 + i)
				b.OnPacketSent(c.now, congestion.ByteCount(i)*1200, number, 1200, true)
				isLost := i < 12 && i%2 == 0
				if burst {
					isLost = i < 6
				}
				if isLost {
					lost = append(lost, congestion.LostPacketInfo{PacketNumber: number, BytesLost: 1200})
				} else {
					acked = append(acked, congestion.AckedPacketInfo{PacketNumber: number, BytesAcked: 1200})
				}
			}
			c.now = c.now.Add(50 * time.Millisecond)
			b.OnCongestionEventEx(32*1200, c.now, acked, lost)
			if round == 0 && !b.InSlowStart() {
				t.Fatal("Startup exited before a full recovery round")
			}
		}
		if burst {
			if !b.InSlowStart() {
				t.Fatal("one contiguous burst counted as six discontiguous loss events")
			}
		} else if b.InSlowStart() || !b.fullBandwidthReached || b.inflightLongterm == unlimitedInflight {
			t.Fatal("application-limited Startup ignored sustained high loss")
		}
	}
}

func TestBBRv3ShortTermBoundsOncePerLossRound(t *testing.T) {
	b, c := testSender()
	b.startProbeDown(c.now)
	b.mode, b.fullBandwidthReached = bbrModeProbeBwCruise, true
	b.maxBwFilter[1], b.congestionWindow = 8_000_000, 100_000
	for i := range 32 {
		b.OnPacketSent(c.now, congestion.ByteCount(i)*1200, congestion.PacketNumber(i), 1200, true)
	}
	c.now = c.now.Add(50 * time.Millisecond)
	b.OnCongestionEventEx(38_400, c.now, []congestion.AckedPacketInfo{{PacketNumber: 31, BytesAcked: 1200}},
		[]congestion.LostPacketInfo{{PacketNumber: 0, BytesLost: 1200}})
	if b.bwShortterm != 5_600_000 || b.inflightShortterm != 70_000 {
		t.Fatalf("loss did not bound cruising rate/volume: %d / %d", b.bwShortterm, b.inflightShortterm)
	}
	c.now = c.now.Add(time.Millisecond)
	b.OnCongestionEventEx(36_000, c.now, []congestion.AckedPacketInfo{{PacketNumber: 30, BytesAcked: 1200}},
		[]congestion.LostPacketInfo{{PacketNumber: 1, BytesLost: 1200}})
	if b.bwShortterm != 5_600_000 || b.inflightShortterm != 70_000 {
		t.Fatal("bounds decreased twice in the same delivered round")
	}
	// A fresh ACK carries the next loss round's delivery sample.
	b.OnPacketSent(c.now, 33_600, 32, 1200, true)
	c.now = c.now.Add(50 * time.Millisecond)
	b.OnCongestionEventEx(34_800, c.now, []congestion.AckedPacketInfo{{PacketNumber: 32, BytesAcked: 1200}}, nil)
	if b.bwShortterm >= 5_600_000 || b.inflightShortterm >= 70_000 {
		t.Fatal("new loss round did not tighten the short-term model")
	}
}

// A deterministic paced bottleneck. Unlike state-only tests, this drives the
// public send / ACK / loss callbacks with a finite queue and delayed feedback.
type linkPacket struct {
	number congestion.PacketNumber
	due    time.Time
	lost   bool
}

func TestBBRv3Bottleneck(t *testing.T) {
	// Include the seeds that exposed the old test's phase-dependent deadline.
	for _, seed := range []uint64{1, 21, 23, 27, 42, 49, 56} {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			testBBRv3Bottleneck(t, seed)
		})
	}
}

func testBBRv3Bottleneck(t *testing.T, seed uint64) {
	t.Helper()
	for _, randomLoss := range []bool{false, true} {
		name := "no_loss"
		if randomLoss {
			name = "one_percent_loss"
		}
		t.Run(name, func(t *testing.T) {
			b, c := testSender()
			b.random = rand.New(rand.NewPCG(seed, 2))
			start := c.now
			var flight congestion.ByteCount
			var number congestion.PacketNumber
			var packets []linkPacket
			var queueEnd time.Time
			var delivered, lateDelivered congestion.ByteCount
			seen := make(map[bbrMode]bool)
			// Link bandwidth doubles at 8s, then drops to half the original at
			// 16s. Allow the min-RTT filter (10s) and two bandwidth probe
			// cycles (up to 3s each) to settle after the last change.
			// The byte rate is 1200 bytes per serialization interval.
			for tick := range 32_000 {
				c.now = start.Add(time.Duration(tick) * time.Millisecond)
				serialization := time.Millisecond
				if tick >= 8000 {
					serialization = 500 * time.Microsecond
				}
				if tick >= 16000 {
					serialization = 2 * time.Millisecond
				}
				prior := flight
				var acked []congestion.AckedPacketInfo
				var lost []congestion.LostPacketInfo
				consumed := 0
				for _, p := range packets {
					if p.due.After(c.now) {
						break
					}
					consumed++
					flight -= 1200
					if p.lost {
						lost = append(lost, congestion.LostPacketInfo{PacketNumber: p.number, BytesLost: 1200})
					} else {
						acked = append(acked, congestion.AckedPacketInfo{PacketNumber: p.number, BytesAcked: 1200})
						delivered += 1200
						if tick >= 28000 {
							lateDelivered += 1200
						}
					}
				}
				packets = packets[consumed:]
				b.OnCongestionEventEx(prior, c.now, acked, lost)
				for b.CanSend(flight) && b.HasPacingBudget(c.now) {
					b.OnPacketSent(c.now, flight, number, 1200, true)
					flight += 1200
					if queueEnd.Before(c.now) {
						queueEnd = c.now
					}
					drop := queueEnd.Sub(c.now) > 50*time.Millisecond || (randomLoss && number%100 == 73)
					if !drop {
						queueEnd = queueEnd.Add(serialization)
					}
					packets = append(packets, linkPacket{number: number, due: queueEnd.Add(50 * time.Millisecond), lost: drop})
					number++
				}
				seen[b.mode] = true
				if b.GetCongestionWindow() < 4800 || b.GetCongestionWindow() > b.maxCongestionWindow || b.PacingRate() == 0 {
					t.Fatalf("invalid controls at %v: cwnd %d pacing %d", c.now, b.GetCongestionWindow(), b.PacingRate())
				}
			}
			for _, mode := range []bbrMode{bbrModeStartup, bbrModeDrain, bbrModeProbeBwCruise, bbrModeProbeBwRefill, bbrModeProbeBwUp, bbrModeProbeRtt} {
				if !seen[mode] {
					t.Errorf("never visited mode %d (seen %v)", mode, seen)
				}
			}
			if delivered < 18_000_000 || lateDelivered < 1_500_000 {
				t.Errorf("insufficient delivery: total %d final four seconds %d", delivered, lateDelivered)
			}
			// The max filter estimates path capacity. Short-term loss bounds
			// can temporarily reduce the pacing estimate below that capacity.
			if bw := b.maxBandwidth(); bw > 7_000_000 || bw < 3_000_000 {
				t.Errorf("failed to adapt to 4.8 Mbps bottleneck: %d", bw)
			}
			if b.sampler.connectionStateMap.NumberOfPresentEntries() != len(packets) {
				t.Fatal("sampler retained obsolete packets or lost in-flight samples")
			}
		})
	}
}

func TestBandwidthArithmetic(t *testing.T) {
	if BandwidthFromDelta(1200, 0) != 0 || BandwidthFromDelta(1200, -time.Second) != 0 {
		t.Fatal("invalid sampling interval produced a bandwidth")
	}
	if bytesFromBandwidthAndTimeDelta(infBandwidth, time.Duration(math.MaxInt64)) <= 0 {
		t.Fatal("large bandwidth-duration product overflowed")
	}
}
