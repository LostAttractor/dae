package bbr

import (
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"time"

	"github.com/daeuniverse/quic-go/congestion"
)

// BBRv3 follows draft-ietf-ccwg-bbr-06. See README.md for the QUIC
// integration, reference, and the transport's feedback limitations.
const (
	invalidPacketNumber            = -1
	initialCongestionWindowPackets = 32
	startupPacingGain              = 2.77
	pacingMargin                   = 0.99
	lossThreshold                  = 0.02
	beta                           = 0.7
	headroom                       = 0.15
	startupLossEvents              = 6
	minRttExpiry                   = 10 * time.Second
	probeRttInterval               = 5 * time.Second
	probeRttTime                   = 200 * time.Millisecond
	unlimitedInflight              = congestion.ByteCount(math.MaxInt64)
)

type bbrMode uint8

const (
	bbrModeStartup bbrMode = iota
	bbrModeDrain
	bbrModeProbeBwDown
	bbrModeProbeBwCruise
	bbrModeProbeBwRefill
	bbrModeProbeBwUp
	bbrModeProbeRtt
)

type ackPhase uint8

const (
	acksInit ackPhase = iota
	acksRefilling
	acksProbeStarting
	acksProbeFeedback
	acksProbeStopping
)

type bbrSender struct {
	rttStats congestion.RTTStatsProvider
	clock    Clock
	random   *rand.Rand
	pacer    pacer
	sampler  *bandwidthSampler
	mode     bbrMode

	maxDatagramSize         congestion.ByteCount
	initialCongestionWindow congestion.ByteCount
	maxCongestionWindow     congestion.ByteCount
	congestionWindow        congestion.ByteCount
	priorCongestionWindow   congestion.ByteCount
	bytesInFlight           congestion.ByteCount
	lastSentPacket          congestion.PacketNumber
	cwndLimited             bool
	idleRestart             bool

	roundCount         roundTripCount
	nextRoundDelivered congestion.ByteCount
	roundEndPacket     congestion.PacketNumber
	drainStartRound    roundTripCount

	// Exactly two bandwidth-probe cycles, rather than BBRv1's ten RTTs.
	maxBwFilter        [2]Bandwidth
	bwShortterm        Bandwidth
	bwLatest           Bandwidth
	inflightLatest     congestion.ByteCount
	inflightLongterm   congestion.ByteCount
	inflightShortterm  congestion.ByteCount
	lossRoundDelivered congestion.ByteCount
	lossInRound        bool
	lossEventsInRound  int
	lastLostPacket     congestion.PacketNumber

	fullBandwidthReached bool
	fullBandwidthNow     bool
	fullBandwidth        Bandwidth
	fullBandwidthCount   int

	phase                   ackPhase
	bwProbeSamples          bool
	cycleStamp              time.Time
	bwProbeWait             time.Duration
	roundsSinceProbe        roundTripCount
	probeUpRounds           uint
	probeUpAcked            congestion.ByteCount
	probeUpAckedPerIncrease congestion.ByteCount
	prevProbeTooHigh        bool
	prevProbePrecautionary  bool

	minRtt            time.Duration
	minRttStamp       time.Time
	probeRttMinDelay  time.Duration
	probeRttMinStamp  time.Time
	probeRttDoneStamp time.Time
	probeRttRoundDone bool

	extraAckedStart     time.Time
	extraAckedDelivered congestion.ByteCount
	extraAcked          *WindowedFilter[congestion.ByteCount, roundTripCount]
	pacingRate          Bandwidth
	recovery            bool
	recoveryEnd         congestion.PacketNumber
	recoveryStartPacket congestion.PacketNumber
	ecnEnd              congestion.PacketNumber
}

var (
	_ congestion.CongestionControl                   = (*bbrSender)(nil)
	_ congestion.ApplicationLimitedCongestionControl = (*bbrSender)(nil)
	_ congestion.PacketDiscardedCongestionControl    = (*bbrSender)(nil)
)

// NewBBRv3Sender creates a paced BBR version 3 congestion controller.
func NewBBRv3Sender(clock Clock, initialMaxDatagramSize congestion.ByteCount) *bbrSender {
	return newBbrSender(clock, initialMaxDatagramSize,
		initialCongestionWindowPackets*initialMaxDatagramSize,
		congestion.MaxCongestionWindowPackets*initialMaxDatagramSize)
}

// NewBbrSender is retained for callers using the original BBR constructor.
// It now constructs BBRv3.
func NewBbrSender(clock Clock, initialMaxDatagramSize congestion.ByteCount) *bbrSender {
	return NewBBRv3Sender(clock, initialMaxDatagramSize)
}

func newBbrSender(clock Clock, size, initialWindow, maxWindow congestion.ByteCount) *bbrSender {
	now := clock.Now()
	b := &bbrSender{
		clock: clock, random: rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())),
		sampler:         newBandwidthSampler(10),
		maxDatagramSize: size, initialCongestionWindow: initialWindow,
		maxCongestionWindow: maxWindow, congestionWindow: initialWindow,
		lastSentPacket: invalidPacketNumber, lastLostPacket: invalidPacketNumber,
		roundEndPacket: invalidPacketNumber,
		recoveryEnd:    invalidPacketNumber, ecnEnd: invalidPacketNumber,
		bwShortterm: infBandwidth, inflightShortterm: unlimitedInflight,
		inflightLongterm: unlimitedInflight, probeUpAckedPerIncrease: unlimitedInflight,
		minRtt: infRTT, minRttStamp: now,
		probeRttMinDelay: infRTT, probeRttMinStamp: now,
		extraAckedStart: now,
		extraAcked:      NewWindowedFilter(roundTripCount(1), MaxFilter[congestion.ByteCount]),
	}
	b.pacer.sender = b
	return b
}

func (b *bbrSender) SetRTTStatsProvider(provider congestion.RTTStatsProvider) {
	b.rttStats = provider
	if rtt := provider.SmoothedRTT(); rtt > 0 {
		b.minRtt = rtt
		b.pacingRate = Bandwidth(startupPacingGain * float64(BandwidthFromDelta(b.initialCongestionWindow, rtt)))
	}
}

func (b *bbrSender) TimeUntilSend(congestion.ByteCount) time.Time { return b.pacer.TimeUntilSend() }
func (b *bbrSender) HasPacingBudget(now time.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *bbrSender) OnPacketSent(now time.Time, inFlight congestion.ByteCount, number congestion.PacketNumber, size congestion.ByteCount, retransmittable bool) {
	if retransmittable {
		if inFlight == 0 && b.sampler.IsAppLimited() {
			b.idleRestart = true
			b.extraAckedStart, b.extraAckedDelivered = now, 0
			if b.isProbeBw() {
				b.setPacingRate(1)
			} else if b.mode == bbrModeProbeRtt {
				b.checkProbeRttDone(now)
			}
		}
		b.lastSentPacket = number
		b.bytesInFlight = inFlight + size
		b.cwndLimited = b.cwndLimited || b.bytesInFlight >= b.congestionWindow
	}
	b.pacer.SentPacket(now, size)
	b.sampler.OnPacketSent(now, number, size, inFlight, retransmittable)
}

// OnApplicationLimited is called only when QUIC has a transmission opportunity
// but no data to pack. Pacing and congestion-window limits are not app limits.
func (b *bbrSender) OnApplicationLimited() { b.sampler.OnAppLimited() }

func (b *bbrSender) OnPacketDiscarded(number congestion.PacketNumber, bytesInFlight congestion.ByteCount) {
	b.sampler.OnPacketNeutered(number)
	b.bytesInFlight = bytesInFlight
}

func (b *bbrSender) CanSend(inFlight congestion.ByteCount) bool {
	return inFlight < b.congestionWindow
}
func (b *bbrSender) MaybeExitSlowStart() {}
func (b *bbrSender) OnPacketAcked(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount, time.Time) {
	// ACKs and losses are processed together by OnCongestionEventEx.
}

func (b *bbrSender) OnCongestionEvent(number congestion.PacketNumber, lostBytes, priorInFlight congestion.ByteCount) {
	// quic-go reports validated ECN-CE with lostBytes == 0. Apply a
	// conventional congestion response once per flight, without inventing loss
	// samples or double-counting the packet losses delivered in the batch.
	if lostBytes != 0 || number <= b.ecnEnd {
		return
	}
	b.ecnEnd = b.lastSentPacket
	b.bwShortterm = Bandwidth(beta * float64(b.bandwidthEstimate()))
	b.inflightShortterm = max(b.minimumWindow(), congestion.ByteCount(beta*float64(priorInFlight)))
	b.fullBandwidthReached = true
	if b.mode == bbrModeStartup {
		b.enterDrain()
	} else if b.mode == bbrModeProbeBwUp {
		b.startProbeDown(b.clock.Now())
	}
	b.updateControl(0)
}

func (b *bbrSender) OnRetransmissionTimeout(retransmitted bool) {
	// A QUIC PTO is not an RTO; the transport must not call this for PTO probes.
	if retransmitted {
		b.saveCongestionWindow()
		if !b.recovery {
			b.recoveryStartPacket = b.lastSentPacket
		}
		b.recovery, b.recoveryEnd = true, b.lastSentPacket
		b.congestionWindow = b.minimumWindow()
	}
}

func (b *bbrSender) SetMaxDatagramSize(size congestion.ByteCount) {
	if size < b.maxDatagramSize {
		panic(fmt.Sprintf("congestion BUG: decreased max datagram size from %d to %d", b.maxDatagramSize, size))
	}
	// Model estimates are bytes, not packets. Only packet-based limits scale.
	b.initialCongestionWindow = b.initialCongestionWindow / b.maxDatagramSize * size
	b.maxCongestionWindow = b.maxCongestionWindow / b.maxDatagramSize * size
	b.maxDatagramSize = size
	b.congestionWindow = max(b.congestionWindow, b.minimumWindow())
}

func (b *bbrSender) InSlowStart() bool                         { return b.mode == bbrModeStartup }
func (b *bbrSender) InRecovery() bool                          { return b.recovery }
func (b *bbrSender) GetCongestionWindow() congestion.ByteCount { return b.congestionWindow }

func (b *bbrSender) OnCongestionEventEx(priorInFlight congestion.ByteCount, now time.Time, acked []congestion.AckedPacketInfo, lost []congestion.LostPacketInfo) {
	if len(acked) == 0 && len(lost) == 0 {
		return
	}
	b.bytesInFlight = priorInFlight
	for _, p := range acked {
		b.bytesInFlight -= p.BytesAcked
	}
	hasCongestionLoss := false
	for _, p := range lost {
		b.bytesInFlight -= p.BytesLost
		hasCongestionLoss = hasCongestionLoss || (!p.IsPathMTUProbe && b.sampler.connectionStateMap.GetEntry(p.PacketNumber) != nil)
	}
	b.bytesInFlight = max(0, b.bytesInFlight)
	if hasCongestionLoss {
		if !b.recovery {
			b.saveCongestionWindow()
			b.recoveryStartPacket = b.lastSentPacket
		}
		b.recovery, b.recoveryEnd = true, b.lastSentPacket
	}
	b.handleLostPackets(now, lost)
	ackedBefore := b.sampler.TotalBytesAcked()
	sample := b.sampler.OnCongestionEvent(now, acked, lost, b.maxBandwidth(), b.bwShortterm, b.roundCount)
	bytesAcked := b.sampler.TotalBytesAcked() - ackedBefore
	state := sample.lastAckedPacketSendState
	if !state.isValid || bytesAcked == 0 {
		b.updateControl(0)
		return // loss-only events must not advance rounds or complete ProbeRTT
	}
	// In a loss-only callback, StartRound can run without C.delivered changing.
	// The packet sentinel prevents an ACK of already-outstanding data from
	// immediately completing the phase that callback just started.
	roundStart := state.totalBytesAcked >= b.nextRoundDelivered && acked[len(acked)-1].PacketNumber > b.roundEndPacket
	if roundStart {
		b.startRound()
		b.roundCount++
		b.roundsSinceProbe++
	}
	// Acknowledging data sent after recovery began proves a full delivered
	// round has elapsed. The ACK that first detects loss cannot satisfy this.
	recoveryRoundPassed := b.recovery && acked[len(acked)-1].PacketNumber > b.recoveryStartPacket
	if b.recovery && acked[len(acked)-1].PacketNumber > b.recoveryEnd {
		b.recovery = false
		b.congestionWindow = max(b.congestionWindow, b.priorCongestionWindow)
	}
	b.bwLatest = max(b.bwLatest, sample.sampleMaxBandwidth)
	b.inflightLatest = max(b.inflightLatest, sample.sampleMaxInflight)
	lossRoundStart := state.totalBytesAcked >= b.lossRoundDelivered
	if lossRoundStart {
		b.lossRoundDelivered = b.sampler.TotalBytesAcked()
	}
	if sample.sampleMaxBandwidth > 0 && (!sample.sampleIsAppLimited || sample.sampleMaxBandwidth >= b.maxBandwidth()) {
		b.maxBwFilter[1] = max(b.maxBwFilter[1], sample.sampleMaxBandwidth)
	}
	if lossRoundStart {
		if b.mode == bbrModeStartup && recoveryRoundPassed &&
			b.lossEventsInRound >= startupLossEvents && b.inflightTooHigh(state) {
			b.fullBandwidthReached = true
			b.inflightLongterm = max(b.bdp(1), b.inflightLatest)
		}
		if !b.isProbingBandwidth() && b.lossInRound {
			if b.bwShortterm == infBandwidth {
				b.bwShortterm = b.maxBandwidth()
			}
			if b.inflightShortterm == unlimitedInflight {
				b.inflightShortterm = b.congestionWindow
			}
			b.bwShortterm = max(b.bwLatest, Bandwidth(beta*float64(b.bwShortterm)))
			b.inflightShortterm = max(b.inflightLatest, congestion.ByteCount(beta*float64(b.inflightShortterm)))
		}
		b.lossInRound, b.lossEventsInRound = false, 0
	}
	b.updateAckAggregation(now, bytesAcked)
	b.checkFullBandwidth(sample, roundStart)
	if b.mode == bbrModeStartup && b.fullBandwidthReached {
		b.enterDrain()
	}
	if b.mode == bbrModeDrain && (b.bytesInFlight <= b.inflight(1) || b.roundCount > b.drainStartRound+3) {
		b.startProbeDown(now)
		// A round started above cannot also finish the phase just entered.
		roundStart = false
	}
	b.updateProbeBw(now, sample, bytesAcked, roundStart)
	b.updateMinRtt(now, sample.sampleRtt, roundStart)
	if lossRoundStart {
		b.bwLatest, b.inflightLatest = sample.sampleMaxBandwidth, sample.sampleMaxInflight
	}
	b.idleRestart = false
	b.updateControl(bytesAcked)
	if roundStart {
		b.cwndLimited = false
	}
}

func (b *bbrSender) handleLostPackets(now time.Time, lost []congestion.LostPacketInfo) {
	totalLost := b.sampler.TotalBytesLost()
	for _, p := range lost {
		if p.IsPathMTUProbe {
			continue
		}
		packet := b.sampler.connectionStateMap.GetEntry(p.PacketNumber)
		if packet == nil {
			continue // packets sent before this controller was installed
		}
		totalLost += p.BytesLost
		if !b.lossInRound {
			b.lossRoundDelivered = b.sampler.TotalBytesAcked()
		}
		b.lossInRound = true
		if b.lossEventsInRound == 0 || p.PacketNumber != b.lastLostPacket+1 {
			b.lossEventsInRound++
		}
		b.lastLostPacket = p.PacketNumber
		state := packet.sendTimeState
		lostSinceSent := totalLost - state.totalBytesLost
		if !b.bwProbeSamples || float64(lostSinceSent) <= lossThreshold*float64(state.bytesInFlight) {
			continue
		}
		// Interpolate the point in this datagram/burst at which loss crossed
		// the threshold, using its own send state rather than a later ACK.
		previousInflight := state.bytesInFlight - packet.size
		previousLost := lostSinceSent - packet.size
		prefix := (lossThreshold*float64(previousInflight) - float64(previousLost)) / (1 - lossThreshold)
		inflightAtLoss := previousInflight + congestion.ByteCount(max(0, prefix))
		b.prevProbeTooHigh, b.bwProbeSamples = true, false
		if !state.isAppLimited {
			b.inflightLongterm = max(inflightAtLoss, congestion.ByteCount(beta*float64(b.targetInflight())))
		}
		if b.mode == bbrModeProbeBwUp {
			b.startProbeDown(now)
		}
	}
}

func (b *bbrSender) inflightTooHigh(state sendTimeState) bool {
	return state.isValid && float64(b.sampler.TotalBytesLost()-state.totalBytesLost) > lossThreshold*float64(state.bytesInFlight)
}

func (b *bbrSender) checkFullBandwidth(sample congestionEventSample, roundStart bool) {
	if b.fullBandwidthNow || !roundStart || sample.sampleIsAppLimited || sample.sampleMaxBandwidth == 0 {
		return
	}
	if float64(sample.sampleMaxBandwidth) >= 1.25*float64(b.fullBandwidth) {
		b.resetFullBandwidth(sample.sampleMaxBandwidth)
		return
	}
	b.fullBandwidthCount++
	if b.fullBandwidthCount >= 3 {
		b.fullBandwidthNow, b.fullBandwidthReached = true, true
	}
}

func (b *bbrSender) resetFullBandwidth(bw Bandwidth) {
	b.fullBandwidth, b.fullBandwidthCount, b.fullBandwidthNow = bw, 0, false
}

func (b *bbrSender) startRound() {
	b.nextRoundDelivered = b.sampler.TotalBytesAcked()
	b.roundEndPacket = b.lastSentPacket
}
func (b *bbrSender) enterDrain() {
	b.mode, b.drainStartRound = bbrModeDrain, b.roundCount
}
func (b *bbrSender) resetShortTermModel() {
	b.bwShortterm, b.inflightShortterm = infBandwidth, unlimitedInflight
}
func (b *bbrSender) startProbeDown(now time.Time) {
	b.mode, b.phase = bbrModeProbeBwDown, acksProbeStopping
	b.lossInRound, b.lossEventsInRound = false, 0
	b.bwLatest, b.inflightLatest = 0, 0
	b.probeUpAckedPerIncrease = unlimitedInflight
	b.roundsSinceProbe = roundTripCount(b.random.IntN(2))
	b.bwProbeWait = 2*time.Second + time.Duration(b.random.Int64N(int64(time.Second)))
	b.cycleStamp = now
	b.startRound()
}
func (b *bbrSender) startProbeRefill() {
	b.resetShortTermModel()
	b.mode, b.phase = bbrModeProbeBwRefill, acksRefilling
	b.probeUpRounds, b.probeUpAcked, b.prevProbePrecautionary = 0, 0, false
	b.startRound()
}
func (b *bbrSender) startProbeUp(bw Bandwidth) {
	b.mode, b.phase, b.bwProbeSamples = bbrModeProbeBwUp, acksProbeStarting, true
	b.startRound()
	b.resetFullBandwidth(bw)
	b.raiseInflightSlope()
}
func (b *bbrSender) raiseInflightSlope() {
	b.probeUpAckedPerIncrease = max(b.congestionWindow/(1<<b.probeUpRounds), b.maxDatagramSize)
	b.probeUpRounds = min(b.probeUpRounds+1, 30)
}

func (b *bbrSender) updateProbeBw(now time.Time, sample congestionEventSample, bytesAcked congestion.ByteCount, roundStart bool) {
	if !b.fullBandwidthReached {
		return
	}
	if b.phase == acksProbeStarting && roundStart {
		b.phase = acksProbeFeedback
	} else if b.phase == acksProbeStopping && roundStart {
		b.phase, b.bwProbeSamples = acksInit, false
		if b.isProbeBw() && !sample.sampleIsAppLimited {
			b.maxBwFilter[0], b.maxBwFilter[1] = b.maxBwFilter[1], 0
		}
		if b.isProbeBw() && b.prevProbePrecautionary && !b.prevProbeTooHigh {
			b.startProbeRefill()
			return
		}
	}
	state := sample.lastAckedPacketSendState
	if !b.inflightTooHigh(state) && b.inflightLongterm != unlimitedInflight {
		b.inflightLongterm = max(b.inflightLongterm, state.bytesInFlight)
		if b.mode == bbrModeProbeBwUp && b.cwndLimited && b.congestionWindow >= b.inflightLongterm {
			b.probeUpAcked += bytesAcked
			delta := b.probeUpAcked / b.probeUpAckedPerIncrease
			b.probeUpAcked -= delta * b.probeUpAckedPerIncrease
			b.inflightLongterm += delta * b.maxDatagramSize
			if roundStart {
				b.raiseInflightSlope()
			}
		}
	}
	switch b.mode {
	case bbrModeProbeBwDown, bbrModeProbeBwCruise:
		// Reno coexistence counts packets, while all model volumes are bytes.
		renoRounds := roundTripCount(max(1, min(b.targetInflight()/b.maxDatagramSize, 63)))
		if now.Sub(b.cycleStamp) > b.bwProbeWait || b.roundsSinceProbe >= renoRounds {
			b.startProbeRefill()
		} else if b.mode == bbrModeProbeBwDown && b.bytesInFlight <= min(b.inflightWithHeadroom(), b.inflight(1)) {
			b.mode = bbrModeProbeBwCruise
		}
	case bbrModeProbeBwRefill:
		if roundStart {
			b.startProbeUp(sample.sampleMaxBandwidth)
		}
	case bbrModeProbeBwUp:
		if b.prevProbeTooHigh && b.bytesInFlight >= b.inflightLongterm {
			b.prevProbePrecautionary, b.prevProbeTooHigh = true, false
			b.startProbeDown(now)
		} else if b.cwndLimited && b.congestionWindow >= b.inflightLongterm {
			b.resetFullBandwidth(sample.sampleMaxBandwidth)
		} else if b.fullBandwidthNow {
			b.prevProbeTooHigh = false
			b.startProbeDown(now)
		}
	}
}

func (b *bbrSender) updateMinRtt(now time.Time, rtt time.Duration, roundStart bool) {
	if rtt <= 0 || rtt == infRTT {
		return
	}
	expired := now.Sub(b.probeRttMinStamp) > probeRttInterval
	if rtt < b.probeRttMinDelay || expired {
		b.probeRttMinDelay, b.probeRttMinStamp = rtt, now
	}
	if b.probeRttMinDelay < b.minRtt || now.Sub(b.minRttStamp) > minRttExpiry {
		b.minRtt, b.minRttStamp = b.probeRttMinDelay, b.probeRttMinStamp
	}
	if b.mode != bbrModeProbeRtt && expired && !b.idleRestart {
		b.saveCongestionWindow()
		b.mode, b.phase = bbrModeProbeRtt, acksProbeStopping
		b.probeRttDoneStamp = time.Time{}
		b.startRound()
		roundStart = false
	}
	if b.mode != bbrModeProbeRtt {
		return
	}
	b.sampler.OnAppLimited()
	if b.probeRttDoneStamp.IsZero() && b.bytesInFlight <= b.probeRttWindow() {
		b.probeRttDoneStamp, b.probeRttRoundDone = now.Add(probeRttTime), false
		b.startRound()
	} else if !b.probeRttDoneStamp.IsZero() {
		b.probeRttRoundDone = b.probeRttRoundDone || roundStart
		if b.probeRttRoundDone {
			b.checkProbeRttDone(now)
		}
	}
}

func (b *bbrSender) checkProbeRttDone(now time.Time) {
	if b.probeRttDoneStamp.IsZero() || !now.After(b.probeRttDoneStamp) {
		return
	}
	b.probeRttMinStamp = now
	b.congestionWindow = max(b.congestionWindow, b.priorCongestionWindow)
	b.resetShortTermModel()
	if b.fullBandwidthReached {
		b.startProbeDown(now)
		b.mode = bbrModeProbeBwCruise
	} else {
		b.mode = bbrModeStartup
	}
}

func (b *bbrSender) updateAckAggregation(now time.Time, acked congestion.ByteCount) {
	expected := bytesFromBandwidthAndTimeDelta(b.bandwidthEstimate(), now.Sub(b.extraAckedStart))
	if b.extraAckedDelivered <= expected {
		b.extraAckedDelivered, b.extraAckedStart, expected = 0, now, 0
	}
	b.extraAckedDelivered += acked
	if b.fullBandwidthReached {
		b.extraAcked.SetWindowLength(10)
	}
	b.extraAcked.Update(min(b.congestionWindow, b.extraAckedDelivered-expected), b.roundCount)
}

func (b *bbrSender) gains() (pacing, cwnd float64) {
	switch b.mode {
	case bbrModeStartup:
		return startupPacingGain, 2
	case bbrModeDrain:
		return 0.5, 2
	case bbrModeProbeBwDown:
		return 0.9, 2
	case bbrModeProbeBwUp:
		return 1.25, 2.25
	case bbrModeProbeRtt:
		return 1, 0.5
	default:
		return 1, 2
	}
}
func (b *bbrSender) isProbeBw() bool {
	return b.mode >= bbrModeProbeBwDown && b.mode <= bbrModeProbeBwUp
}
func (b *bbrSender) isProbingBandwidth() bool {
	return b.mode == bbrModeStartup || b.mode == bbrModeProbeBwRefill || b.mode == bbrModeProbeBwUp
}
func (b *bbrSender) minimumWindow() congestion.ByteCount { return 4 * b.maxDatagramSize }
func (b *bbrSender) maxBandwidth() Bandwidth             { return max(b.maxBwFilter[0], b.maxBwFilter[1]) }
func (b *bbrSender) bandwidthEstimate() Bandwidth        { return min(b.maxBandwidth(), b.bwShortterm) }
func (b *bbrSender) bdp(gain float64) congestion.ByteCount {
	if b.minRtt == infRTT {
		return b.initialCongestionWindow
	}
	return congestion.ByteCount(min(float64(b.maxCongestionWindow), gain*float64(bytesFromBandwidthAndTimeDelta(b.bandwidthEstimate(), b.minRtt))))
}
func (b *bbrSender) quantizationBudget(inflight congestion.ByteCount) congestion.ByteCount {
	// QUIC's offload budget is one send quantum, not TCP's three quanta.
	inflight = max(inflight, b.pacer.sendQuantum(), b.minimumWindow())
	if b.mode == bbrModeProbeBwUp {
		inflight += 2 * b.maxDatagramSize
	}
	return inflight
}
func (b *bbrSender) inflight(gain float64) congestion.ByteCount {
	return b.quantizationBudget(b.bdp(gain))
}
func (b *bbrSender) targetInflight() congestion.ByteCount { return min(b.bdp(1), b.congestionWindow) }
func (b *bbrSender) probeRttWindow() congestion.ByteCount { return max(b.minimumWindow(), b.bdp(0.5)) }
func (b *bbrSender) inflightWithHeadroom() congestion.ByteCount {
	if b.inflightLongterm == unlimitedInflight {
		return unlimitedInflight
	}
	return max(b.minimumWindow(), b.inflightLongterm-max(b.maxDatagramSize, congestion.ByteCount(headroom*float64(b.inflightLongterm))))
}
func (b *bbrSender) saveCongestionWindow() {
	if !b.recovery && b.mode != bbrModeProbeRtt {
		b.priorCongestionWindow = b.congestionWindow
	} else {
		b.priorCongestionWindow = max(b.priorCongestionWindow, b.congestionWindow)
	}
}

// PacingRate returns bits per second, like the original BBR API.
func (b *bbrSender) PacingRate() Bandwidth {
	if b.pacingRate != 0 {
		return b.pacingRate
	}
	rtt := time.Millisecond
	if b.rttStats != nil && b.rttStats.SmoothedRTT() > 0 {
		rtt = b.rttStats.SmoothedRTT()
	}
	return Bandwidth(startupPacingGain * float64(BandwidthFromDelta(b.initialCongestionWindow, rtt)))
}
func (b *bbrSender) setPacingRate(gain float64) {
	if b.bandwidthEstimate() == 0 {
		return
	}
	rate := Bandwidth(gain * pacingMargin * float64(b.bandwidthEstimate()))
	if b.fullBandwidthReached || rate > b.PacingRate() {
		b.pacingRate = max(1, rate)
	}
}
func (b *bbrSender) updateControl(acked congestion.ByteCount) {
	pacingGain, cwndGain := b.gains()
	b.setPacingRate(pacingGain)
	window := b.quantizationBudget(b.bdp(cwndGain) + b.extraAcked.GetBest())
	if b.fullBandwidthReached {
		b.congestionWindow = min(b.congestionWindow+acked, window)
	} else if b.congestionWindow < window || b.sampler.TotalBytesAcked() < b.initialCongestionWindow {
		b.congestionWindow += acked
	}
	b.congestionWindow = max(b.congestionWindow, b.minimumWindow())
	cap := b.inflightShortterm
	if b.mode == bbrModeProbeBwCruise || b.mode == bbrModeProbeRtt {
		cap = min(cap, b.inflightWithHeadroom())
	} else if b.isProbeBw() || b.mode == bbrModeDrain {
		cap = min(cap, b.inflightLongterm)
	}
	if b.mode == bbrModeProbeRtt {
		cap = min(cap, b.probeRttWindow())
	}
	b.congestionWindow = min(b.congestionWindow, max(b.minimumWindow(), cap), b.maxCongestionWindow)
}

func GetInitialPacketSize(addr net.Addr) congestion.ByteCount {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if udpAddr.IP.To4() != nil {
			return congestion.InitialPacketSizeIPv4
		}
		return congestion.InitialPacketSizeIPv6
	}
	return congestion.MinInitialPacketSize
}
