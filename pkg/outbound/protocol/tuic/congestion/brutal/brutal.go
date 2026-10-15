package brutal

import (
	"errors"
	"math"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/congestion/common"

	"github.com/daeuniverse/quic-go/congestion"
	log "github.com/sirupsen/logrus"
)

const (
	pktInfoSlotCount           = 5 // slot index is based on seconds, so this is basically how many seconds we sample
	minSampleCount             = 50
	minAckRate                 = 0.8
	congestionWindowMultiplier = 2

	traceInterval = 2
)

var _ congestion.CongestionControl = &BrutalSender{}

type BrutalSender struct {
	rttStats        congestion.RTTStatsProvider
	bps             congestion.ByteCount
	maxDatagramSize congestion.ByteCount
	pacer           *common.Pacer

	pktInfoSlots [pktInfoSlotCount]pktInfo
	ackRate      float64

	lastAckTraceTimestamp int64
}

type pktInfo struct {
	Timestamp int64
	AckCount  uint64
	LossCount uint64
}

func NewBrutalSender(bps uint64) (*BrutalSender, error) {
	if bps == 0 || bps > math.MaxInt64 {
		return nil, errors.New("Brutal bandwidth must be in [1, MaxInt64] bytes per second")
	}
	bs := &BrutalSender{
		bps:             congestion.ByteCount(bps),
		maxDatagramSize: congestion.InitialPacketSizeIPv4,
		ackRate:         1,
	}
	bs.pacer = common.NewPacer(func() congestion.ByteCount {
		return boundedByteCount(float64(bs.bps) / bs.ackRate)
	})
	return bs, nil
}

// Congestion budgets may saturate at the largest representable byte count;
// converting an out-of-range float directly would instead make them negative.
func boundedByteCount(value float64) congestion.ByteCount {
	if value >= float64(math.MaxInt64) {
		return math.MaxInt64
	}
	return congestion.ByteCount(value)
}

func (b *BrutalSender) SetRTTStatsProvider(rttStats congestion.RTTStatsProvider) {
	b.rttStats = rttStats
}

func (b *BrutalSender) TimeUntilSend(bytesInFlight congestion.ByteCount) time.Time {
	return b.pacer.TimeUntilSend()
}

func (b *BrutalSender) HasPacingBudget(now time.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *BrutalSender) CanSend(bytesInFlight congestion.ByteCount) bool {
	return bytesInFlight <= b.GetCongestionWindow()
}

func (b *BrutalSender) GetCongestionWindow() congestion.ByteCount {
	rtt := b.rttStats.SmoothedRTT()
	if rtt <= 0 {
		return 10240
	}
	cwnd := boundedByteCount(float64(b.bps) * rtt.Seconds() * congestionWindowMultiplier / b.ackRate)
	if cwnd < b.maxDatagramSize {
		cwnd = b.maxDatagramSize
	}
	return cwnd
}

func (b *BrutalSender) OnPacketSent(sentTime time.Time, bytesInFlight congestion.ByteCount,
	packetNumber congestion.PacketNumber, bytes congestion.ByteCount, isRetransmittable bool,
) {
	b.pacer.SentPacket(sentTime, bytes)
}

func (b *BrutalSender) OnPacketAcked(number congestion.PacketNumber, ackedBytes congestion.ByteCount,
	priorInFlight congestion.ByteCount, eventTime time.Time,
) {
	// Stub
}

func (b *BrutalSender) OnCongestionEvent(number congestion.PacketNumber, lostBytes congestion.ByteCount,
	priorInFlight congestion.ByteCount,
) {
	// Stub
}

func (b *BrutalSender) OnCongestionEventEx(priorInFlight congestion.ByteCount, eventTime time.Time, ackedPackets []congestion.AckedPacketInfo, lostPackets []congestion.LostPacketInfo) {
	currentTimestamp := eventTime.Unix()
	slot := currentTimestamp % pktInfoSlotCount
	if b.pktInfoSlots[slot].Timestamp == currentTimestamp {
		b.pktInfoSlots[slot].LossCount += uint64(len(lostPackets))
		b.pktInfoSlots[slot].AckCount += uint64(len(ackedPackets))
	} else {
		// uninitialized slot or too old, reset
		b.pktInfoSlots[slot].Timestamp = currentTimestamp
		b.pktInfoSlots[slot].AckCount = uint64(len(ackedPackets))
		b.pktInfoSlots[slot].LossCount = uint64(len(lostPackets))
	}
	b.updateAckRate(currentTimestamp)
}

func (b *BrutalSender) SetMaxDatagramSize(size congestion.ByteCount) {
	b.maxDatagramSize = size
	b.pacer.SetMaxDatagramSize(size)
	log.WithField("bytes", size).Trace("Brutal maximum datagram size changed")
}

func (b *BrutalSender) updateAckRate(currentTimestamp int64) {
	minTimestamp := currentTimestamp - pktInfoSlotCount
	var ackCount, lossCount uint64
	for _, info := range b.pktInfoSlots {
		if info.Timestamp < minTimestamp {
			continue
		}
		ackCount += info.AckCount
		lossCount += info.LossCount
	}
	if ackCount+lossCount < minSampleCount {
		b.ackRate = 1
	} else {
		b.ackRate = max(float64(ackCount)/float64(ackCount+lossCount), minAckRate)
	}
	if log.IsLevelEnabled(log.TraceLevel) && currentTimestamp-b.lastAckTraceTimestamp >= traceInterval {
		b.lastAckTraceTimestamp = currentTimestamp
		log.WithFields(log.Fields{
			"acked_packets": ackCount,
			"lost_packets":  lossCount,
			"ack_rate":      b.ackRate,
			"rtt":           b.rttStats.SmoothedRTT(),
		}).Trace("Brutal congestion sample")
	}
}

func (b *BrutalSender) InSlowStart() bool {
	return false
}

func (b *BrutalSender) InRecovery() bool {
	return false
}

func (b *BrutalSender) MaybeExitSlowStart() {}

func (b *BrutalSender) OnRetransmissionTimeout(packetsRetransmitted bool) {}
