package common

import (
	"math"
	"math/bits"
	"time"

	"github.com/daeuniverse/quic-go/congestion"
)

const (
	maxBurstPackets = 10
)

// Pacer implements a token bucket pacing algorithm.
type Pacer struct {
	budgetAtLastSent congestion.ByteCount
	maxDatagramSize  congestion.ByteCount
	lastSentTime     time.Time
	getBandwidth     func() congestion.ByteCount // in bytes/s
}

func NewPacer(getBandwidth func() congestion.ByteCount) *Pacer {
	p := &Pacer{
		budgetAtLastSent: maxBurstPackets * congestion.InitialPacketSizeIPv4,
		maxDatagramSize:  congestion.InitialPacketSizeIPv4,
		getBandwidth:     getBandwidth,
	}
	return p
}

func (p *Pacer) SentPacket(sendTime time.Time, size congestion.ByteCount) {
	budget := p.Budget(sendTime)
	if size > budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = sendTime
}

func (p *Pacer) Budget(now time.Time) congestion.ByteCount {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize()
	}
	limit := p.maxBurstSize()
	added := bytesForInterval(p.getBandwidth(), now.Sub(p.lastSentTime))
	if p.budgetAtLastSent >= limit || added >= limit-p.budgetAtLastSent {
		return limit
	}
	return p.budgetAtLastSent + added
}

func (p *Pacer) maxBurstSize() congestion.ByteCount {
	return max(
		bytesForInterval(p.getBandwidth(), congestion.MinPacingDelay+time.Millisecond),
		maxBurstPackets*p.maxDatagramSize,
	)
}

func bytesForInterval(bandwidth congestion.ByteCount, interval time.Duration) congestion.ByteCount {
	if bandwidth <= 0 || interval <= 0 {
		return 0
	}
	// Multiply before dividing without overflowing at high rates or after idle.
	hi, lo := bits.Mul64(uint64(bandwidth), uint64(interval))
	if hi >= uint64(time.Second) {
		return math.MaxInt64
	}
	value, _ := bits.Div64(hi, lo, uint64(time.Second))
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return congestion.ByteCount(value)
}

// TimeUntilSend returns when the next packet should be sent.
// It returns the zero value of time.Time if a packet can be sent immediately.
func (p *Pacer) TimeUntilSend() time.Time {
	if p.budgetAtLastSent >= p.maxDatagramSize {
		return time.Time{}
	}
	return p.lastSentTime.Add(maxDuration(
		congestion.MinPacingDelay,
		time.Duration(math.Ceil(float64(p.maxDatagramSize-p.budgetAtLastSent)*1e9/
			float64(p.getBandwidth())))*time.Nanosecond,
	))
}

func (p *Pacer) SetMaxDatagramSize(s congestion.ByteCount) {
	p.maxDatagramSize = s
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
