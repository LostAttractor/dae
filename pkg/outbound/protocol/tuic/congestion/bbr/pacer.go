package bbr

import (
	"math"
	"time"

	"github.com/daeuniverse/quic-go/congestion"
)

// pacer uses BBR's actual pacing rate and QUIC send quantum. In particular,
// neither the cwnd gain nor a fixed minimum bandwidth may override Drain.
type pacer struct {
	sender   *bbrSender
	lastSent time.Time
	budget   congestion.ByteCount
}

func (p *pacer) sendQuantum() congestion.ByteCount {
	return max(2*p.sender.maxDatagramSize,
		min(64*1024, bytesFromBandwidthAndTimeDelta(p.sender.PacingRate(), time.Millisecond)))
}

func (p *pacer) maxBurstSize() congestion.ByteCount {
	// A timer wakeup can send multiple quanta. Capping the entire budget at
	// 64 KiB would cap timer-driven throughput at 64 KiB / MinPacingDelay.
	// Preserve a partial datagram between wakeups as well.
	return max(p.sendQuantum(),
		bytesFromBandwidthAndTimeDelta(p.sender.PacingRate(), congestion.MinPacingDelay)+p.sender.maxDatagramSize)
}

func (p *pacer) Budget(now time.Time) congestion.ByteCount {
	burst := p.maxBurstSize()
	if p.lastSent.IsZero() {
		return p.sendQuantum()
	}
	// The conversion already clamps negative intervals to zero and caps the
	// credit at MaxInt64/2. Adding one timer interval of saved budget is safe.
	added := bytesFromBandwidthAndTimeDelta(p.sender.PacingRate(), now.Sub(p.lastSent))
	return min(burst, p.budget+added)
}

func (p *pacer) SentPacket(now time.Time, size congestion.ByteCount) {
	p.budget = max(0, p.Budget(now)-size)
	p.lastSent = now
}

func (p *pacer) TimeUntilSend() time.Time {
	if p.lastSent.IsZero() || p.budget >= p.sender.maxDatagramSize {
		return time.Time{}
	}
	seconds := float64(p.sender.maxDatagramSize-p.budget) * 8 / float64(p.sender.PacingRate())
	delay := time.Duration(min(float64(math.MaxInt64/2), math.Ceil(seconds*float64(time.Second))))
	return p.lastSent.Add(max(congestion.MinPacingDelay, delay))
}
