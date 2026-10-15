package bbr

import (
	"math"
	"time"

	"github.com/daeuniverse/quic-go/congestion"
)

const (
	infBandwidth = Bandwidth(math.MaxUint64)
)

// Bandwidth of a connection
type Bandwidth uint64

const (
	// BitsPerSecond is 1 bit per second
	BitsPerSecond Bandwidth = 1
	// BytesPerSecond is 1 byte per second
	BytesPerSecond = 8 * BitsPerSecond
)

// BandwidthFromDelta calculates the bandwidth from a number of bytes and a time delta
func BandwidthFromDelta(bytes congestion.ByteCount, delta time.Duration) Bandwidth {
	if bytes <= 0 || delta <= 0 {
		return 0
	}
	return Bandwidth(min(float64(math.MaxUint64/4), float64(bytes)*8/delta.Seconds()))
}
