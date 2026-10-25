package common

import (
	"sync"

	"github.com/daeuniverse/quic-go"
)

// StreamCredit follows the stream credit a peer grants one connection, as
// quic.Config.CapabilityCallback reports it: per stream type, how many
// streams can still be opened and the most the peer granted at once. The
// zero value is ready to use.
type StreamCredit struct {
	mu               sync.Mutex
	highest, current [2]int64 // by quic.StreamType
}

// Report is a quic.Config.CapabilityCallback; it never blocks.
func (c *StreamCredit) Report(streamType quic.StreamType, available int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current[streamType] = available
	c.highest[streamType] = max(c.highest[streamType], available)
}

// Credit reports how many streams of a type can still be opened and the
// most the peer granted; both are 0 until the peer reported any.
func (c *StreamCredit) Credit(streamType quic.StreamType) (current, highest int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current[streamType], c.highest[streamType]
}
