package common

import (
	"context"
	"sync"

	"github.com/daeuniverse/quic-go"
)

// StreamCredit follows the stream credit a peer grants one connection, as
// quic.Config.CapabilityCallback reports it: per stream type, how many
// streams can still be opened and the most the peer granted at once. A peer
// returns a stream's credit only once its application has finished with the
// stream, so credit back at its highest shows that the peer consumed every
// stream it was sent, not merely that the packets were acknowledged. The
// zero value is ready to use.
type StreamCredit struct {
	mu               sync.Mutex
	highest, current [2]int64 // by quic.StreamType
	changed          chan struct{}
}

// Report is a quic.Config.CapabilityCallback; it never blocks.
func (c *StreamCredit) Report(streamType quic.StreamType, available int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current[streamType] = available
	c.highest[streamType] = max(c.highest[streamType], available)
	if c.changed != nil {
		close(c.changed)
		c.changed = nil
	}
}

// Credit reports how many streams of a type can still be opened and the
// most the peer granted; both are 0 until the peer reported any.
func (c *StreamCredit) Credit(streamType quic.StreamType) (current, highest int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current[streamType], c.highest[streamType]
}

// WaitReleased waits until bidirectional credit is back at its highest, ctx
// ends or done is closed. Unidirectional streams carry best-effort packets
// or stay open with the connection (authentication, HTTP/3 control), so
// their credit is not awaited. quic-go returns credit as each stream ends,
// but a peer granting about QUIC's cap of 2^60 streams, as sing-box's does,
// cannot raise its limit again: its credit counts as released. quinn
// returns credit in batches of an eighth of its limit, so what is left
// below a batch is waited for until ctx ends.
func (c *StreamCredit) WaitReleased(ctx context.Context, done <-chan struct{}) {
	for {
		c.mu.Lock()
		current, highest := c.current[quic.StreamTypeBidi], c.highest[quic.StreamTypeBidi]
		if current >= highest || highest >= 1<<59 {
			c.mu.Unlock()
			return
		}
		if c.changed == nil {
			c.changed = make(chan struct{})
		}
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-changed:
		case <-done:
			return
		case <-ctx.Done():
			return
		}
	}
}
