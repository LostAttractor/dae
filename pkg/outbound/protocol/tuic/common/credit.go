package common

import (
	"context"
	"sync"

	"github.com/daeuniverse/quic-go"
)

// StreamCredit follows the stream credit a peer grants one connection, as
// quic.Config.CapabilityCallback reports it: per stream type, how many
// streams can still be opened and the peer's concurrency allowance. The
// zero value is ready to use.
type StreamCredit struct {
	mu               sync.Mutex
	highest, current [2]int64 // by quic.StreamType
	handshake        <-chan struct{}
	// sinceZero is the most credit granted since a type last reported zero,
	// which quic-go does when it restarts its limits after a 0-RTT rejection.
	sinceZero [2]int64
	restarted bool
	changed   chan struct{}
}

// Track0RTT must be called before opening early streams. quic-go applies the
// final transport parameters before it closes handshake.
func (c *StreamCredit) Track0RTT(handshake <-chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handshake = handshake
}

// Report is a quic.Config.CapabilityCallback; it never blocks.
func (c *StreamCredit) Report(streamType quic.StreamType, available int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handshake != nil {
		select {
		case <-c.handshake:
			c.handshake = nil
		default:
			// A larger handshake grant does not release already opened streams.
			c.highest[streamType] += max(0, available-c.current[streamType])
		}
	}
	c.current[streamType] = available
	c.highest[streamType] = max(c.highest[streamType], available)
	c.sinceZero[streamType] = max(c.sinceZero[streamType], available)
	if available == 0 {
		c.sinceZero[streamType] = 0
	}
	c.notify()
}

// Rejected0RTT follows quic-go restarting both stream limits from zero once
// the peer rejected 0-RTT: the restored grant from the session ticket no
// longer applies, and the peer's new grant may be lower. It must run before
// the new limits are used up; only the first call has an effect.
func (c *StreamCredit) Rejected0RTT() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.restarted {
		return
	}
	c.restarted = true
	c.highest = c.sinceZero
	c.notify()
}

func (c *StreamCredit) notify() {
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
// their credit is not awaited. quic-go returns credit as each stream ends.
// Peers at QUIC's stream limit cannot return credit, and quinn returns it
// in batches; missing credit still waits until ctx ends, since the peer
// may not have received the last upload yet.
func (c *StreamCredit) WaitReleased(ctx context.Context, done <-chan struct{}) {
	for {
		c.mu.Lock()
		current, highest := c.current[quic.StreamTypeBidi], c.highest[quic.StreamTypeBidi]
		if current >= highest {
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
