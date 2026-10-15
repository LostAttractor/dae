// SPDX-License-Identifier: AGPL-3.0-only

package control

// A program counter follows the profile's execution order, independently of
// physical fragment placement. All jumps use this coordinate.
type routingCursor struct {
	spans                         []routingSpan
	span                          int
	instruction, position, length uint32
}

func newRoutingCursor(spans []routingSpan) routingCursor {
	c := routingCursor{spans: spans, length: uint32(spanExecutionLen(spans))}
	c.advance(0)
	return c
}

func (c *routingCursor) advance(distance uint32) bool {
	if distance > c.length-c.position {
		return false
	}
	c.position += distance
	for c.span < len(c.spans) {
		span := c.spans[c.span]
		if c.instruction < span.Start {
			c.instruction = span.Start
		}
		remaining := span.End - c.instruction
		if distance < remaining {
			c.instruction += distance
			return true
		}
		distance -= remaining
		c.span++
		c.instruction = 0
	}
	return true
}
