package common

import (
	"context"
	"testing"
	"time"

	"github.com/daeuniverse/quic-go"
)

// The reports quic-go makes for a 0-RTT dial whose ticket granted 100
// bidirectional streams, before the peer rejects 0-RTT and grants 20.
func reportRejected0RTT(c *StreamCredit) {
	c.Report(quic.StreamTypeBidi, 0)   // new connection
	c.Report(quic.StreamTypeBidi, 100) // restored from the ticket
	c.Report(quic.StreamTypeBidi, 99)  // opened in 0-RTT
	c.Report(quic.StreamTypeBidi, 0)   // limits restart after the rejection
}

func TestStreamCreditFollowsRejected0RTT(t *testing.T) {
	t.Run("rejection seen after the new grant", func(t *testing.T) {
		var c StreamCredit
		reportRejected0RTT(&c)
		c.Report(quic.StreamTypeBidi, 20)
		c.Report(quic.StreamTypeBidi, 19) // already opened on the new limits
		c.Rejected0RTT()
		if current, highest := c.Credit(quic.StreamTypeBidi); current != 19 || highest != 20 {
			t.Fatalf("credit = %d/%d, want 19/20", current, highest)
		}
	})
	t.Run("rejection seen before the new grant", func(t *testing.T) {
		var c StreamCredit
		reportRejected0RTT(&c)
		c.Rejected0RTT()
		c.Report(quic.StreamTypeBidi, 20)
		if current, highest := c.Credit(quic.StreamTypeBidi); current != 20 || highest != 20 {
			t.Fatalf("credit = %d/%d, want 20/20", current, highest)
		}
	})
	t.Run("only the first rejection counts", func(t *testing.T) {
		var c StreamCredit
		reportRejected0RTT(&c)
		c.Report(quic.StreamTypeBidi, 20)
		c.Rejected0RTT()
		for n := int64(19); n >= 0; n-- {
			c.Report(quic.StreamTypeBidi, n)
		}
		c.Report(quic.StreamTypeBidi, 5)
		c.Rejected0RTT()
		if _, highest := c.Credit(quic.StreamTypeBidi); highest != 20 {
			t.Fatalf("highest = %d, want 20", highest)
		}
	})
	t.Run("released credit ends the wait", func(t *testing.T) {
		var c StreamCredit
		reportRejected0RTT(&c)
		c.Report(quic.StreamTypeBidi, 20)
		c.Rejected0RTT()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		c.WaitReleased(ctx, nil)
		if ctx.Err() != nil {
			t.Fatal("WaitReleased waited for the ticket's grant")
		}
	})
}
