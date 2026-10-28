package fq

import (
	"slices"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

// These scenarios report policy effects under a deterministic carrier clock.
// Admission, ownership and accounting must hold for every policy variant.
func TestDatagramQueueScenarios(t *testing.T) {
	for _, scenario := range []string{"standing-queue", "fair-share", "slow-fair-share", "split-datagram"} {
		t.Run(scenario, func(t *testing.T) {
			used := netproxy.DatagramMemory.Status().Used
			t.Cleanup(func() {
				if held := netproxy.DatagramMemory.Status().Used - used; held != 0 {
					t.Fatalf("retained %d bytes", held)
				}
			})
			rate := 125000.0
			if scenario == "fair-share" {
				rate = 40e6 / 8 / 3
			}
			c := newCarrier(t, rate)
			flow := new(Flow)
			dropped := drops(dropCoDel)
			var offered, sent uint32
			var waits []time.Duration
			offer := func(at time.Time, size int) {
				if !c.s.Offer(flow, at, frame('d', offered, size)) {
					t.Fatal("unexpected memory rejection")
				}
				offered++
			}
			var lastStarted uint32
			started := false
			observe := func(held heldFrame) {
				if held.flow != flow {
					return
				}
				seq := seqOf(held.frame)
				if !started || seq != lastStarted {
					if c.now.Sub(epoch) >= time.Second {
						waits = append(waits, c.now.Sub(held.at))
					}
					lastStarted, started = seq, true
				}
			}
			take := func(want int) {
				batch := c.s.Take(c.now, want, nil)
				for _, held := range c.s.inflight {
					observe(held)
					if held.flow == flow {
						sent++
					}
				}
				// Record the first dequeue, not completion of a split datagram.
				observe(c.s.partial)
				size := 0
				for _, part := range batch {
					size += len(part)
				}
				c.s.ReleaseBatch()
				if size == 0 {
					t.Fatal("backlogged carrier made no progress")
				}
				c.now = c.now.Add(time.Duration(float64(size) / rate * float64(time.Second)))
			}
			if scenario == "split-datagram" {
				c.now = epoch.Add(time.Second)
				offer(c.now, 3000)
				take(2000)
				take(1000)
				if len(waits) != 1 || waits[0] != 0 {
					t.Fatalf("partial send time counted as queue delay: %v", waits)
				}
			} else if scenario == "standing-queue" {
				for range 40 {
					offer(c.now, 1000)
				}
				for c.now.Sub(epoch) < 10*time.Second {
					offer(c.now, 1000)
					take(1000)
				}
			} else {
				bulk := make([]Flow, 16)
				interval := time.Duration(float64(len(bulk)+1) * Quantum / rate * float64(time.Second))
				next := epoch
				for c.now.Sub(epoch) < 10*time.Second {
					for i := range bulk {
						for !bulk[i].Full(16 << 10) {
							c.s.Push(&bulk[i], frame('b', 0, 16<<10))
						}
					}
					for !next.After(c.now) {
						offer(next, Quantum)
						next = next.Add(interval)
					}
					take(64 << 10)
				}
			}
			pending := flow.queue.Len()
			if c.s.partial.flow == flow {
				pending++
			}
			if uint64(offered) != uint64(sent)+dropped()+uint64(pending) || len(waits) == 0 {
				t.Fatalf("offered=%d sent=%d dropped=%d pending=%d samples=%d", offered, sent, dropped(), pending, len(waits))
			}
			slices.Sort(waits)
			t.Logf("offered=%d sent=%d dropped=%d pending=%d samples=%d queue_p50=%v queue_p99=%v queue_max=%v", offered, sent, dropped(), pending, len(waits), waits[len(waits)/2], waits[(len(waits)-1)*99/100], waits[len(waits)-1])
		})
	}
}
