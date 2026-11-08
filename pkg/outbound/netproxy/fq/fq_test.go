package fq

import (
	"encoding/binary"
	"math"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

var epoch = time.Unix(1_000_000, 0)

// frame returns a frame of size bytes that names its flow and sequence.
func frame(flow byte, seq uint32, size int) []byte {
	b := make([]byte, size)
	b[0] = flow
	binary.BigEndian.PutUint32(b[1:], seq)
	return b
}

// admit queues a copy of b through AllocateDatagram, as its users do.
func admit(s *Scheduler, f *Flow, now time.Time, b []byte, force bool) bool {
	frame := s.AllocateDatagram(f, now, len(b), force)
	copy(frame, b)
	return frame != nil
}

func flowOf(b []byte) byte  { return b[0] }
func seqOf(b []byte) uint32 { return binary.BigEndian.Uint32(b[1:]) }

// carrier drains a scheduler at rate bytes per second on a fake clock.
type carrier struct {
	s    *Scheduler
	now  time.Time
	rate float64
	sent map[byte][]uint32
	// bytes counts the bytes sent per flow.
	bytes map[byte]int
}

func newCarrier(t *testing.T, rate float64) *carrier {
	c := &carrier{s: &Scheduler{Drops: testDrops}, now: epoch, rate: rate, sent: make(map[byte][]uint32), bytes: make(map[byte]int)}
	// Datagram memory is shared by the tests.
	t.Cleanup(func() { c.s.Clear(); c.s.ReleaseBatch() })
	return c
}

// take sends one batch of want bytes and advances the clock by its time on
// the wire.
func (c *carrier) take(want int) [][]byte {
	batch := c.s.Take(c.now, want, nil)
	size := 0
	for _, b := range batch {
		size += len(b)
	}
	// Record complete frames, not the slices of a partially written frame.
	var complete [][]byte
	for _, h := range c.s.inflight {
		b := h.frame
		c.sent[flowOf(b)] = append(c.sent[flowOf(b)], seqOf(b))
		c.bytes[flowOf(b)] += len(b)
		complete = append(complete, b)
	}
	c.now = c.now.Add(time.Duration(float64(size) / c.rate * float64(time.Second)))
	c.s.ReleaseBatch()
	return complete
}

// testDrops counts the drops of the schedulers whose counts tests check.
var testDrops = NewDrops("fq-test")

func drops(d *netproxy.Drop) func() uint64 {
	before := d.Load()
	return func() uint64 { return d.Load() - before }
}

// A flow that turns busy goes first in the next batch, ahead of a flow that
// has queued for long; the busy flow keeps its turns after it.
func TestSparseFlowGoesFirst(t *testing.T) {
	c := newCarrier(t, 5e6)
	bulk, sparse := new(Flow), new(Flow)
	for i := range 4 {
		c.s.Push(bulk, frame('b', uint32(i), 16<<10))
	}
	c.take(16 << 10)
	admit(c.s, sparse, c.now, frame('s', 0, 100), false)
	batch := c.take((16 << 10) + 100)
	if len(batch) != 2 || flowOf(batch[0]) != 's' || flowOf(batch[1]) != 'b' {
		t.Fatalf("batch after a sparse datagram: %d frames, first of flow %c", len(batch), flowOf(batch[0]))
	}
}

// Deficit round robin shares bytes, not frames: a flow of 1514-byte
// datagrams and one of 16 KiB stream frames get the same bytes within 5%.
func TestDRRSharesBytes(t *testing.T) {
	c := newCarrier(t, 5e6)
	datagrams, streams := new(Flow), new(Flow)
	var seq uint32
	for range 2000 {
		for datagrams.datagrams < 32<<10 {
			seq++
			admit(c.s, datagrams, c.now, frame('d', seq, 1514), false)
		}
		for !streams.Full(16 << 10) {
			c.s.Push(streams, frame('s', 0, 16<<10))
		}
		// CoDel stays out: the datagrams wait no longer than a round.
		c.now = epoch
		c.take(16 << 10)
	}
	d, s := float64(c.bytes['d']), float64(c.bytes['s'])
	if share := d / (d + s); math.Abs(share-0.5) > 0.025 {
		t.Fatalf("datagram flow got %.1f%% of the bytes", share*100)
	}
}

// CoDel drops only once the sojourn stayed above target for an interval,
// then at intervals shrinking as 1/√count; reentering the dropping state
// soon after leaving it resumes from the count reached.
func TestCoDelControlLaw(t *testing.T) {
	c := newCarrier(t, 1e6)
	f := new(Flow)
	codel := drops(testDrops.CoDel)
	var seq uint32
	offer := func() {
		seq++
		admit(c.s, f, c.now, frame('d', seq, 1000), false)
	}
	// A standing queue of 30 ms: one datagram arrives per one sent.
	for range 30 {
		offer()
	}
	var dropTimes []time.Duration
	var above time.Time
	step := func() {
		before := codel()
		offer()
		c.take(1000)
		if above.IsZero() && !f.codel.firstAbove.IsZero() {
			above = f.codel.firstAbove.Add(-Interval)
		}
		for range codel() - before {
			dropTimes = append(dropTimes, c.now.Sub(epoch))
		}
	}
	for c.now.Sub(epoch) < 2*time.Second {
		step()
	}
	if above.IsZero() || len(dropTimes) < 3 {
		t.Fatalf("%d drops, above target since %v", len(dropTimes), above)
	}
	if first := dropTimes[0]; first < above.Sub(epoch)+Interval || first > above.Sub(epoch)+Interval+5*time.Millisecond {
		t.Fatalf("first drop at %v, above target from %v", first, above.Sub(epoch))
	}
	for i := 2; i < len(dropTimes) && i < 6; i++ {
		gap, want := dropTimes[i]-dropTimes[i-1], time.Duration(float64(Interval)/math.Sqrt(float64(i)))
		if gap < want-2*time.Millisecond || gap > want+2*time.Millisecond {
			t.Fatalf("drop %d came %v after the last, want %v", i+1, gap, want)
		}
	}
	// Drain below target, then build the queue again within 16 intervals.
	count := f.codel.count
	for f.queue.Len() > 0 {
		c.take(1000)
	}
	for range 30 {
		offer()
	}
	for limit := c.now.Add(time.Second); !f.codel.dropping && c.now.Before(limit); {
		step()
	}
	if !f.codel.dropping || f.codel.count <= 1 {
		t.Fatalf("reentered the dropping state (%v) with count %d after %d", f.codel.dropping, f.codel.count, count)
	}
}

// An empty queue breaks persistent congestion even when a datagram fills
// the batch, so Take never calls dequeue again to observe the empty flow.
func TestCoDelIntermittentLargeDatagrams(t *testing.T) {
	c := newCarrier(t, 1e6)
	f := new(Flow)
	dropped := drops(testDrops.CoDel)
	for i := range 20 {
		c.now = epoch.Add(time.Duration(i) * 50 * time.Millisecond)
		if !admit(c.s, f, c.now, frame('d', uint32(i), 8<<10), false) {
			t.Fatal("datagram refused")
		}
		c.now = c.now.Add(10 * time.Millisecond)
		batch := c.take(8 << 10)
		if len(batch) != 1 || seqOf(batch[0]) != uint32(i) {
			t.Fatalf("idle cycle %d: sent %d frames, dropped %d", i, len(batch), dropped())
		}
	}
	if n := dropped(); n != 0 {
		t.Fatalf("CoDel dropped %d intermittent datagrams", n)
	}
}

// Emptying a flow clears congestion, not the remembered drop rate, whether
// its last entry was sent or evicted to admit another flow's datagram.
func TestCoDelEmptyFlowKeepsDropMemory(t *testing.T) {
	for _, evict := range []bool{false, true} {
		t.Run(map[bool]string{false: "send", true: "evict"}[evict], func(t *testing.T) {
			c := newCarrier(t, 1e6)
			f := new(Flow)
			admit(c.s, f, c.now, frame('d', 0, 8<<10), false)
			f.codel = codel{dropping: true, count: 8, lastCount: 3,
				firstAbove: epoch.Add(-Interval), dropNext: epoch.Add(Interval)}
			if evict {
				c.s.dropOldest(f, false, testDrops.Memory)
			} else {
				c.now = c.now.Add(10 * time.Millisecond)
				c.take(8 << 10)
			}
			want := codel{count: 8, lastCount: 3, dropNext: epoch.Add(Interval)}
			if f.codel != want {
				t.Fatalf("empty flow CoDel state = %+v, want %+v", f.codel, want)
			}
		})
	}
}

// A carrier with a third of 40 Mbit/s shared by 16 bulk flows: a datagram
// flow sending at its fair share keeps a datagram waiting about a round,
// beyond the 5 ms target, but cake's guard keeps CoDel from dropping it.
// Above its share, it is dropped.
func TestCoDelSparesFairShare(t *testing.T) {
	for _, tc := range []struct {
		name  string
		share float64
		drops bool
	}{{"fair share", 1, false}, {"two shares", 2, true}} {
		t.Run(tc.name, func(t *testing.T) {
			rate := 40e6 / 8 / 3
			c := newCarrier(t, rate)
			bulk := make([]*Flow, 16)
			for i := range bulk {
				bulk[i] = new(Flow)
			}
			game := new(Flow)
			codel := drops(testDrops.CoDel)
			// One Quantum per round of the 17 flows; one datagram waits from
			// the start.
			interval := time.Duration(17 * Quantum / (tc.share * rate) * float64(time.Second))
			next := epoch
			var seq uint32
			admit(c.s, game, next, frame('g', seq, Quantum), false)
			for c.now.Sub(epoch) < 10*time.Second {
				for _, f := range bulk {
					for !f.Full(16 << 10) {
						c.s.Push(f, frame('b', 0, 16<<10))
					}
				}
				for !next.After(c.now) {
					seq++
					admit(c.s, game, next, frame('g', seq, Quantum), false)
					next = next.Add(interval)
				}
				c.take(8 << 10)
			}
			if dropped := codel(); (dropped > 0) != tc.drops {
				t.Fatalf("CoDel dropped %d of %d datagrams", dropped, seq+1)
			}
		})
	}
}

// A burst queued while an association was set up leaves without drops: it
// drains within an interval, before CoDel may act.
func TestBurstIsNotDropped(t *testing.T) {
	c := newCarrier(t, 40e6/8)
	bulk := make([]*Flow, 4)
	for i := range bulk {
		bulk[i] = new(Flow)
	}
	burst := new(Flow)
	dropped := drops(testDrops.CoDel)
	for i := range 128 {
		admit(c.s, burst, c.now, frame('u', uint32(i), 400), false)
	}
	for c.now.Sub(epoch) < time.Second {
		for _, f := range bulk {
			for !f.Full(16 << 10) {
				c.s.Push(f, frame('b', 0, 16<<10))
			}
		}
		c.take(8 << 10)
	}
	if n := dropped(); n > 0 || len(c.sent['u']) != 128 {
		t.Fatalf("sent %d of 128 burst datagrams, %d dropped", len(c.sent['u']), n)
	}
}

// Beyond its limit a flow drops its own oldest datagrams; beyond the
// carrier's, the fattest flow drops its oldest. The newest datagram always
// gets in, also into a flow that queued nothing.
func TestLimitsDropOldestOfFattest(t *testing.T) {
	used := netproxy.DatagramMemory.Status().Used
	s := &Scheduler{Drops: testDrops}
	var released int
	s.Release = func([]byte) { released++ }
	flowFull, carrierFull := drops(testDrops.FlowQueueFull), drops(testDrops.CarrierQueueFull)
	flows := make([]*Flow, 5)
	for i := range flows {
		flows[i] = new(Flow)
		n := 60
		if i == 0 {
			n = 70
		}
		for seq := range n {
			if !admit(s, flows[i], epoch, frame(byte('a'+i), uint32(seq), 1000), false) {
				t.Fatal("datagram refused")
			}
		}
		if want := uint64(70 - FlowDatagramLimit/1000); i == 0 && (flowFull() != want || seqOf(flows[0].queue.Peek().frame) != uint32(want)) {
			t.Fatalf("flow a dropped %d, oldest left %d", flowFull(), seqOf(flows[0].queue.Peek().frame))
		}
	}
	if s.datagrams > CarrierDatagramLimit || carrierFull() == 0 {
		t.Fatalf("%d datagram bytes queued after %d carrier drops", s.datagrams, carrierFull())
	}
	// The flows dropped evenly, each from its oldest.
	for _, f := range flows {
		if f.datagrams > flows[4].datagrams+1000 {
			t.Fatalf("flow %c keeps %d bytes, flow e %d", flowOf(f.queue.Peek().frame), f.datagrams, flows[4].datagrams)
		}
	}
	empty := new(Flow)
	before := carrierFull()
	if !admit(s, empty, epoch, frame('z', 0, 1000), false) || empty.queue.Len() != 1 || carrierFull() != before+1 {
		t.Fatal("a flow that queued nothing did not get its datagram in")
	}
	if released != int(flowFull()+carrierFull()) {
		t.Fatalf("released %d frames for %d drops", released, flowFull()+carrierFull())
	}
	s.Clear()
	if n := netproxy.DatagramMemory.Status().Used - used; n != 0 {
		t.Fatalf("%d bytes of datagram memory held after Clear", n)
	}
}

// A forced datagram survives every drop: the flow's and the carrier's
// limits, CoDel and later memory pressure after admission.
func TestForcedDatagramIsNeverDropped(t *testing.T) {
	c := newCarrier(t, 1e5)
	f := new(Flow)
	c.s.Push(f, frame('f', 0, 8)) // as smux's SYN
	admit(c.s, f, c.now, frame('f', 1, 1000), true)
	for seq := uint32(2); seq < 100; seq++ {
		admit(c.s, f, c.now, frame('f', seq, 1000), false)
	}
	others := make([]*Flow, 4)
	for i := range others {
		others[i] = new(Flow)
		for seq := range 64 {
			admit(c.s, others[i], c.now, frame(byte('a'+i), uint32(seq), 1000), false)
		}
	}
	limit := netproxy.DatagramMemory.UseLimit(1)
	if admit(c.s, f, c.now, frame('f', 100, 1000), false) {
		t.Fatal("a datagram got memory beyond the limit")
	}
	limit.Close()
	// Let CoDel act on everything left.
	c.now = c.now.Add(time.Second)
	for range 10 {
		c.take(1000)
		c.now = c.now.Add(time.Second)
	}
	if sent := c.sent['f']; len(sent) < 2 || sent[0] != 0 || sent[1] != 1 {
		t.Fatalf("flow sent %v first, want the SYN and the forced datagram", sent)
	}
}

// A flow queues stream frames up to StreamLimit; a flow that queued none
// always gets one in. Frames leaving signal Writable.
func TestStreamLimit(t *testing.T) {
	s := newCarrier(t, 1).s
	f := new(Flow)
	if f.Full(1 << 20) {
		t.Fatal("an empty flow refused a frame")
	}
	for range StreamLimit / (16 << 10) {
		s.Push(f, make([]byte, 16<<10))
	}
	if !f.Full(1) {
		t.Fatal("a full flow took more")
	}
	writable := f.Writable()
	s.Take(epoch, 16<<10, nil)
	defer s.ReleaseBatch()
	select {
	case <-writable:
	default:
		t.Fatal("no signal when a stream frame left")
	}
	if f.Full(16 << 10) {
		t.Fatal("a frame left, but the flow stayed full")
	}
	if tail := f.Tail(); tail == nil || len(*tail) != 16<<10 {
		t.Fatal("no tail stream frame")
	}
}

// The rate is estimated only while frames wait: an idle carrier does not
// look slow.
func TestRateWhileBacklogged(t *testing.T) {
	c := newCarrier(t, 5e6)
	f := new(Flow)
	for range 100 {
		c.s.Push(f, make([]byte, 16<<10))
	}
	for f.queue.Len() > 0 {
		c.take(16 << 10)
	}
	if r := c.s.rate; math.Abs(r-5e6) > 0.05*5e6 {
		t.Fatalf("rate %.0f while backlogged, want 5e6", r)
	}
	c.now = c.now.Add(10 * time.Second)
	c.s.Push(f, make([]byte, 16<<10))
	c.take(16 << 10)
	c.take(16 << 10)
	if r := c.s.rate; math.Abs(r-5e6) > 0.05*5e6 {
		t.Fatalf("rate %.0f after an idle carrier, want 5e6", r)
	}
}

// Queued datagrams hold datagram memory until they leave.
func TestDatagramMemory(t *testing.T) {
	used := netproxy.DatagramMemory.Status().Used
	c := newCarrier(t, 5e6)
	f := new(Flow)
	admit(c.s, f, c.now, make([]byte, 1000), false)
	admit(c.s, f, c.now, make([]byte, 2000), true)
	if n := netproxy.DatagramMemory.Status().Used - used; n != 1024+2048 {
		t.Fatalf("%d bytes of datagram memory held, want %d", n, 1024+2048)
	}
	c.take(1 << 20)
	if n := netproxy.DatagramMemory.Status().Used - used; n != 0 {
		t.Fatalf("%d bytes held after the datagrams left", n)
	}
}

// Queueing a datagram does not allocate once the queues have grown and
// released buffers return to the pool.
func TestDatagramQueueingDoesNotAllocate(t *testing.T) {
	s := newCarrier(t, 1).s
	s.Release = pool.PutBuffer
	f := new(Flow)
	b := make([]byte, 1200)
	batch := make([][]byte, 0, 16)
	if allocs := testing.AllocsPerRun(200, func() {
		admit(s, f, epoch, b, false)
		batch = s.Take(epoch, len(b), batch[:0])
		s.ReleaseBatch()
	}); allocs > 0 {
		t.Fatalf("%v allocations per datagram", allocs)
	}
}

// Dequeue transfers datagram memory to the writer, not to the free budget.
// Closing the scheduler while the writer is blocked must not release it.
func TestBatchHoldsDatagramMemoryUntilWritten(t *testing.T) {
	used := netproxy.DatagramMemory.Status().Used
	s := new(Scheduler)
	f := new(Flow)
	admit(s, f, epoch, make([]byte, 2000), true)
	admit(s, f, epoch, make([]byte, 1000), false)
	s.Take(epoch, 2000, nil)
	s.Clear()
	if n := netproxy.DatagramMemory.Status().Used - used; n != 2048 {
		t.Fatalf("in-flight datagram owns %d bytes, want 2048", n)
	}
	s.ReleaseBatch()
	if n := netproxy.DatagramMemory.Status().Used - used; n != 0 {
		t.Fatalf("writer released the batch but kept %d bytes", n)
	}
}

func TestWriterPassesAvailableSpaceOn(t *testing.T) {
	s := new(Scheduler)
	f := new(Flow)
	for range 4 {
		s.Push(f, make([]byte, 16<<10))
	}
	wake := f.Writable()
	s.Take(epoch, 32<<10, nil)
	defer s.ReleaseBatch()
	<-wake // the first waiting writer takes the only buffered signal
	s.Push(f, make([]byte, 100))
	f.WakeWriter()
	select {
	case <-wake:
	default:
		t.Fatal("the second writer cannot use the remaining queue space")
	}
	s.Clear()
}

func TestBatchFillsAcrossFrameBoundaries(t *testing.T) {
	s := new(Scheduler)
	f := new(Flow)
	for range 3 {
		s.Push(f, make([]byte, 1000))
	}
	batch := s.Take(epoch, 1514, nil)
	if len(batch) != 2 || len(batch[0]) != 1000 || len(batch[1]) != 514 {
		t.Fatalf("batch lengths: %v", lengths(batch))
	}
	s.ReleaseBatch()
	batch = s.Take(epoch, 500, nil)
	if len(batch) != 2 || len(batch[0]) != 486 || len(batch[1]) != 14 {
		t.Fatalf("continuation lengths: %v", lengths(batch))
	}
	s.ReleaseBatch()
	s.Clear()
}

func lengths(batch [][]byte) []int {
	var sizes []int
	for _, b := range batch {
		sizes = append(sizes, len(b))
	}
	return sizes
}

func TestRejectedAdmissionDoesNotAllocateDatagramCopy(t *testing.T) {
	s := new(Scheduler)
	f := new(Flow)
	limit := netproxy.DatagramMemory.UseLimit(1)
	defer limit.Close()
	if allocations := testing.AllocsPerRun(100, func() {
		if frame := s.AllocateDatagram(f, epoch, 65535, false); frame != nil {
			t.Fatal("admitted a datagram without budget")
		}
	}); allocations != 0 {
		t.Fatalf("rejected admission allocated %v copies", allocations)
	}
}
