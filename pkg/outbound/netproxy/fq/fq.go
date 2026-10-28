// Package fq schedules the frames of the flows that share one carrier as
// fq_codel schedules packets on a link (sch_fq_codel.c): deficit round robin
// by bytes, first over flows that just turned busy, then over the rest, and
// CoDel on the datagrams of each flow. The carrier's own congestion control
// paces it; the scheduler decides whose bytes go next, drops datagrams that
// waited too long, and makes stream writers wait instead.
package fq

import (
	"math"
	"time"

	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

const (
	// Quantum is the bytes a flow may send per round, about one Ethernet
	// frame: a round over n busy flows then lasts n frame times, so that
	// CoDel acts only on flows above their fair share.
	Quantum = 1514
	// Target is the sojourn CoDel lets a datagram flow keep; Interval, how
	// long it may stay above before drops start, is about the RTT of the
	// inner flows (carrier RTT plus the server's path to the target).
	Target   = 5 * time.Millisecond
	Interval = 100 * time.Millisecond
	// A flow queues at most FlowDatagramLimit bytes of datagrams, and the
	// flows of a scheduler CarrierDatagramLimit; beyond either, the oldest
	// datagrams go, from the flow itself or else from the fattest flow.
	FlowDatagramLimit    = 64 << 10
	CarrierDatagramLimit = 256 << 10
	// StreamLimit bounds the buffer capacity of a flow's queued stream
	// frames; then its writer waits, unless the flow has nothing queued.
	StreamLimit = 64 << 10
	// The rate estimate weighs each sample by its duration over rateTime.
	rateTime = 50 * time.Millisecond
)

var (
	dropCoDel            = netproxy.NewDrop(netproxy.DropUpload, "codel")
	dropFlowQueueFull    = netproxy.DropFlowQueueFull
	dropCarrierQueueFull = netproxy.DropCarrierQueueFull
)

type kind uint8

const (
	stream   kind = iota
	datagram      // may be dropped
	forced        // a datagram that must not be dropped
)

type entry struct {
	frame  []byte
	at     time.Time
	kind   kind
	memory membuffer.Reservation
}

type list uint8

const (
	unlisted list = iota
	newFlows
	oldFlows
)

// Flow is the queue of one flow, a stream or an association. Its zero value
// is empty; the Scheduler it is used with owns it.
type Flow struct {
	queue   FIFO[entry]
	list    list
	deficit int
	// stream is the capacity of the queued stream frames; datagrams the
	// length of the queued datagrams, forced the length of those among
	// them that must not be dropped.
	stream, datagrams, forced int
	inflight                  int // stream buffer capacity still held by the writer
	writable                  chan struct{}
	codel                     codel
}

// codel is the CoDel state of a flow (codel.h).
type codel struct {
	dropping             bool
	count, lastCount     int
	firstAbove, dropNext time.Time
}

// Writable is signalled whenever stream frames of the flow leave its queue.
func (f *Flow) Writable() <-chan struct{} {
	if f.writable == nil {
		f.writable = make(chan struct{}, 1)
	}
	return f.writable
}

// Full reports whether a stream frame of capacity n must wait: the flow
// already queues stream frames and n would take them past StreamLimit.
func (f *Flow) Full(n int) bool { return f.stream > 0 && f.stream+n > StreamLimit }

// Available is the remaining queued stream capacity; the one carrier batch
// is accounted separately until ReleaseBatch.
func (f *Flow) Available() int { return max(0, StreamLimit-f.stream) }

// Buffered includes queued and in-flight stream buffer capacity.
func (f *Flow) Buffered() int { return f.stream + f.inflight }

// WakeWriter passes space on to another writer of the flow after a write
// used only part of what a dequeue made available.
func (f *Flow) WakeWriter() {
	if f.writable != nil && !f.Full(1) {
		select {
		case f.writable <- struct{}{}:
		default:
		}
	}
}

// Tail returns the flow's last queued frame if it is a stream frame, which
// the caller may extend within its capacity; nil otherwise. It is valid
// until the next change to the scheduler.
func (f *Flow) Tail() *[]byte {
	if f.queue.Len() == 0 || f.queue.Last().kind != stream {
		return nil
	}
	return &f.queue.Last().frame
}

// Scheduler orders the frames of its flows. It is not safe for concurrent
// use; its user serialises calls, with those to its flows.
type Scheduler struct {
	// Release takes back a complete buffer after writing, dropping or clearing.
	Release func([]byte)
	// Delay, if set, observes how long each datagram sent had waited.
	Delay *netproxy.QueueDelay

	new, old          FIFO[*Flow]
	entries           int
	datagrams         int
	inflight          []heldFrame // complete buffers borrowed by the outstanding batch
	partial           heldFrame   // a started frame must finish before any other frame
	offset            int
	borrowed, cleared bool
	// rate is the estimate, in bytes per second, of how fast Take's frames
	// leave while frames wait; taken bytes left at lastTake.
	rate     float64
	lastTake time.Time
	taken    int
	backlog  bool
}

type heldFrame struct {
	flow *Flow
	entry
}

// Queued reports whether frames are queued.
func (s *Scheduler) Queued() bool { return s.entries > 0 || s.partial.frame != nil }

// Push queues a stream frame of f behind its earlier frames. It never
// drops; writers check Full first.
func (s *Scheduler) Push(f *Flow, frame []byte) {
	f.stream += cap(frame)
	s.enqueue(f, entry{frame: frame, kind: stream})
}

// Offer queues a datagram of f that arrived at now and never waits. The
// datagram is one buffer, even if the protocol frames it several times, so
// that it is sent or dropped whole. The flow and the carrier then make
// room from their oldest datagrams if they exceed their limits. It reports
// false, having dropped and released the frame, only if the datagram memory
// cannot hold it even after the fattest flow made room.
func (s *Scheduler) Offer(f *Flow, now time.Time, frame []byte) bool {
	memory, ok := s.reserveDatagram(cap(frame))
	if !ok {
		s.release(frame)
		return false
	}
	s.queueDatagram(f, entry{frame: frame, at: now, kind: datagram, memory: memory})
	return true
}

// Force protects an admitted request from queue eviction and CoDel. Admission
// still respects the shared memory limit; rejection releases frame.
func (s *Scheduler) Force(f *Flow, now time.Time, frame []byte) bool {
	memory, ok := s.reserveDatagram(cap(frame))
	if !ok {
		s.release(frame)
		return false
	}
	f.forced += len(frame)
	s.queueDatagram(f, entry{frame: frame, at: now, kind: forced, memory: memory})
	return true
}

// AllocateDatagram reserves memory before getting and queueing a pooled
// buffer. The caller fills it while still holding the scheduler's lock,
// before any further operation on the scheduler. Nil means memory admission
// failed, without allocating a copy of the borrowed datagram.
func (s *Scheduler) AllocateDatagram(f *Flow, now time.Time, size int, force bool) []byte {
	memory, ok := s.reserveDatagram(pool.BufferCapacity(size))
	if !ok {
		return nil
	}
	frame := pool.GetBuffer(size)
	k := datagram
	if force {
		k = forced
		f.forced += len(frame)
	}
	s.queueDatagram(f, entry{frame: frame, at: now, kind: k, memory: memory})
	return frame
}

func (s *Scheduler) reserveDatagram(size int) (membuffer.Reservation, bool) {
	for {
		if memory, err := netproxy.DatagramMemory.Reserve(int64(size)); err == nil {
			return memory, true
		}
		if int64(size) > netproxy.DatagramMemory.Status().Limit {
			break
		}
		g := s.fattest(nil, 0)
		if g == nil {
			break
		}
		s.dropOldest(g, false, netproxy.DropUploadMemory)
	}
	netproxy.DropUploadMemory.Add(1)
	return membuffer.Reservation{}, false
}

func (s *Scheduler) queueDatagram(f *Flow, e entry) {
	f.datagrams += len(e.frame)
	s.datagrams += len(e.frame)
	s.enqueue(f, e)
	// The new datagram stays: a flow that queued nothing always gets one in.
	keep, keepTail := 0, e.kind == datagram
	if keepTail {
		keep = len(e.frame)
	}
	for f.datagrams > FlowDatagramLimit && f.datagrams-f.forced > keep {
		s.dropOldest(f, keepTail, dropFlowQueueFull)
	}
	for s.datagrams > CarrierDatagramLimit {
		g := s.fattest(f, keep)
		if g == nil {
			break
		}
		s.dropOldest(g, keepTail && g == f, dropCarrierQueueFull)
	}
}

func (s *Scheduler) enqueue(f *Flow, e entry) {
	f.queue.Push(e)
	s.entries++
	if f.list == unlisted {
		f.list, f.deficit = newFlows, Quantum
		s.new.Push(f)
	}
}

// fattest returns the flow with the most bytes of datagrams that may be
// dropped, not counting the keep bytes of f's newest, or nil if none.
func (s *Scheduler) fattest(f *Flow, keep int) *Flow {
	var fattest *Flow
	most := 0
	for _, flows := range [...]*FIFO[*Flow]{&s.new, &s.old} {
		for g := range flows.All() {
			n := g.datagrams - g.forced
			if g == f {
				n -= keep
			}
			if n > most {
				fattest, most = g, n
			}
		}
	}
	return fattest
}

// dropOldest drops the oldest datagram of f that may be dropped, short of
// its newest frame if keepTail.
func (s *Scheduler) dropOldest(f *Flow, keepTail bool, reason *netproxy.Drop) {
	n := f.queue.Len()
	if keepTail {
		n--
	}
	for i := range n {
		if f.queue.items[f.queue.head+i].kind == datagram {
			s.free(f, f.queue.remove(i))
			reason.Add(1)
			return
		}
	}
}

// free accounts an entry that left f without being sent.
func (s *Scheduler) free(f *Flow, e entry) {
	s.unqueue(f, e)
	if e.kind != stream {
		e.memory.Close()
	}
	s.release(e.frame)
}

func (s *Scheduler) unqueue(f *Flow, e entry) {
	s.entries--
	if f.queue.Len() == 0 {
		f.codel.firstAbove = time.Time{}
		f.codel.dropping = false
	}
	if e.kind == stream {
		f.stream -= cap(e.frame)
		if f.writable != nil {
			select {
			case f.writable <- struct{}{}:
			default:
			}
		}
		return
	}
	f.datagrams -= len(e.frame)
	s.datagrams -= len(e.frame)
	if e.kind == forced {
		f.forced -= len(e.frame)
	}
}

// ReleaseBatch releases the buffers borrowed by the last Take. Clear never
// releases a buffer still borrowed by the writer, including a partial frame.
func (s *Scheduler) ReleaseBatch() {
	for i, h := range s.inflight {
		s.releaseHeld(h)
		s.inflight[i] = heldFrame{}
	}
	s.inflight = s.inflight[:0]
	s.borrowed = false
	if s.cleared && s.partial.frame != nil {
		s.releaseHeld(s.partial)
		s.partial, s.offset = heldFrame{}, 0
	}
}

func (s *Scheduler) releaseHeld(h heldFrame) {
	if h.kind == stream {
		h.flow.inflight -= cap(h.frame)
	} else {
		h.memory.Close()
	}
	s.release(h.frame)
}

func (s *Scheduler) release(frame []byte) {
	if s.Release != nil {
		s.Release(frame)
	}
}

// Take borrows up to want bytes, filling across frame boundaries. A partial
// frame leads the next batch, even if another flow becomes ready meanwhile.
// The caller must ReleaseBatch after writing, before the next Take.
func (s *Scheduler) Take(now time.Time, want int, batch [][]byte) [][]byte {
	if s.backlog {
		// The frames taken last left while others waited: they went at the
		// carrier's pace.
		if dt := now.Sub(s.lastTake); dt > 0 {
			s.rate += (float64(s.taken)/dt.Seconds() - s.rate) * min(1, float64(dt)/float64(rateTime))
		}
	}
	size := 0
	s.borrowed, s.cleared = true, false
	for size < want {
		if s.partial.frame != nil {
			n := min(want-size, len(s.partial.frame)-s.offset)
			batch = append(batch, s.partial.frame[s.offset:s.offset+n])
			size, s.offset = size+n, s.offset+n
			if s.offset == len(s.partial.frame) {
				s.inflight = append(s.inflight, s.partial)
				s.partial, s.offset = heldFrame{}, 0
			}
			continue
		}
		flows := &s.new
		if flows.Len() == 0 {
			if flows = &s.old; flows.Len() == 0 {
				break
			}
		}
		f := flows.Peek()
		if f.deficit <= 0 {
			f.deficit += Quantum
			flows.Pop()
			f.list = oldFlows
			s.old.Push(f)
			continue
		}
		e, ok := s.dequeue(f, now)
		if !ok {
			flows.Pop()
			// A flow leaving the new list passes through the old one, so
			// that a flow turning busy again does not starve the old ones.
			if flows == &s.new && s.old.Len() > 0 {
				f.list = oldFlows
				s.old.Push(f)
			} else {
				f.list = unlisted
			}
			continue
		}
		f.deficit -= len(e.frame)
		s.partial = heldFrame{flow: f, entry: e}
	}
	s.lastTake, s.taken, s.backlog = now, size, s.Queued()
	return batch
}

// dequeue takes the next frame of f, applying CoDel to its datagrams as
// codel_dequeue does (codel_impl.h).
func (s *Scheduler) dequeue(f *Flow, now time.Time) (entry, bool) {
	c := &f.codel
	drop := s.overTarget(f, now)
	switch {
	case c.dropping && !drop:
		c.dropping = false
	case c.dropping:
		for c.dropping && !now.Before(c.dropNext) {
			c.count++
			s.dropHead(f)
			if !s.overTarget(f, now) {
				c.dropping = false
			} else {
				c.dropNext = controlLaw(c.dropNext, c.count)
			}
		}
	case drop:
		s.dropHead(f)
		s.overTarget(f, now)
		c.dropping = true
		// Reentering the dropping state soon after leaving it resumes near
		// the drop rate that controlled the queue then.
		if delta := c.count - c.lastCount; delta > 1 && now.Sub(c.dropNext) < 16*Interval {
			c.count = delta
		} else {
			c.count = 1
		}
		c.lastCount = c.count
		c.dropNext = controlLaw(now, c.count)
	}
	if f.queue.Len() == 0 {
		c.dropping = false
		return entry{}, false
	}
	e := f.queue.Pop()
	s.unqueue(f, e)
	if e.kind == stream {
		f.inflight += cap(e.frame)
	} else {
		if s.Delay != nil {
			s.Delay.Observe(now.Sub(e.at))
		}
	}
	return e, true
}

// overTarget reports whether CoDel may drop the head of f (codel_should_drop):
// a datagram whose sojourn has stayed above target for an interval. With
// cake's guard (sch_cake.c), a sojourn within twice a frame time per bulk
// flow, or four frame times, is not above target: on a carrier shared by
// many flows, this estimates fair-share waiting. Large batches or stream
// frames can still make a flow at its average fair share exceed the guard.
func (s *Scheduler) overTarget(f *Flow, now time.Time) bool {
	c := &f.codel
	if f.queue.Len() == 0 || f.queue.Peek().kind != datagram {
		c.firstAbove = time.Time{}
		return false
	}
	sojourn := now.Sub(f.queue.Peek().at)
	var frameTime time.Duration
	if s.rate > 0 {
		frameTime = time.Duration(Quantum / s.rate * float64(time.Second))
	}
	if sojourn <= Target || sojourn <= 2*frameTime*time.Duration(s.old.Len()) || sojourn <= 4*frameTime || f.datagrams <= Quantum {
		c.firstAbove = time.Time{}
		return false
	}
	if c.firstAbove.IsZero() {
		c.firstAbove = now.Add(Interval)
		return false
	}
	return now.After(c.firstAbove)
}

func (s *Scheduler) dropHead(f *Flow) {
	s.free(f, f.queue.Pop())
	dropCoDel.Add(1)
}

// controlLaw schedules the next drop interval/√count after t.
func controlLaw(t time.Time, count int) time.Time {
	return t.Add(time.Duration(float64(Interval) / math.Sqrt(float64(count))))
}

// Clear releases every queued frame without counting a drop, as when the
// carrier is gone.
func (s *Scheduler) Clear() {
	s.cleared = true
	if !s.borrowed && s.partial.frame != nil {
		s.releaseHeld(s.partial)
		s.partial, s.offset = heldFrame{}, 0
	}
	for _, flows := range [...]*FIFO[*Flow]{&s.new, &s.old} {
		for flows.Len() > 0 {
			f := flows.Pop()
			for f.queue.Len() > 0 {
				s.free(f, f.queue.Pop())
			}
			f.list, f.codel = unlisted, codel{}
		}
	}
	s.backlog = false
}
