// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

const (
	udpTaskQueueLength = 128
	udpTaskMaxWorkers  = 128
	udpTaskMaxSources  = 2048
	udpTaskMaxPending  = 8192
)

type queuedUDPTask struct {
	work   udpPacketWork
	packet udpPacket
	next   *queuedUDPTask
}

var queuedUDPTasks = sync.Pool{New: func() any { return new(queuedUDPTask) }}

// A source is either being processed by one worker or on the ready list.
// Only pending tasks retain a queue; NAT association lifetime is independent.
type udpTaskQueue struct {
	key        netip.AddrPort
	head, tail *queuedUDPTask
	pending    int
	next       *udpTaskQueue
}

// udpWriteSlot publishes a worker's in-flight transport write, so cancelling
// the generation interrupts it without the source lock or per-packet timers.
type udpWriteSlot struct {
	mu   sync.Mutex
	conn net.PacketConn
}

// begin publishes conn before rechecking ctx. Paired with interrupt's
// cancel-then-scan, either the scan sees this write or ctx is already done.
// A nil slot (outside a pool worker) only checks ctx.
func (s *udpWriteSlot) begin(ctx context.Context, conn net.PacketConn) error {
	if s != nil {
		s.mu.Lock()
		s.conn = conn
		s.mu.Unlock()
	}
	if err := ctx.Err(); err != nil {
		s.end()
		return err
	}
	return nil
}

func (s *udpWriteSlot) end() {
	if s != nil {
		s.mu.Lock()
		s.conn = nil
		s.mu.Unlock()
	}
}

// interrupt wakes a deadline-aware write at once and closes the socket without
// waiting for Close. The writer's deadline reset is ordered after it by mu.
func (s *udpWriteSlot) interrupt() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		_ = s.conn.SetWriteDeadline(time.Now())
		closeInBackground(s.conn)
	}
}

type udpTaskPool struct {
	// Cancel packet work independently of ingress, which still delivers QUIC
	// packets during MITM's graceful shutdown.
	ctx                              context.Context
	cancel                           context.CancelFunc
	mu                               sync.Mutex
	ready                            *sync.Cond
	queues                           map[netip.AddrPort]*udpTaskQueue
	head, tail                       *udpTaskQueue
	execute                          func(udpPacketWork, *udpWriteSlot, []byte)
	workers                          int
	slots                            []*udpWriteSlot // One per worker, appended with mu held.
	workersDone                      sync.WaitGroup
	closed                           bool
	tasks                            int // Accepted tasks, including those currently running.
	memory                           *membuffer.Budget
	maxWorkers, maxSources, maxTasks int
}

func newUdpTaskPool(execute func(udpPacketWork, *udpWriteSlot, []byte)) *udpTaskPool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &udpTaskPool{
		ctx: ctx, cancel: cancel,
		queues: make(map[netip.AddrPort]*udpTaskQueue), memory: udpPacketMemory,
		execute:    execute,
		maxWorkers: udpTaskMaxWorkers, maxSources: udpTaskMaxSources, maxTasks: udpTaskMaxPending,
	}
	p.ready = sync.NewCond(&p.mu)
	return p
}

// emit checks capacity before copying the borrowed datagram. A worker may move
// its packet to the next owner; the pool releases only what it still owns.
func (p *udpTaskPool) emit(data []byte, work udpPacketWork) bool {
	packet := udpPacket{data: data, deadline: work.deadline}
	return p.emitPacket(&packet, work)
}

func (p *udpTaskPool) emitPacket(packet *udpPacket, work udpPacketWork) bool {
	key := work.src
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		return false
	}
	q := p.queues[key]
	var drop *netproxy.Drop
	switch {
	case q != nil && q.pending == udpTaskQueueLength:
		drop = dropSourceQueue
	case p.tasks == p.maxTasks:
		drop = dropTaskLimit
	case q == nil && len(p.queues) == p.maxSources:
		drop = dropSourceLimit
	}
	if drop != nil {
		p.mu.Unlock()
		drop.Add(1)
		return false
	}
	owned, ok := packet.take(p.memory)
	if !ok {
		p.mu.Unlock()
		dropUploadMemory.Add(1)
		return false
	}
	task := queuedUDPTasks.Get().(*queuedUDPTask)
	work.deadline = owned.deadline
	task.packet, task.work = owned, work
	if q == nil {
		q = &udpTaskQueue{key: key}
		p.queues[key] = q
		p.enqueue(q)
	}
	if q.tail == nil {
		q.head = task
	} else {
		q.tail.next = task
	}
	q.tail = task
	q.pending++
	p.tasks++
	// Grow lazily to the number of active sources, with a fixed upper bound.
	// Workers wait on one shared condition; idle sources retain no workers.
	if p.workers < min(p.maxWorkers, len(p.queues)) {
		p.workers++
		slot := new(udpWriteSlot)
		p.slots = append(p.slots, slot)
		p.workersDone.Go(func() { p.run(slot) })
	}
	p.ready.Signal()
	p.mu.Unlock()
	return true
}

// enqueue appends a source to the round-robin ready list with mu held.
func (p *udpTaskPool) enqueue(q *udpTaskQueue) {
	if p.tail == nil {
		p.head = q
	} else {
		p.tail.next = q
	}
	p.tail = q
}

func (p *udpTaskPool) run(slot *udpWriteSlot) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		for p.head == nil && !p.closed {
			p.ready.Wait()
		}
		if p.head == nil {
			return
		}
		q := p.head
		p.head, q.next = q.next, nil
		if p.head == nil {
			p.tail = nil
		}
		task := q.head
		q.head = task.next
		if q.head == nil {
			q.tail = nil
		}
		q.pending--
		p.mu.Unlock()
		if p.ctx.Err() == nil {
			work := task.work
			work.packet = &task.packet
			p.execute(work, slot, task.packet.data)
		}
		task.packet.release()
		*task = queuedUDPTask{}
		queuedUDPTasks.Put(task)
		p.mu.Lock()
		p.tasks--
		if q.head == nil {
			delete(p.queues, q.key)
		} else {
			// One packet per turn: a busy source cannot monopolize a worker.
			p.enqueue(q)
			p.ready.Signal()
		}
	}
}

// interrupt cancels the pool's work, then interrupts writes already in flight:
// lifecycle callers next take the source locks those writes hold.
func (p *udpTaskPool) interrupt() {
	p.cancel()
	p.mu.Lock()
	slots := p.slots
	p.mu.Unlock()
	for _, slot := range slots {
		slot.interrupt()
	}
}

// close rejects new tasks and waits for all accepted tasks to release their
// resources. Concurrent callers wait for the same workers.
func (p *udpTaskPool) close() {
	p.mu.Lock()
	p.closed = true
	p.ready.Broadcast()
	p.mu.Unlock()
	p.workersDone.Wait()
	p.cancel()
}
