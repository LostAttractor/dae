// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"sync"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

const (
	udpTaskQueueLength = 128
	udpTaskMaxWorkers  = 128
	udpTaskMaxSources  = 2048
	udpTaskMaxPending  = 8192
)

type udpTask = func()

type queuedUDPTask struct {
	run    udpTask
	packet udpPacket
	next   *queuedUDPTask
}

// A source is either being processed by one worker or on the ready list.
// Only pending tasks retain a queue; NAT association lifetime is independent.
type udpTaskQueue[K comparable] struct {
	key        K
	head, tail *queuedUDPTask
	pending    int
	next       *udpTaskQueue[K]
}

type udpTaskPool[K comparable] struct {
	mu                               sync.Mutex
	ready                            *sync.Cond
	queues                           map[K]*udpTaskQueue[K]
	head, tail                       *udpTaskQueue[K]
	workers                          int
	workersDone                      sync.WaitGroup
	closed                           bool
	tasks                            int // Accepted tasks, including those currently running.
	memory                           *membuffer.Budget
	drops                            udpPacketDrops
	maxWorkers, maxSources, maxTasks int
}

func newUdpTaskPool[K comparable]() *udpTaskPool[K] {
	p := &udpTaskPool[K]{
		queues: make(map[K]*udpTaskQueue[K]), memory: udpPacketMemory,
		maxWorkers: udpTaskMaxWorkers, maxSources: udpTaskMaxSources, maxTasks: udpTaskMaxPending,
	}
	p.ready = sync.NewCond(&p.mu)
	return p
}

// emit checks capacity before copying the borrowed datagram or preparing work.
// prepare runs synchronously under the pool lock and must only construct the
// task, without blocking or reentering the pool. The task may use the owned
// datagram until it returns; the pool then releases its buffer and budget.
func (p *udpTaskPool[K]) emit(key K, data []byte, prepare func([]byte) udpTask) bool {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return false
	}
	q := p.queues[key]
	reason := ""
	switch {
	case q != nil && q.pending == udpTaskQueueLength:
		reason = "source_queue_full"
	case p.tasks == p.maxTasks:
		reason = "task_limit"
	case q == nil && len(p.queues) == p.maxSources:
		reason = "source_limit"
	}
	if reason != "" {
		p.mu.Unlock()
		p.drops.report(reason)
		return false
	}
	packet, ok := copyUDPPacket(data, p.memory)
	if !ok {
		p.mu.Unlock()
		p.drops.report("packet_memory_limit")
		return false
	}
	task := &queuedUDPTask{run: prepare(packet.data), packet: packet}
	if q == nil {
		q = &udpTaskQueue[K]{key: key}
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
		p.workersDone.Go(p.run)
	}
	p.ready.Signal()
	p.mu.Unlock()
	return true
}

// enqueue appends a source to the round-robin ready list with mu held.
func (p *udpTaskPool[K]) enqueue(q *udpTaskQueue[K]) {
	if p.tail == nil {
		p.head = q
	} else {
		p.tail.next = q
	}
	p.tail = q
}

func (p *udpTaskPool[K]) run() {
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
		task.run()
		task.packet.release()
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

// close rejects new tasks and waits for all accepted tasks to release their
// resources. Concurrent callers wait for the same workers.
func (p *udpTaskPool[K]) close() {
	p.mu.Lock()
	p.closed = true
	p.ready.Broadcast()
	p.mu.Unlock()
	p.workersDone.Wait()
}
