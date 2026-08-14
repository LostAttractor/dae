/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	udpTaskQueueLength           = 128
	udpTaskSaturationLogInterval = time.Minute
)

type udpTask = func()

// udpTaskQueue executes tasks for one key in acceptance order.
type udpTaskQueue[K comparable] struct {
	key       K
	pool      *udpTaskPool[K]
	tasks     chan udpTask
	agingTime time.Duration
	done      chan struct{}
}

func (q *udpTaskQueue[K]) run() {
	timer := time.NewTimer(q.agingTime)
	defer func() {
		timer.Stop()
		close(q.done)
	}()
	for {
		select {
		case task, ok := <-q.tasks:
			if !ok {
				return
			}
			task()
			timer.Reset(q.agingTime)
		case <-timer.C:
			q.pool.mu.Lock()
			// emit may have queued work after the timer fired but before run
			// acquired the pool lock. Keep the queue in that case.
			if len(q.tasks) != 0 {
				timer.Reset(q.agingTime)
				q.pool.mu.Unlock()
				continue
			}
			if q.pool.queues[q.key] == q {
				delete(q.pool.queues, q.key)
			}
			q.pool.mu.Unlock()
			return
		}
	}
}

type udpTaskPool[K comparable] struct {
	mu        sync.Mutex
	queues    map[K]*udpTaskQueue[K]
	agingTime time.Duration
	closed    bool
	closeOnce sync.Once

	lastSaturationLog atomic.Int64
}

func newUdpTaskPool[K comparable](agingTime time.Duration) *udpTaskPool[K] {
	return &udpTaskPool[K]{
		queues:    make(map[K]*udpTaskQueue[K]),
		agingTime: agingTime,
	}
}

// emit transfers ownership of task and its captured resources when it returns
// true. A false result means the caller retains ownership and task will not run.
func (p *udpTaskPool[K]) emit(key K, task udpTask) bool {
	p.mu.Lock()

	if p.closed {
		p.mu.Unlock()
		return false
	}
	q, ok := p.queues[key]
	if !ok {
		q = &udpTaskQueue[K]{
			key:       key,
			pool:      p,
			tasks:     make(chan udpTask, udpTaskQueueLength),
			agingTime: p.agingTime,
			done:      make(chan struct{}),
		}
		p.queues[key] = q
		go q.run()
	}
	select {
	case q.tasks <- task:
		p.mu.Unlock()
		return true
	default:
		p.mu.Unlock()
		p.reportSaturation()
		return false
	}
}

func (p *udpTaskPool[K]) reportSaturation() {
	now := time.Now().UnixNano()
	for {
		last := p.lastSaturationLog.Load()
		if last != 0 && now >= last && now-last < int64(udpTaskSaturationLogInterval) {
			return
		}
		if p.lastSaturationLog.CompareAndSwap(last, now) {
			log.Warn("UDP task queue full; dropping packet")
			return
		}
	}
}

// close rejects new tasks and waits for all accepted tasks to finish.
func (p *udpTaskPool[K]) close() {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		queues := make([]*udpTaskQueue[K], 0, len(p.queues))
		for _, q := range p.queues {
			queues = append(queues, q)
			close(q.tasks)
		}
		clear(p.queues)
		p.mu.Unlock()

		for _, q := range queues {
			<-q.done
		}
	})
}
