/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

const UdpTaskQueueLength = 128

type UdpTask = func()

// UdpTaskQueue make sure packets with the same key (4 tuples) will be sent in order.
type UdpTaskQueue[K comparable] struct {
	key       K
	p         *UdpTaskPool[K]
	ch        chan UdpTask
	timer     *time.Timer
	agingTime time.Duration
	ctx       context.Context
	closed    chan struct{}
}

// TODO: Timout?
func (q *UdpTaskQueue[K]) convoy() {
	for {
		select {
		case <-q.ctx.Done():
			close(q.closed)
			return
		case task := <-q.ch:
			task()
			q.timer.Reset(q.agingTime)
		}
	}
}

type UdpTaskPool[K comparable] struct {
	queueChPool sync.Pool
	// mu protects m
	mu sync.Mutex
	m  map[K]*UdpTaskQueue[K]
}

func NewUdpTaskPool[K comparable]() *UdpTaskPool[K] {
	p := &UdpTaskPool[K]{
		queueChPool: sync.Pool{New: func() any {
			return make(chan UdpTask, UdpTaskQueueLength)
		}},
		m: make(map[K]*UdpTaskQueue[K]),
	}
	return p
}

// EmitTask: Make sure packets with the same key (4 tuples) will be sent in order.
func (p *UdpTaskPool[K]) EmitTask(key K, task UdpTask) {
	p.mu.Lock()
	q, ok := p.m[key]
	if !ok {
		ch := p.queueChPool.Get().(chan UdpTask)
		ctx, cancel := context.WithCancel(context.Background())
		q = &UdpTaskQueue[K]{
			key:       key,
			p:         p,
			ch:        ch,
			timer:     nil,
			agingTime: DefaultNatTimeoutUDP,
			ctx:       ctx,
			closed:    make(chan struct{}),
		}
		q.timer = time.AfterFunc(q.agingTime, func() {
			// if timer executed, there should no task in queue.
			// q.closed should not blocking things.
			p.mu.Lock()
			cancel()
			delete(p.m, key)
			p.mu.Unlock()
			<-q.closed
			if len(ch) == 0 { // Otherwise let it to be gc
				p.queueChPool.Put(ch)
			}
		})
		p.m[key] = q
		go q.convoy()
	}
	p.mu.Unlock()
	// if task cannot be executed within 180s(DefaultNatTimeout), GC may be triggered, so skip the task when GC occurs
	select {
	case q.ch <- task:
		// OK
	default:
		// Channel full, drop the packet
	}
}

// 目前没有实现在遇到连接错误时将节点设置为不可用
// 因此一旦节点失效，将必然最终导致队列拥塞，导致阻塞所有新连接

var (
	DefaultUdpTaskPool = NewUdpTaskPool[netip.AddrPort]()
)
