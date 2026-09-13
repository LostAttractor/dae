/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/stretchr/testify/require"
)

func emitUDPTask[K comparable](pool *udpTaskPool[K], key K, task udpTask) bool {
	return pool.emit(key, nil, func([]byte) udpTask { return task })
}

func testUdpKey(port uint16) netip.AddrPort {
	return netip.MustParseAddrPort(fmt.Sprintf("10.0.0.1:%d", port))
}

func TestUdpTaskPool_TaskExecution(t *testing.T) {
	pool := newUdpTaskPool[netip.AddrPort]()
	t.Cleanup(pool.close)
	key := testUdpKey(10001)

	done := make(chan struct{})
	require.True(t, emitUDPTask(pool, key, func() { close(done) }))

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("task was not executed")
	}
}

func TestUdpTaskPool_TasksWithSameKeyAreOrdered(t *testing.T) {
	pool := newUdpTaskPool[netip.AddrPort]()
	t.Cleanup(pool.close)
	key := testUdpKey(10002)

	const n = 100
	var mu sync.Mutex
	executed := make([]int, 0, n)
	done := make(chan struct{})
	for i := range n {
		emitUDPTask(pool, key, func() {
			mu.Lock()
			executed = append(executed, i)
			mu.Unlock()
			if i == n-1 {
				close(done)
			}
		})
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("tasks were not fully executed")
	}
	for i := range n {
		if executed[i] != i {
			t.Fatalf("tasks executed out of order: executed[%v] = %v", i, executed[i])
		}
	}
}

func TestUdpTaskPool_DropWhenQueueFull(t *testing.T) {
	pool := newUdpTaskPool[netip.AddrPort]()
	t.Cleanup(pool.close)
	key := testUdpKey(10003)

	// Block the convoy goroutine so the queue channel can be filled.
	unblock := make(chan struct{})
	var unblockOnce sync.Once
	release := func() { unblockOnce.Do(func() { close(unblock) }) }
	t.Cleanup(release)
	started := make(chan struct{})
	require.True(t, emitUDPTask(pool, key, func() {
		close(started)
		<-unblock
	}))
	<-started

	// Fill the queue channel.
	for range udpTaskQueueLength {
		require.True(t, emitUDPTask(pool, key, func() {}))
	}

	// The queue is full now: this task should be dropped instead of blocking.
	emitDone := make(chan bool)
	go func() {
		emitDone <- emitUDPTask(pool, key, func() {})
	}()
	select {
	case accepted := <-emitDone:
		require.False(t, accepted)
	case <-time.After(3 * time.Second):
		t.Fatal("EmitTask blocked on a full queue")
	}
	firstLog := pool.drops.lastLog.Load()
	require.NotZero(t, firstLog, "queue saturation was not reported")
	require.False(t, emitUDPTask(pool, key, func() {}))
	require.Equal(t, firstLog, pool.drops.lastLog.Load(), "queue saturation warning was not rate limited")
	futureLog := time.Now().Add(time.Hour).UnixNano()
	pool.drops.lastLog.Store(futureLog)
	pool.drops.report("source_queue_full")
	require.Less(t, pool.drops.lastLog.Load(), futureLog, "clock rollback suppressed saturation warnings")
	release()
}

func TestUdpTaskPool_ReleasesIdleSources(t *testing.T) {
	pool := newUdpTaskPool[int]()
	t.Cleanup(pool.close)
	pool.memory = membuffer.NewBudget(4096)
	for i := range 100 {
		done := make(chan struct{})
		require.True(t, pool.emit(i, []byte("packet"), func([]byte) udpTask {
			return func() { close(done) }
		}))
		<-done
	}
	require.Eventually(t, func() bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		return len(pool.queues) == 0 && pool.tasks == 0 && pool.memory.Status().Used == 0
	}, time.Second, time.Millisecond)
	// Reusing an idle source must create a fresh queue and remain executable.
	done := make(chan struct{})
	require.True(t, emitUDPTask(pool, 0, func() { close(done) }))
	<-done
}

func TestUdpTaskPool_CloseDrainsAcceptedTasks(t *testing.T) {
	pool := newUdpTaskPool[netip.AddrPort]()
	key := testUdpKey(10005)
	started := make(chan struct{})
	unblock := make(chan struct{})
	secondDone := make(chan struct{})
	require.True(t, emitUDPTask(pool, key, func() {
		close(started)
		<-unblock
	}))
	<-started
	require.True(t, emitUDPTask(pool, key, func() { close(secondDone) }))

	closeDone := make(chan struct{})
	go func() {
		pool.close()
		close(closeDone)
	}()
	require.Eventually(t, func() bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		return pool.closed
	}, time.Second, time.Millisecond)
	require.False(t, emitUDPTask(pool, key, func() {}), "closed pool accepted a task")
	select {
	case <-closeDone:
		t.Fatal("Close returned before accepted tasks finished")
	case <-time.After(20 * time.Millisecond):
	}

	close(unblock)
	select {
	case <-secondDone:
	case <-time.After(3 * time.Second):
		t.Fatal("accepted task was not executed during Close")
	}
	select {
	case <-closeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return after accepted tasks finished")
	}
}

func TestUdpTaskPool_ConcurrentEmitAndClose(t *testing.T) {
	pool := newUdpTaskPool[netip.AddrPort]()
	key := testUdpKey(10006)
	start := make(chan struct{})
	var producers sync.WaitGroup
	var accepted atomic.Int64
	var executed atomic.Int64
	for range 8 {
		producers.Go(func() {
			<-start
			for range 100 {
				if emitUDPTask(pool, key, func() { executed.Add(1) }) {
					accepted.Add(1)
				}
			}
		})
	}

	close(start)
	closeDone := make(chan struct{})
	go func() {
		pool.close()
		close(closeDone)
	}()
	producers.Wait()
	<-closeDone
	require.Equal(t, accepted.Load(), executed.Load())
	require.False(t, emitUDPTask(pool, key, func() {}))
}

func TestUdpTaskPool_RoundRobin(t *testing.T) {
	p := newUdpTaskPool[string]()
	p.maxWorkers = 1
	t.Cleanup(p.close)
	started, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(unblock) }) }
	t.Cleanup(release)
	require.True(t, emitUDPTask(p, "busy", func() { close(started); <-unblock }))
	<-started
	var order []string
	for range 3 {
		require.True(t, emitUDPTask(p, "busy", func() { order = append(order, "busy") }))
		require.True(t, emitUDPTask(p, "other", func() { order = append(order, "other") }))
	}
	require.True(t, emitUDPTask(p, "third", func() { order = append(order, "third") }))
	release()
	p.close()
	require.Equal(t, []string{"other", "third", "busy", "other", "busy", "other", "busy"}, order)
}

func TestUdpTaskPool_AdmissionBeforePreparing(t *testing.T) {
	for _, limit := range []string{"sources", "tasks", "memory"} {
		t.Run(limit, func(t *testing.T) {
			p := newUdpTaskPool[int]()
			p.maxWorkers = 1
			p.memory = membuffer.NewBudget(64)
			t.Cleanup(p.close)
			switch limit {
			case "sources":
				p.maxSources = 1
			case "tasks":
				p.maxTasks = 1
			case "memory":
				p.memory = membuffer.NewBudget(8)
			}
			started, unblock := make(chan struct{}), make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(unblock) }) }
			t.Cleanup(release)
			borrowed := []byte("12345")
			var received string
			require.True(t, p.emit(1, borrowed, func(owned []byte) udpTask {
				return func() { close(started); <-unblock; received = string(owned) }
			}))
			<-started
			borrowed[0] = 'X'
			require.EqualValues(t, 8, p.memory.Status().Used, "running buffer capacity must remain charged")
			prepared := false
			require.False(t, p.emit(2, borrowed, func([]byte) udpTask {
				prepared = true
				return func() {}
			}))
			require.False(t, prepared, "overload allocated per-packet work")
			require.EqualValues(t, 8, p.memory.Status().Used)
			release()
			require.Eventually(t, func() bool {
				p.mu.Lock()
				defer p.mu.Unlock()
				return p.tasks == 0 && len(p.queues) == 0
			}, time.Second, time.Millisecond)
			require.True(t, p.emit(2, borrowed, func([]byte) udpTask { return func() {} }), "released capacity was not reusable")
			p.close()
			require.Equal(t, "12345", received)
			require.Zero(t, p.memory.Status().Used)
			require.False(t, p.emit(3, borrowed, func([]byte) udpTask {
				t.Fatal("prepared work after shutdown")
				return nil
			}))
		})
	}
}

func TestUdpTaskPool_BoundedWorkers(t *testing.T) {
	p := newUdpTaskPool[int]()
	p.maxWorkers = 2
	t.Cleanup(p.close)
	started, unblock := make(chan struct{}, 20), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(unblock) }) }
	t.Cleanup(release)
	var executed atomic.Int32
	for key := range 20 {
		require.True(t, emitUDPTask(p, key, func() {
			started <- struct{}{}
			<-unblock
			executed.Add(1)
		}))
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("workers did not start")
		}
	}
	select {
	case <-started:
		t.Fatal("exceeded worker limit")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	var closers sync.WaitGroup
	for range 3 {
		closers.Go(p.close)
	}
	closers.Wait()
	require.EqualValues(t, 20, executed.Load())
}

func BenchmarkUdpTaskPoolRejectedPacket(b *testing.B) {
	p := newUdpTaskPool[netip.AddrPort]()
	p.maxTasks = 1
	unblock := make(chan struct{})
	source := testUdpKey(12345)
	emitUDPTask(p, source, func() { <-unblock })
	defer p.close()
	defer close(unblock)
	plane := &ControlPlane{ctx: context.Background(), udpTaskPool: p}
	data := make([]byte, 1500)
	p.drops.lastLog.Store(time.Now().UnixNano())
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		plane.enqueueUDPPacket(data, source, source, nil)
	}
}

func TestUDPQueuedCancellationReleasesBuffer(t *testing.T) {
	p := newUdpTaskPool[netip.AddrPort]()
	p.memory = membuffer.NewBudget(4096)
	t.Cleanup(p.close)
	source := testUdpKey(12346)
	started, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(unblock) }) }
	t.Cleanup(release)
	require.True(t, emitUDPTask(p, source, func() { close(started); <-unblock }))
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	plane := &ControlPlane{ctx: ctx, udpTaskPool: p}
	plane.enqueueUDPPacket([]byte("canceled"), source, source, nil)
	require.NotZero(t, p.memory.Status().Used)
	cancel()
	release()
	p.close()
	// A canceled queued packet must release storage without touching routing
	// state (the plane intentionally has no core or endpoints).
	require.Zero(t, p.memory.Status().Used)
}
