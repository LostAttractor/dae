/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testUdpKey(port uint16) netip.AddrPort {
	return netip.MustParseAddrPort(fmt.Sprintf("10.0.0.1:%d", port))
}

func TestUdpTaskPool_TaskExecution(t *testing.T) {
	pool := newUdpTaskPool[netip.AddrPort](DefaultNatTimeoutUDP)
	t.Cleanup(pool.close)
	key := testUdpKey(10001)

	done := make(chan struct{})
	require.True(t, pool.emit(key, func() { close(done) }))

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("task was not executed")
	}
}

func TestUdpTaskPool_TasksWithSameKeyAreOrdered(t *testing.T) {
	pool := newUdpTaskPool[netip.AddrPort](DefaultNatTimeoutUDP)
	t.Cleanup(pool.close)
	key := testUdpKey(10002)

	const n = 100
	var mu sync.Mutex
	executed := make([]int, 0, n)
	done := make(chan struct{})
	for i := 0; i < n; i++ {
		i := i
		pool.emit(key, func() {
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
	for i := 0; i < n; i++ {
		if executed[i] != i {
			t.Fatalf("tasks executed out of order: executed[%v] = %v", i, executed[i])
		}
	}
}

func TestUdpTaskPool_DropWhenQueueFull(t *testing.T) {
	pool := newUdpTaskPool[netip.AddrPort](DefaultNatTimeoutUDP)
	t.Cleanup(pool.close)
	key := testUdpKey(10003)

	// Block the convoy goroutine so the queue channel can be filled.
	unblock := make(chan struct{})
	var unblockOnce sync.Once
	release := func() { unblockOnce.Do(func() { close(unblock) }) }
	t.Cleanup(release)
	started := make(chan struct{})
	require.True(t, pool.emit(key, func() {
		close(started)
		<-unblock
	}))
	<-started

	// Fill the queue channel.
	for i := 0; i < udpTaskQueueLength; i++ {
		require.True(t, pool.emit(key, func() {}))
	}

	// The queue is full now: this task should be dropped instead of blocking.
	emitDone := make(chan bool)
	go func() {
		emitDone <- pool.emit(key, func() {})
	}()
	select {
	case accepted := <-emitDone:
		require.False(t, accepted)
	case <-time.After(3 * time.Second):
		t.Fatal("EmitTask blocked on a full queue")
	}
	firstLog := pool.lastSaturationLog.Load()
	require.NotZero(t, firstLog, "queue saturation was not reported")
	require.False(t, pool.emit(key, func() {}))
	require.Equal(t, firstLog, pool.lastSaturationLog.Load(), "queue saturation warning was not rate limited")
	futureLog := time.Now().Add(time.Hour).UnixNano()
	pool.lastSaturationLog.Store(futureLog)
	pool.reportSaturation()
	require.Less(t, pool.lastSaturationLog.Load(), futureLog, "clock rollback suppressed saturation warnings")
	release()
}

func TestUdpTaskPool_QueueAging(t *testing.T) {
	pool := newUdpTaskPool[netip.AddrPort](100 * time.Millisecond)
	t.Cleanup(pool.close)
	key := testUdpKey(10004)

	done := make(chan struct{})
	pool.emit(key, func() { close(done) })
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("task was not executed")
	}

	pool.mu.Lock()
	_, ok := pool.queues[key]
	pool.mu.Unlock()
	require.True(t, ok, "queue should exist right after emitting a task")

	// The queue should be GCed after agingTime of inactivity.
	require.Eventually(t, func() bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		_, ok = pool.queues[key]
		return !ok
	}, 3*time.Second, 20*time.Millisecond, "queue should be GCed after aging timeout")

	// A new task should recreate the queue.
	done2 := make(chan struct{})
	pool.emit(key, func() { close(done2) })
	select {
	case <-done2:
	case <-time.After(3 * time.Second):
		t.Fatal("task was not executed after queue recreation")
	}
}

func TestUdpTaskPool_CloseDrainsAcceptedTasks(t *testing.T) {
	pool := newUdpTaskPool[netip.AddrPort](DefaultNatTimeoutUDP)
	key := testUdpKey(10005)
	started := make(chan struct{})
	unblock := make(chan struct{})
	secondDone := make(chan struct{})
	require.True(t, pool.emit(key, func() {
		close(started)
		<-unblock
	}))
	<-started
	require.True(t, pool.emit(key, func() { close(secondDone) }))

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
	require.False(t, pool.emit(key, func() {}), "closed pool accepted a task")
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
	pool := newUdpTaskPool[netip.AddrPort](DefaultNatTimeoutUDP)
	key := testUdpKey(10006)
	start := make(chan struct{})
	var producers sync.WaitGroup
	var accepted atomic.Int64
	var executed atomic.Int64
	for range 8 {
		producers.Add(1)
		go func() {
			defer producers.Done()
			<-start
			for range 100 {
				if pool.emit(key, func() { executed.Add(1) }) {
					accepted.Add(1)
				}
			}
		}()
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
	require.False(t, pool.emit(key, func() {}))
}
