/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testUdpKey(port uint16) netip.AddrPort {
	return netip.MustParseAddrPort(fmt.Sprintf("10.0.0.1:%d", port))
}

func TestUdpTaskPool_TaskExecution(t *testing.T) {
	pool := NewUdpTaskPool[netip.AddrPort]()
	key := testUdpKey(10001)

	done := make(chan struct{})
	pool.EmitTask(key, func() { close(done) })

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("task was not executed")
	}
}

func TestUdpTaskPool_TasksWithSameKeyAreOrdered(t *testing.T) {
	pool := NewUdpTaskPool[netip.AddrPort]()
	key := testUdpKey(10002)

	const n = 100
	var mu sync.Mutex
	executed := make([]int, 0, n)
	done := make(chan struct{})
	for i := 0; i < n; i++ {
		i := i
		pool.EmitTask(key, func() {
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
	pool := NewUdpTaskPool[netip.AddrPort]()
	key := testUdpKey(10003)

	// Block the convoy goroutine so the queue channel can be filled.
	unblock := make(chan struct{})
	started := make(chan struct{})
	pool.EmitTask(key, func() {
		close(started)
		<-unblock
	})
	<-started

	// Fill the queue channel.
	for i := 0; i < UdpTaskQueueLength; i++ {
		pool.EmitTask(key, func() {})
	}

	// The queue is full now: this task should be dropped instead of blocking.
	emitDone := make(chan struct{})
	go func() {
		pool.EmitTask(key, func() {})
		close(emitDone)
	}()
	select {
	case <-emitDone:
	case <-time.After(3 * time.Second):
		t.Fatal("EmitTask blocked on a full queue")
	}
	close(unblock)
}

func TestUdpTaskPool_QueueAging(t *testing.T) {
	oldNatTimeout := DefaultNatTimeoutUDP
	DefaultNatTimeoutUDP = 100 * time.Millisecond
	defer func() { DefaultNatTimeoutUDP = oldNatTimeout }()

	pool := NewUdpTaskPool[netip.AddrPort]()
	key := testUdpKey(10004)

	done := make(chan struct{})
	pool.EmitTask(key, func() { close(done) })
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("task was not executed")
	}

	pool.mu.Lock()
	_, ok := pool.m[key]
	pool.mu.Unlock()
	require.True(t, ok, "queue should exist right after emitting a task")

	// The queue should be GCed after agingTime of inactivity.
	require.Eventually(t, func() bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		_, ok = pool.m[key]
		return !ok
	}, 3*time.Second, 20*time.Millisecond, "queue should be GCed after aging timeout")

	// A new task should recreate the queue.
	done2 := make(chan struct{})
	pool.EmitTask(key, func() { close(done2) })
	select {
	case <-done2:
	case <-time.After(3 * time.Second):
		t.Fatal("task was not executed after queue recreation")
	}
}
