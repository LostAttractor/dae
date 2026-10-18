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
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/stretchr/testify/require"
)

func testUdpKey(port uint16) netip.AddrPort {
	return netip.MustParseAddrPort(fmt.Sprintf("10.0.0.1:%d", port))
}

func TestUdpTaskPool_TaskExecution(t *testing.T) {
	done := make(chan struct{})
	pool := newUdpTaskPool(func(udpPacketWork, []byte) { close(done) })
	t.Cleanup(pool.close)
	require.True(t, pool.emit(nil, udpPacketWork{src: testUdpKey(10001)}))
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("task was not executed")
	}
}

func TestUdpTaskPool_TasksWithSameKeyAreOrdered(t *testing.T) {
	const n = 100
	var mu sync.Mutex
	var executed []byte
	done := make(chan struct{})
	pool := newUdpTaskPool(func(_ udpPacketWork, data []byte) {
		mu.Lock()
		defer mu.Unlock()
		executed = append(executed, data[0])
		if len(executed) == n {
			close(done)
		}
	})
	t.Cleanup(pool.close)
	for i := range n {
		require.True(t, pool.emit([]byte{byte(i)}, udpPacketWork{src: testUdpKey(10002)}))
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("tasks were not fully executed")
	}
	for i := range n {
		require.Equal(t, byte(i), executed[i], "tasks executed out of order")
	}
}

func TestUdpTaskPool_DropWhenQueueFull(t *testing.T) {
	started, unblock := make(chan struct{}), make(chan struct{})
	pool := newUdpTaskPool(func(_ udpPacketWork, data []byte) {
		if string(data) == "hold" {
			close(started)
			<-unblock
		}
	})
	t.Cleanup(pool.close)
	release := sync.OnceFunc(func() { close(unblock) })
	t.Cleanup(release)
	work := udpPacketWork{src: testUdpKey(10003)}
	require.True(t, pool.emit([]byte("hold"), work))
	<-started
	for range udpTaskQueueLength {
		require.True(t, pool.emit(nil, work))
	}
	emitDone := make(chan bool)
	go func() { emitDone <- pool.emit(nil, work) }()
	select {
	case accepted := <-emitDone:
		require.False(t, accepted)
	case <-time.After(3 * time.Second):
		t.Fatal("emit blocked on a full queue")
	}
	firstLog := pool.drops.lastLog.Load()
	require.NotZero(t, firstLog, "queue saturation was not reported")
	require.False(t, pool.emit(nil, work))
	require.Equal(t, firstLog, pool.drops.lastLog.Load(), "queue saturation warning was not rate limited")
	futureLog := time.Now().Add(time.Hour).UnixNano()
	pool.drops.lastLog.Store(futureLog)
	pool.drops.report("source_queue_full")
	require.Less(t, pool.drops.lastLog.Load(), futureLog, "clock rollback suppressed saturation warnings")
	release()
}

func TestUdpTaskPool_ReleasesIdleSources(t *testing.T) {
	done := make(chan struct{})
	pool := newUdpTaskPool(func(udpPacketWork, []byte) { done <- struct{}{} })
	t.Cleanup(pool.close)
	pool.memory = membuffer.NewBudget(4096)
	for i := range 100 {
		require.True(t, pool.emit([]byte("packet"), udpPacketWork{src: testUdpKey(uint16(i))}))
		<-done
	}
	require.Eventually(t, func() bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		return len(pool.queues) == 0 && pool.tasks == 0 && pool.memory.Status().Used == 0
	}, time.Second, time.Millisecond)
	// Reusing an idle source must create a fresh queue and remain executable.
	require.True(t, pool.emit(nil, udpPacketWork{src: testUdpKey(0)}))
	<-done
}

func TestUdpTaskPool_CloseDrainsAcceptedTasks(t *testing.T) {
	started, unblock, secondDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	pool := newUdpTaskPool(func(_ udpPacketWork, data []byte) {
		if string(data) == "hold" {
			close(started)
			<-unblock
		} else {
			close(secondDone)
		}
	})
	t.Cleanup(pool.close)
	release := sync.OnceFunc(func() { close(unblock) })
	t.Cleanup(release)
	work := udpPacketWork{src: testUdpKey(10005)}
	require.True(t, pool.emit([]byte("hold"), work))
	<-started
	require.True(t, pool.emit(nil, work))
	closeDone := make(chan struct{})
	go func() { pool.close(); close(closeDone) }()
	require.Eventually(t, func() bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		return pool.closed
	}, time.Second, time.Millisecond)
	require.False(t, pool.emit(nil, work), "closed pool accepted a task")
	select {
	case <-closeDone:
		t.Fatal("Close returned before accepted tasks finished")
	case <-time.After(20 * time.Millisecond):
	}
	release()
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
	var executed atomic.Int64
	pool := newUdpTaskPool(func(udpPacketWork, []byte) { executed.Add(1) })
	work := udpPacketWork{src: testUdpKey(10006)}
	start := make(chan struct{})
	var producers sync.WaitGroup
	var accepted atomic.Int64
	for range 8 {
		producers.Go(func() {
			<-start
			for range 100 {
				if pool.emit(nil, work) {
					accepted.Add(1)
				}
			}
		})
	}
	close(start)
	closeDone := make(chan struct{})
	go func() { pool.close(); close(closeDone) }()
	producers.Wait()
	<-closeDone
	require.Equal(t, accepted.Load(), executed.Load())
	require.False(t, pool.emit(nil, work))
}

func TestUdpTaskPool_RoundRobin(t *testing.T) {
	started, unblock := make(chan struct{}), make(chan struct{})
	var order []netip.AddrPort
	p := newUdpTaskPool(func(work udpPacketWork, data []byte) {
		if string(data) == "hold" {
			close(started)
			<-unblock
		} else {
			order = append(order, work.src)
		}
	})
	p.maxWorkers = 1
	t.Cleanup(p.close)
	release := sync.OnceFunc(func() { close(unblock) })
	t.Cleanup(release)
	busy, other, third := testUdpKey(1), testUdpKey(2), testUdpKey(3)
	require.True(t, p.emit([]byte("hold"), udpPacketWork{src: busy}))
	<-started
	for range 3 {
		require.True(t, p.emit(nil, udpPacketWork{src: busy}))
		require.True(t, p.emit(nil, udpPacketWork{src: other}))
	}
	require.True(t, p.emit(nil, udpPacketWork{src: third}))
	release()
	p.close()
	require.Equal(t, []netip.AddrPort{other, third, busy, other, busy, other, busy}, order)
}

func TestUdpTaskPool_AdmissionBeforeCopying(t *testing.T) {
	for _, limit := range []string{"sources", "tasks", "memory"} {
		t.Run(limit, func(t *testing.T) {
			started, unblock := make(chan struct{}), make(chan struct{})
			var received string
			var executed atomic.Int32
			p := newUdpTaskPool(func(work udpPacketWork, owned []byte) {
				executed.Add(1)
				if work.src == testUdpKey(1) {
					close(started)
					<-unblock
					received = string(owned)
				}
			})
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
			release := sync.OnceFunc(func() { close(unblock) })
			t.Cleanup(release)
			borrowed := []byte("12345")
			require.True(t, p.emit(borrowed, udpPacketWork{src: testUdpKey(1)}))
			<-started
			borrowed[0] = 'X'
			require.EqualValues(t, 8, p.memory.Status().Used, "running buffer capacity must remain charged")
			require.False(t, p.emit(borrowed, udpPacketWork{src: testUdpKey(2)}))
			require.EqualValues(t, 8, p.memory.Status().Used)
			require.EqualValues(t, 8, p.memory.Status().Peak, "rejected packet allocated a buffer")
			release()
			require.Eventually(t, func() bool {
				p.mu.Lock()
				defer p.mu.Unlock()
				return p.tasks == 0 && len(p.queues) == 0
			}, time.Second, time.Millisecond)
			require.True(t, p.emit(borrowed, udpPacketWork{src: testUdpKey(2)}), "released capacity was not reusable")
			p.close()
			require.Equal(t, "12345", received)
			require.EqualValues(t, 2, executed.Load())
			require.Zero(t, p.memory.Status().Used)
			require.False(t, p.emit(borrowed, udpPacketWork{src: testUdpKey(3)}))
		})
	}
}

func TestUdpTaskPool_BoundedWorkers(t *testing.T) {
	started, unblock := make(chan struct{}, 20), make(chan struct{})
	var executed atomic.Int32
	p := newUdpTaskPool(func(udpPacketWork, []byte) {
		started <- struct{}{}
		<-unblock
		executed.Add(1)
	})
	p.maxWorkers = 2
	t.Cleanup(p.close)
	release := sync.OnceFunc(func() { close(unblock) })
	t.Cleanup(release)
	for key := range 20 {
		require.True(t, p.emit(nil, udpPacketWork{src: testUdpKey(uint16(key))}))
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
	unblock := make(chan struct{})
	p := newUdpTaskPool(func(udpPacketWork, []byte) { <-unblock })
	p.maxTasks = 1
	source := testUdpKey(12345)
	p.emit(nil, udpPacketWork{src: source})
	defer p.close()
	defer close(unblock)
	plane := &ControlPlane{ctx: b.Context(), udpTaskPool: p}
	data := make([]byte, 1500)
	p.drops.lastLog.Store(time.Now().UnixNano())
	b.ReportAllocs()
	for b.Loop() {
		plane.enqueueUDPPacket(data, source, source, nil)
	}
}

func TestUDPQueuedCancellationReleasesBuffer(t *testing.T) {
	started, unblock := make(chan struct{}), make(chan struct{})
	p := newUdpTaskPool(func(work udpPacketWork, data []byte) {
		if string(data) == "hold" {
			close(started)
			<-unblock
		} else {
			work.execute(data)
		}
	})
	p.memory = membuffer.NewBudget(4096)
	t.Cleanup(p.close)
	release := sync.OnceFunc(func() { close(unblock) })
	t.Cleanup(release)
	source := testUdpKey(12346)
	require.True(t, p.emit([]byte("hold"), udpPacketWork{src: source}))
	<-started
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	plane := &ControlPlane{ctx: ctx, udpTaskPool: p}
	plane.enqueueUDPPacket([]byte("canceled"), source, source, nil)
	require.NotZero(t, p.memory.Status().Used)
	cancel()
	release()
	p.close()
	// The canceled packet must release storage without touching routing state.
	require.Zero(t, p.memory.Status().Used)
}

func TestUdpTaskPoolAbortDiscardsQueuedWork(t *testing.T) {
	started, unblock := make(chan struct{}), make(chan struct{})
	queuedRan := false
	p := newUdpTaskPool(func(_ udpPacketWork, data []byte) {
		if string(data) == "hold" {
			close(started)
			<-unblock
		} else {
			queuedRan = true
		}
	})
	p.memory = membuffer.NewBudget(4096)
	t.Cleanup(p.close)
	release := sync.OnceFunc(func() { close(unblock) })
	t.Cleanup(release)
	work := udpPacketWork{src: testUdpKey(1)}
	require.True(t, p.emit([]byte("hold"), work))
	<-started
	require.True(t, p.emit([]byte("discard on shutdown"), work))
	require.NotZero(t, p.memory.Status().Used)
	p.cancel()
	release()
	p.close()
	require.False(t, queuedRan, "aborted pool executed queued business work")
	require.Zero(t, p.memory.Status().Used)
}

func TestUDPQueuedWriteUsesRemainingDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		unblock := make(chan struct{})
		p := newUdpTaskPool(func(work udpPacketWork, data []byte) {
			if string(data) == "hold" {
				<-unblock
			} else {
				work.execute(data)
			}
		})
		defer p.close()
		endpoints := new(UdpEndpointPool)
		defer endpoints.closeAll()
		conn := newDeadlineInterruptPacketConn()
		defer close(conn.releaseClose)
		source := testUdpKey(12347)
		destination := netip.MustParseAddrPort("192.0.2.1:443")
		endpoint := newUdpEndpoint(&UdpEndpointOptions{PacketConn: conn, NatTimeout: time.Hour})
		endpoints.add(source, endpoint)
		plane := &ControlPlane{ctx: t.Context(), udpTaskPool: p, udpEndpoints: endpoints}

		// Hold this source until only one second of the original timeout remains.
		require.True(t, p.emit([]byte("hold"), udpPacketWork{src: source}))
		queuedAt := time.Now()
		plane.enqueueUDPPacket([]byte("packet"), source, destination, nil)
		time.Sleep(consts.DefaultDialTimeout - time.Second)
		close(unblock)
		<-conn.writeStarted
		<-conn.interrupted
		require.Equal(t, consts.DefaultDialTimeout, time.Since(queuedAt))
		p.close()
		require.Zero(t, p.memory.Status().Used)
		require.False(t, endpoint.IsClosed(), "packet timeout retired a deadline-capable socket")
		select {
		case <-conn.closeStarted:
			t.Fatal("packet timeout closed a deadline-capable socket")
		default:
		}
	})
}
