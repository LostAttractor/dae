/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type testPacketConn struct {
	blockWrite   bool
	writeStarted chan struct{}
	closed       chan struct{}
	writeOnce    sync.Once
	closeOnce    sync.Once
}

func newTestPacketConn(blockWrite bool) *testPacketConn {
	return &testPacketConn{
		blockWrite:   blockWrite,
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (c *testPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *testPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })
	if !c.blockWrite {
		return len(b), nil
	}
	<-c.closed
	return 0, net.ErrClosed
}

func (c *testPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *testPacketConn) LocalAddr() net.Addr              { return nil }
func (c *testPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *testPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testPacketConn) SetWriteDeadline(time.Time) error { return nil }

type deadlineInterruptPacketConn struct {
	writeStarted  chan struct{}
	interrupted   chan struct{}
	closeStarted  chan struct{}
	releaseClose  chan struct{}
	writeOnce     sync.Once
	interruptOnce sync.Once
	closeOnce     sync.Once
}

func newDeadlineInterruptPacketConn() *deadlineInterruptPacketConn {
	return &deadlineInterruptPacketConn{
		writeStarted: make(chan struct{}),
		interrupted:  make(chan struct{}),
		closeStarted: make(chan struct{}),
		releaseClose: make(chan struct{}),
	}
}

func (c *deadlineInterruptPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.interrupted
	return 0, nil, net.ErrClosed
}

func (c *deadlineInterruptPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })
	<-c.interrupted
	return 0, os.ErrDeadlineExceeded
}

func (c *deadlineInterruptPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closeStarted) })
	<-c.releaseClose
	return nil
}

func (c *deadlineInterruptPacketConn) LocalAddr() net.Addr             { return nil }
func (c *deadlineInterruptPacketConn) SetDeadline(time.Time) error     { return nil }
func (c *deadlineInterruptPacketConn) SetReadDeadline(time.Time) error { return nil }
func (c *deadlineInterruptPacketConn) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		c.interruptOnce.Do(func() { close(c.interrupted) })
	}
	return nil
}

func TestWritePacketCancellationInterruptsWrite(t *testing.T) {
	conn := newTestPacketConn(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := writePacket(ctx, conn, []byte("packet"), nil)
		done <- err
	}()
	<-conn.writeStarted
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("writePacket returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt WriteTo")
	}
}

func TestWritePacketCancellationDoesNotWaitForBlockingClose(t *testing.T) {
	conn := newDeadlineInterruptPacketConn()
	t.Cleanup(func() { close(conn.releaseClose) })
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	done := make(chan error, 1)
	go func() {
		_, err := writePacket(ctx, conn, []byte("packet"), nil)
		done <- err
	}()
	<-conn.writeStarted
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("writePacket returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("writePacket waited for blocking Close")
	}
	select {
	case <-conn.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not start connection cleanup")
	}
}

func TestUdpEndpointPoolCloseAllDoesNotWaitForBlockingClose(t *testing.T) {
	endpointPool := new(UdpEndpointPool)
	conn := newDeadlineInterruptPacketConn()
	t.Cleanup(func() { close(conn.releaseClose) })
	key := testUdpKey(12001)
	endpoint := newUdpEndpoint(&UdpEndpointOptions{PacketConn: conn, NatTimeout: time.Hour})
	endpointPool.add(key, endpoint)

	endpointPool.closeAll()
	if !endpoint.IsClosed() {
		t.Fatal("closeAll returned before retiring the endpoint")
	}
	if _, ok := endpointPool.Get(key); ok {
		t.Fatal("closeAll left the endpoint in the pool")
	}
	select {
	case <-conn.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("closeAll did not start connection cleanup")
	}
}

func TestUdpEndpointPoolRemoveFlushesTrafficBeforeBlockingClose(t *testing.T) {
	identity := stats.TrafficIdentity{
		NodeID: t.Name(), Outbound: t.Name(), Subtag: "sub", Dialer: "node", Network: "udp4",
	}
	labels := prometheus.Labels{
		"id": identity.NodeID, "outbound": identity.Outbound, "subtag": identity.Subtag,
		"dialer": identity.Dialer, "network": identity.Network,
	}
	for _, direction := range []string{stats.TrafficDirectionUpload, stats.TrafficDirectionDownload} {
		metricLabels := prometheus.Labels{}
		for key, value := range labels {
			metricLabels[key] = value
		}
		metricLabels["direction"] = direction
		common.TrafficBytes.Delete(metricLabels)
		t.Cleanup(func() { common.TrafficBytes.Delete(metricLabels) })
	}

	var endpointPool UdpEndpointPool
	conn := newDeadlineInterruptPacketConn()
	t.Cleanup(func() {
		select {
		case <-conn.releaseClose:
		default:
			close(conn.releaseClose)
		}
	})
	endpoint := newUdpEndpoint(&UdpEndpointOptions{PacketConn: conn, NatTimeout: time.Hour})
	endpoint.traffic = stats.DefaultTrafficTracker.Open(identity)
	endpoint.traffic.RecordUpload(77)
	key := testUdpKey(12005)
	endpointPool.add(key, endpoint)
	removed := make(chan struct{})
	go func() {
		endpointPool.remove(key, endpoint)
		close(removed)
	}()

	select {
	case <-conn.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("endpoint removal did not start connection close")
	}
	var metric dto.Metric
	labels["direction"] = stats.TrafficDirectionUpload
	if err := common.TrafficBytes.With(labels).Write(&metric); err != nil {
		t.Fatal(err)
	}
	if got := metric.GetCounter().GetValue(); got != 77 {
		t.Fatalf("traffic bytes before connection close = %v, want 77", got)
	}
	close(conn.releaseClose)
	<-removed
}

func TestUdpEndpointPoolRemovalChecksIdentity(t *testing.T) {
	var pool UdpEndpointPool
	key := netip.MustParseAddrPort("192.0.2.1:1234")
	oldConn := newTestPacketConn(false)
	oldEndpoint := newUdpEndpoint(&UdpEndpointOptions{
		PacketConn: oldConn,
		NatTimeout: time.Hour,
	})
	newEndpoint := newUdpEndpoint(&UdpEndpointOptions{
		PacketConn: newTestPacketConn(false),
		NatTimeout: time.Hour,
	})
	pool.add(key, oldEndpoint)
	pool.add(key, newEndpoint)
	t.Cleanup(func() { pool.remove(key, newEndpoint) })
	if !oldEndpoint.IsClosed() {
		t.Fatal("replacing an endpoint did not retire the old endpoint")
	}
	select {
	case <-oldConn.closed:
	case <-time.After(time.Second):
		t.Fatal("replacing an endpoint did not close the old connection")
	}

	pool.remove(key, oldEndpoint)
	got, ok := pool.Get(key)
	if !ok || got != newEndpoint {
		t.Fatal("removing stale endpoint deleted its replacement")
	}
}

func endpointTimerDeadline(endpoint *UdpEndpoint) time.Time {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	return endpoint.timerDeadline
}

func TestUdpEndpointPoolRefreshInvalidatesPendingExpiry(t *testing.T) {
	var pool UdpEndpointPool
	key := testUdpKey(12002)
	conn := newTestPacketConn(false)
	endpoint := newUdpEndpoint(&UdpEndpointOptions{
		PacketConn: conn,
		NatTimeout: time.Hour,
	})
	pool.add(key, endpoint)
	t.Cleanup(pool.closeAll)
	oldDeadline := endpointTimerDeadline(endpoint)

	// Hold the key as Get/use does while an already-fired callback queues for
	// the same key. The refresh must make that callback stale before unlock.
	l, _ := pool.UdpEndpointKeyLocker.Lock(key)
	callbackStarted := make(chan struct{})
	callbackDone := make(chan struct{})
	go func() {
		close(callbackStarted)
		pool.expireAt(key, endpoint, oldDeadline)
		close(callbackDone)
	}()
	<-callbackStarted
	ok := pool.refreshTimerLocked(key, endpoint, oldDeadline)
	pool.UdpEndpointKeyLocker.Unlock(key, l)
	if !ok {
		t.Fatal("refresh rejected the current endpoint")
	}
	<-callbackDone

	current, ok := pool.pool.Load(key)
	if !ok || current != endpoint || endpoint.IsClosed() {
		t.Fatal("pending stale callback expired the refreshed endpoint")
	}
	newDeadline := endpointTimerDeadline(endpoint)
	if !newDeadline.After(oldDeadline) {
		t.Fatal("refresh did not advance the timer deadline")
	}

	pool.expireAt(key, endpoint, newDeadline)
	if _, ok := pool.pool.Load(key); ok {
		t.Fatal("current timer deadline did not expire the endpoint")
	}
	if !endpoint.IsClosed() {
		t.Fatal("expiry did not retire the endpoint")
	}
}

func TestUdpEndpointPoolExpiryHonorsAbsoluteDeadline(t *testing.T) {
	var pool UdpEndpointPool
	key := testUdpKey(12003)
	endpoint := newUdpEndpoint(&UdpEndpointOptions{
		PacketConn: newTestPacketConn(false),
		NatTimeout: time.Hour,
	})
	pool.add(key, endpoint)
	t.Cleanup(pool.closeAll)
	deadline := endpointTimerDeadline(endpoint)

	pool.expireAt(key, endpoint, time.Now())
	current, ok := pool.pool.Load(key)
	if !ok || current != endpoint || endpoint.IsClosed() {
		t.Fatal("early timer callback expired the endpoint before its absolute deadline")
	}

	pool.expireAt(key, endpoint, deadline)
	if _, ok := pool.pool.Load(key); ok {
		t.Fatal("endpoint remained in the pool at its absolute deadline")
	}
}

func TestUdpEndpointPoolTimerExpiresEndpoint(t *testing.T) {
	var pool UdpEndpointPool
	key := testUdpKey(12004)
	conn := newTestPacketConn(false)
	endpoint := newUdpEndpoint(&UdpEndpointOptions{
		PacketConn: conn,
		NatTimeout: 20 * time.Millisecond,
	})
	pool.add(key, endpoint)
	t.Cleanup(pool.closeAll)

	select {
	case <-conn.closed:
	case <-time.After(time.Second):
		t.Fatal("endpoint timer did not close the connection")
	}
	if _, ok := pool.pool.Load(key); ok {
		t.Fatal("endpoint timer did not remove the endpoint")
	}
	if !endpoint.IsClosed() {
		t.Fatal("endpoint timer did not retire the endpoint")
	}
}
