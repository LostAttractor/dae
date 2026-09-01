/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/control/internal/splice"
	"github.com/daeuniverse/outbound/netproxy"
)

type tcpTestDialer struct{ conn net.Conn }

func (d tcpTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

func (tcpTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

type closeTrackingConn struct {
	closed chan struct{}
	once   sync.Once
}

func newCloseTrackingConn() *closeTrackingConn {
	return &closeTrackingConn{closed: make(chan struct{})}
}

func (c *closeTrackingConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (c *closeTrackingConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (c *closeTrackingConn) LocalAddr() net.Addr              { return nil }
func (c *closeTrackingConn) RemoteAddr() net.Addr             { return nil }
func (c *closeTrackingConn) SetDeadline(time.Time) error      { return nil }
func (c *closeTrackingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *closeTrackingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *closeTrackingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func TestStopAndAbortConnectionsClosesConcurrentSetups(t *testing.T) {
	for range 1000 {
		plane := &ControlPlane{tcpConnections: new(tcpConnectionTracker)}
		conn := newCloseTrackingConn()
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			plane.tcpConnections.beginSetup(conn)
		}()
		go func() {
			defer wg.Done()
			<-start
			if err := plane.StopAndAbortConnections(); err != nil {
				t.Errorf("StopAndAbortConnections: %v", err)
			}
		}()
		close(start)
		wg.Wait()

		select {
		case <-conn.closed:
		default:
			t.Fatal("connection escaped concurrent abort")
		}
	}
}

func TestBeginTCPSetupAfterStopClosesConnection(t *testing.T) {
	plane := &ControlPlane{tcpConnections: new(tcpConnectionTracker)}
	if err := plane.StopAndAbortConnections(); err != nil {
		t.Fatal(err)
	}
	conn := newCloseTrackingConn()
	if plane.tcpConnections.beginSetup(conn) {
		t.Fatal("registration succeeded after abort")
	}
	select {
	case <-conn.closed:
	default:
		t.Fatal("rejected connection was not closed")
	}
}

func TestTCPConnectionTrackerWaitsForSetups(t *testing.T) {
	tracker := new(tcpConnectionTracker)
	conn := newCloseTrackingConn()
	if !tracker.beginSetup(conn) {
		t.Fatal("registration failed")
	}
	tracker.stopAccepting()

	done := make(chan struct{})
	waitStarted := make(chan struct{})
	go func() {
		close(waitStarted)
		tracker.waitForSetups()
		close(done)
	}()
	<-waitStarted
	select {
	case <-done:
		t.Fatal("wait returned before setup handoff")
	default:
	}

	tracker.finishSetup()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("wait did not return after setup handoff")
	}
}

func TestRuntimeConnectionRetainsDirectSpliceCapability(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, _ := listener.AcceptTCP()
		accepted <- conn
	}()
	remote, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = server.Close() })

	runtime := netproxy.NewRuntime(netproxy.Layer{Data: tcpTestDialer{conn: remote}})
	conn, err := runtime.Dialer().DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(splice.TCPConn); !ok {
		t.Fatal("runtime connection hid direct splice capability")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	runtime.Retire()
	if err := runtime.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRelayDirectionCountsForwardedBytes(t *testing.T) {
	source, sourcePeer := net.Pipe()
	destination, destinationPeer := net.Pipe()
	t.Cleanup(func() {
		_ = source.Close()
		_ = sourcePeer.Close()
		_ = destination.Close()
		_ = destinationPeer.Close()
	})
	payload := []byte("traffic accounting payload")
	var counted atomic.Uint64
	relayDone := make(chan error, 1)
	go func() {
		defer destination.Close()
		relayDone <- relayDirection(destination, source, func(bytes uint64) { counted.Add(bytes) })
	}()
	go func() {
		_, _ = sourcePeer.Write(payload)
		_ = sourcePeer.Close()
	}()
	got, err := io.ReadAll(destinationPeer)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-relayDone; err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("relayed payload = %q, want %q", got, payload)
	}
	if got := counted.Load(); got != uint64(len(payload)) {
		t.Fatalf("counted bytes = %d, want %d", got, len(payload))
	}
}
