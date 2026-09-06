/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/stats"
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

func startTCPRelayTest(t *testing.T, left, right net.Conn, drainTimeout time.Duration) <-chan error {
	t.Helper()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	traffic := stats.DefaultStore.OpenConnection(stats.Path{Dialer: t.Name()}, false)
	done := make(chan error, 1)
	go func() {
		err := relayTCP(left, right, traffic, drainTimeout, "", nil, nil)
		_ = traffic.Close()
		done <- err
	}()
	return done
}

func waitTCPRelayTest(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not finish")
		return nil
	}
}

func TestRelayTCPHalfClose(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "upload"
		if reverse {
			name = "download"
		}
		t.Run(name, func(t *testing.T) {
			left, client := relayTestTCPPair(t)
			right, server := relayTestTCPPair(t)
			before := stats.DefaultStore.Snapshot()[stats.Path{Dialer: t.Name()}]
			done := startTCPRelayTest(t, left, right, time.Second)
			if reverse {
				client, server = server, client
			}
			if _, err := client.Write([]byte("request")); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(server)
			if err != nil || string(got) != "request" {
				t.Fatalf("request = %q, err = %v", got, err)
			}
			// The response starts only after the request EOF reaches the peer.
			if _, err := server.Write([]byte("response after EOF")); err != nil {
				t.Fatal(err)
			}
			if err := server.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err = io.ReadAll(client)
			if err != nil || string(got) != "response after EOF" {
				t.Fatalf("response = %q, err = %v", got, err)
			}
			if err := waitTCPRelayTest(t, done); err != nil {
				t.Fatal(err)
			}
			gotStats := stats.DefaultStore.Snapshot()[stats.Path{Dialer: t.Name()}]
			upload, download := uint64(len("request")), uint64(len("response after EOF"))
			if reverse {
				upload, download = download, upload
			}
			if gotStats.UploadBytes-before.UploadBytes != upload || gotStats.DownloadBytes-before.DownloadBytes != download {
				t.Fatalf("relay byte counts: %+v", gotStats)
			}
		})
	}
}

type relayCloseWriteConn struct {
	net.Conn
	closeWrite func() error
}

func (c relayCloseWriteConn) CloseWrite() error { return c.closeWrite() }

func TestRelayTCPCloseWriteFailure(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "upload"
		if reverse {
			name = "download"
		}
		t.Run(name, func(t *testing.T) {
			left, client := relayTestTCPPair(t)
			right, server := relayTestTCPPair(t)
			want := errors.New("half-close failed")
			wrap := func(conn net.Conn) net.Conn {
				return relayCloseWriteConn{Conn: conn, closeWrite: func() error {
					return &net.OpError{Op: "write", Net: "tcp", Err: want}
				}}
			}
			var l, r net.Conn = left, wrap(right)
			if reverse {
				l, r = wrap(left), right
				client, server = server, client
			}
			done := startTCPRelayTest(t, l, r, time.Second)
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if err := waitTCPRelayTest(t, done); !errors.Is(err, want) {
				t.Fatalf("relay error = %v, want %v", err, want)
			}
			// Failure must unblock the reverse copy and close both endpoints.
			for _, peer := range []*net.TCPConn{client, server} {
				if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					t.Fatalf("peer read = %v, want EOF", err)
				}
			}
		})
	}
}

type relayReadConn struct {
	*closeTrackingConn
	read func([]byte) (int, error)
}

func (c relayReadConn) Read(p []byte) (int, error) { return c.read(p) }

func TestRelayTCPErrorAfterEOF(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "upload"
		if reverse {
			name = "download"
		}
		t.Run(name, func(t *testing.T) {
			want := errors.New("reverse copy failed")
			halfClosed := make(chan struct{})
			fail := make(chan struct{})
			eof := relayCloseWriteConn{
				Conn:       relayReadConn{newCloseTrackingConn(), func([]byte) (int, error) { return 0, io.EOF }},
				closeWrite: func() error { return nil },
			}
			base := newCloseTrackingConn()
			failed := relayCloseWriteConn{
				Conn: relayReadConn{base, func([]byte) (int, error) {
					select {
					case <-fail:
						return 0, want
					case <-base.closed:
						return 0, net.ErrClosed
					}
				}},
				closeWrite: func() error { close(halfClosed); return nil },
			}
			var l, r net.Conn = eof, failed
			if reverse {
				l, r = r, l
			}
			t.Cleanup(func() { _ = l.Close(); _ = r.Close() })
			done := startTCPRelayTest(t, l, r, time.Second)
			select {
			case <-halfClosed:
			case <-time.After(5 * time.Second):
				t.Fatal("EOF was not propagated")
			}
			close(fail)
			if err := waitTCPRelayTest(t, done); !errors.Is(err, want) {
				t.Fatalf("relay error = %v, want %v", err, want)
			}
		})
	}
}

func TestRelayTCPDrainTimeout(t *testing.T) {
	for _, blockedWrite := range []bool{false, true} {
		name := "active reads"
		if blockedWrite {
			name = "blocked write"
		}
		t.Run(name, func(t *testing.T) {
			left, client := net.Pipe()
			right, server := net.Pipe()
			t.Cleanup(func() {
				_ = left.Close()
				_ = right.Close()
				_ = client.Close()
				_ = server.Close()
			})
			// This source has reached EOF but its write side remains usable.
			l := &relayEOFConn{Conn: left}
			done := startTCPRelayTest(t, l, right, 100*time.Millisecond)
			writesDone := make(chan struct{})
			go func() {
				defer close(writesDone)
				for {
					if _, err := server.Write([]byte("data")); err != nil {
						return
					}
				}
			}()
			if !blockedWrite {
				go func() { _, _ = io.Copy(io.Discard, client) }()
			}
			err := waitTCPRelayTest(t, done)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("relay error = %v, want drain timeout", err)
			}
			select {
			case <-writesDone:
			case <-time.After(time.Second):
				t.Fatal("drain timeout did not unblock peer writer")
			}
		})
	}
}

type relayEOFConn struct{ net.Conn }

func (c *relayEOFConn) Read([]byte) (int, error) { return 0, io.EOF }

func TestRelayTCPReturnsBothDirectionErrors(t *testing.T) {
	leftErr := errors.New("upload copy failed")
	rightErr := errors.New("download copy failed")
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	makeConn := func(want error) net.Conn {
		base := newCloseTrackingConn()
		t.Cleanup(func() { _ = base.Close() })
		return relayReadConn{base, func([]byte) (int, error) {
			started <- struct{}{}
			select {
			case <-release:
				return 0, want
			case <-base.closed:
				// Both reads have already failed when release is closed,
				// regardless of which result the relay processes first.
				select {
				case <-release:
					return 0, want
				default:
					return 0, net.ErrClosed
				}
			}
		}}
	}
	done := startTCPRelayTest(t, makeConn(leftErr), makeConn(rightErr), time.Second)
	for range 2 {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("both relay reads did not start")
		}
	}
	close(release)
	err := waitTCPRelayTest(t, done)
	if !errors.Is(err, leftErr) || !errors.Is(err, rightErr) {
		t.Fatalf("relay error = %v, want both %v and %v", err, leftErr, rightErr)
	}
}

func TestRelayTCPDrainGracePreservesReverseTraffic(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "upload"
		if reverse {
			name = "download"
		}
		t.Run(name, func(t *testing.T) {
			left, client := net.Pipe()
			right, server := net.Pipe()
			t.Cleanup(func() {
				_ = left.Close()
				_ = right.Close()
				_ = client.Close()
				_ = server.Close()
			})
			if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := server.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var l, r net.Conn = &relayEOFConn{Conn: left}, right
			if reverse {
				l, r = r, l
			}
			done := startTCPRelayTest(t, l, r, time.Second)
			select {
			case err := <-done:
				t.Fatalf("relay ended within drain grace period: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			const response = "response within drain grace period"
			writeDone := make(chan error, 1)
			go func() {
				_, err := io.WriteString(server, response)
				_ = server.Close()
				writeDone <- err
			}()
			got := make([]byte, len(response))
			if _, err := io.ReadFull(client, got); err != nil {
				t.Fatal(err)
			}
			if string(got) != response {
				t.Fatalf("response = %q, want %q", got, response)
			}
			if err := <-writeDone; err != nil {
				t.Fatal(err)
			}
			if err := waitTCPRelayTest(t, done); err != nil {
				t.Fatalf("relay within drain grace period: %v", err)
			}
		})
	}
}
