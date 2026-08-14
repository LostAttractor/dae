/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"sync"
	"testing"
	"time"
)

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
