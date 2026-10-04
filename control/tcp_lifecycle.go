/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
)

// TCP sockets belong to the shared datapath, not to the plane that accepted
// them. Ordinary reload retires admission while keeping this set reachable.
type tcpConnectionSet struct {
	mu          sync.Mutex
	connections map[net.Conn]struct{}
}

func (s *tcpConnectionSet) add(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.connections == nil {
		s.connections = make(map[net.Conn]struct{})
	}
	s.connections[conn] = struct{}{}
}

func (s *tcpConnectionSet) remove(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.connections, conn)
}

// Start every abort before waiting for any socket. The caller joins done before
// tearing down the return path; no peer EOF or outbound transport drain is needed.
func (s *tcpConnectionSet) abort() <-chan struct{} {
	done := make(chan struct{})
	var closes sync.WaitGroup
	s.mu.Lock()
	for conn := range s.connections {
		setTCPResetOnClose(conn)
		closes.Go(func() {
			_ = conn.Close()
		})
	}
	s.mu.Unlock()
	go func() {
		closes.Wait()
		close(done)
	}()
	return done
}

// Each plane owns admission and setup work, independently of established sockets.
type tcpConnectionTracker struct {
	// mu serializes setup Add calls with the stopped transition before Wait.
	mu          sync.Mutex
	connections *tcpConnectionSet
	setups      sync.WaitGroup
	stopped     bool
	aborted     <-chan struct{}
}

func (t *tcpConnectionTracker) beginSetup(conn net.Conn) bool {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return false
	}
	t.connections.add(conn)
	t.setups.Add(1)
	t.mu.Unlock()
	return true
}

func (t *tcpConnectionTracker) finishSetup() {
	t.setups.Done()
}

func (t *tcpConnectionTracker) removeConnection(conn net.Conn) {
	t.connections.remove(conn)
}

func (t *tcpConnectionTracker) stopAccepting() {
	t.mu.Lock()
	t.stopped = true
	t.mu.Unlock()
}

func (t *tcpConnectionTracker) abort() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopped = true
	if t.aborted == nil {
		t.aborted = t.connections.abort()
	}
}

func (t *tcpConnectionTracker) waitForAbort() {
	t.mu.Lock()
	done := t.aborted
	t.mu.Unlock()
	if done != nil {
		<-done
	}
}

func (t *tcpConnectionTracker) waitForSetups() {
	t.setups.Wait()
}

func serveTCPConnection(c *ControlPlane, lConn net.Conn, ctx context.Context, tracker *tcpConnectionTracker, result *routingResult) {
	defer tracker.removeConnection(lConn)
	relay, err := c.prepareTCPRelay(ctx, lConn, result)
	// Raw TCP relays retain only their dialer. MITM may route rewritten targets
	// until Host.Close drains its requests, before DNS and outbounds are closed.
	c = nil
	tracker.finishSetup()
	if relay != nil {
		err = relay.run()
	}
	if err == nil || ctx.Err() != nil || !log.IsLevelEnabled(log.DebugLevel) {
		return
	}
	fields := log.Fields{"source": lConn.RemoteAddr(), "destination": lConn.LocalAddr()}
	if relay != nil {
		fields["outbound"], fields["dialer"], fields["domain"] = relay.statsPath.Outbound, relay.statsPath.Dialer, relay.domain
	}
	log.WithFields(fields).WithError(err).Debug("TCP connection failed")
}
