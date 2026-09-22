/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"maps"
	"net"
	"slices"
	"sync"

	log "github.com/sirupsen/logrus"
)

// tcpConnectionTracker lets shutdown stop new setups, wait for existing setups,
// and close accepted connections independently of their relay implementation.
type tcpConnectionTracker struct {
	// mu serializes setup Add calls with the stopped transition before Wait.
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	setups      sync.WaitGroup
	stopped     bool
}

func (t *tcpConnectionTracker) beginSetup(conn net.Conn) bool {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		_ = conn.Close()
		return false
	}
	if t.connections == nil {
		t.connections = make(map[net.Conn]struct{})
	}
	t.connections[conn] = struct{}{}
	t.setups.Add(1)
	t.mu.Unlock()
	return true
}

func (t *tcpConnectionTracker) finishSetup() {
	t.setups.Done()
}

func (t *tcpConnectionTracker) removeConnection(conn net.Conn) {
	t.mu.Lock()
	delete(t.connections, conn)
	t.mu.Unlock()
}

func (t *tcpConnectionTracker) stopAccepting() {
	t.mu.Lock()
	t.stopped = true
	t.mu.Unlock()
}

func (t *tcpConnectionTracker) stopAndSnapshot() []net.Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopped = true
	return slices.Collect(maps.Keys(t.connections))
}

func (t *tcpConnectionTracker) waitForSetups() {
	t.setups.Wait()
}

func serveTCPConnection(c *ControlPlane, lConn net.Conn, ctx context.Context, tracker *tcpConnectionTracker) {
	defer tracker.removeConnection(lConn)
	relay, err := c.prepareTCPRelay(ctx, lConn)
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
