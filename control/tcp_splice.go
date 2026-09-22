// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package control

import (
	"io"
	"time"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/control/internal/splice"
	"github.com/daeuniverse/outbound/netproxy"
)

// trySplice hands eligible connections to the optional kernel relay. Only
// (false, nil) permits the caller to continue with the ordinary userspace relay.
func (r *tcpRelay) trySplice(traffic *stats.Connection) (handled bool, err error) {
	if r.directSplice == nil {
		return false, nil
	}
	left, right := unwrapSniffer(r.lConn).(splice.TCPConn), r.rConn.(splice.TCPConn)
	accepted := &relayEndpoint{conn: left, origin: netproxy.OriginCaller}
	remote := &relayEndpoint{conn: right, origin: netproxy.OriginTarget}
	// Flush sniffed bytes before bypassing the sniffer. If splice declines the
	// connection, the ordinary relay resumes with only the remaining bytes.
	if err := r.lConn.WriteBufferedTo(&trafficWriter{Writer: remote, add: traffic.RecordUpload}); err != nil {
		return false, err
	}
	return r.directSplice.Relay(
		&spliceEndpoint{TCPConn: left, endpoint: accepted},
		&spliceEndpoint{TCPConn: right, endpoint: remote}, traffic, r.activity)
}

// spliceEndpoint preserves the raw TCP capabilities used by the direct path
// while giving its userspace operations the same provenance as relayTCP.
type spliceEndpoint struct {
	splice.TCPConn
	endpoint *relayEndpoint
}

func (c *spliceEndpoint) Read(p []byte) (int, error) {
	n, err := c.TCPConn.Read(p)
	if err == io.EOF {
		return n, err // Only an exact read EOF is a graceful half-close.
	}
	return n, c.endpoint.failure(err, netproxy.OpRead)
}

func (c *spliceEndpoint) Write(p []byte) (int, error) {
	n, err := c.TCPConn.Write(p)
	return n, c.endpoint.failure(err, netproxy.OpWrite)
}

func (c *spliceEndpoint) CloseWrite() error {
	return c.endpoint.failure(c.TCPConn.CloseWrite(), netproxy.OpCloseWrite)
}

func (c *spliceEndpoint) Close() error { return c.endpoint.close() }

func (c *spliceEndpoint) WrapFailure(err error, phase netproxy.Operation) error {
	return c.endpoint.failure(err, phase)
}

func (c *spliceEndpoint) SetReadDeadline(deadline time.Time) error {
	return c.endpoint.failure(c.TCPConn.SetReadDeadline(deadline), netproxy.Operation("set_read_deadline"))
}

func (c *spliceEndpoint) SetWriteDeadline(deadline time.Time) error {
	return c.endpoint.failure(c.TCPConn.SetWriteDeadline(deadline), netproxy.Operation("set_write_deadline"))
}
