/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/dae/control/internal/splice"
	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

// relayEndpoint records the side on which an operation failed. Protocol and
// resource identity still come from the outbound adapter that owns the stream.
type relayEndpoint struct {
	conn   net.Conn
	origin netproxy.FailureOrigin
	closed atomic.Bool
}

func (e *relayEndpoint) Read(p []byte) (int, error) {
	if err := e.conn.SetReadDeadline(time.Now().Add(DefaultNatTimeoutTCPEstablished)); err != nil && !plainClosedError(err) {
		return 0, e.failure(err, netproxy.OpRead)
	}
	n, err := e.conn.Read(p)
	if err == io.EOF {
		return n, err // CopyBuffer recognizes the exact sentinel as normal EOF.
	}
	return n, e.failure(err, netproxy.OpRead)
}

func (e *relayEndpoint) Write(p []byte) (int, error) {
	n, err := e.conn.Write(p)
	if n < len(p) && err == nil {
		err = io.ErrShortWrite
	}
	return n, e.failure(err, netproxy.OpWrite)
}

func (e *relayEndpoint) halfClose() (needsDrain bool, err error) {
	err = netproxy.CloseWrite(e.conn)
	if err == errors.ErrUnsupported {
		return true, nil
	}
	// shutdown can race the peer's complete close after EOF. There is no
	// remaining write half in that case; an independent read/reset still reports.
	if op, ok := err.(*net.OpError); ok {
		if syscall, ok := op.Err.(*os.SyscallError); ok && syscall.Syscall == "shutdown" && syscall.Err == unix.ENOTCONN {
			return false, nil
		}
	}
	return false, e.failure(err, netproxy.OpCloseWrite)
}

func (e *relayEndpoint) close() error {
	e.closed.Store(true)
	return e.conn.Close()
}

func (e *relayEndpoint) failure(err error, phase netproxy.Operation) error {
	if err == nil {
		return nil
	}
	localClose := e.closed.Load() && nativeSocket(e.conn)
	var causes []error
	for _, failure := range netproxy.Failures(err) {
		failure.Phase = phase
		if failure.Origin != netproxy.OriginLocalCleanup && e.origin != "" {
			failure.Origin = e.origin
		}
		if localClose && plainClosedError(failure.Cause) {
			failure.Origin = netproxy.OriginLocalCleanup
			failure.Scope = netproxy.ScopeOperation
		}
		causes = append(causes, &failure)
	}
	return errors.Join(causes...)
}

// The sniffer is the only transparent wrapper on an accepted connection.
func unwrapSniffer(conn any) any {
	switch c := conn.(type) {
	case *sniffing.ConnSniffer:
		return c.Conn
	case *sniffing.ConnSnifferCloseWriter:
		return c.ConnSniffer.Conn
	default:
		return conn
	}
}

// Only native sockets supply evidence that a closed error came from our Close.
func nativeSocket(conn any) bool {
	switch unwrapSniffer(conn).(type) {
	case *net.TCPConn, *net.UDPConn, *net.UnixConn:
		return true
	default:
		return false
	}
}

// Arm an abortive close on the accepted TCP socket. The caller still closes
// the original connection so that sniffer buffers are released as well.
func setTCPResetOnClose(conn net.Conn) {
	if c, ok := unwrapSniffer(conn).(*net.TCPConn); ok {
		_ = c.SetLinger(0)
	}
}

// Only standard socket/pipe closure errors are attributable to a Close we
// performed. Do not traverse arbitrary Unwrap/Is implementations: QUIC fatal
// errors also match net.ErrClosed, but carry an independent connection cause.
func plainClosedError(err error) bool {
	switch err {
	case net.ErrClosed, io.ErrClosedPipe:
		return true
	}
	switch err := err.(type) {
	case *net.OpError:
		return plainClosedError(err.Err)
	case *os.SyscallError:
		return plainClosedError(err.Err)
	default:
		return false
	}
}

func withoutCleanupErrors(err error) error {
	var retained []error
	for _, failure := range netproxy.Failures(err) {
		if failure.Origin != netproxy.OriginLocalCleanup {
			retained = append(retained, &failure)
		}
	}
	return errors.Join(retained...)
}

// recordDataPlaneError always lets the dialer inspect every cause, even when a
// timeout or caller error occurs beside a shared-resource failure. The return
// value controls path-level warning logs, not the resource recovery decision.
func recordDataPlaneError(reporter *dialer.Dialer, path stats.Path, err error) bool {
	if err == nil {
		return false
	}
	if reporter != nil {
		reporter.ReportDataPlaneError(err)
	}
	warn := false
	for _, failure := range netproxy.Failures(err) {
		if failure.Origin == netproxy.OriginLocalCleanup || failure.Origin == netproxy.OriginCaller {
			continue
		}
		if failure.Scope == netproxy.ScopeOperation && (failure.Reason == netproxy.ReasonDeadline || failure.Reason == netproxy.ReasonCanceled) {
			continue
		}
		warn = true
	}
	if warn {
		stats.DefaultStore.RecordError(path)
	}
	return warn
}

// spliceEndpoint preserves the raw TCP capabilities used by the direct path
// while giving its user-space operations the same provenance as relayTCP.
type spliceEndpoint struct {
	splice.TCPConn
	endpoint *relayEndpoint
}

func (c *spliceEndpoint) Read(p []byte) (int, error) {
	n, err := c.TCPConn.Read(p)
	if err == io.EOF {
		return n, err
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
