package protocol

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

// Handshake owns conn until the exchange succeeds. Cancellation interrupts only
// this connection or stream; no callback may outlive a successful handoff.
func Handshake(ctx context.Context, conn net.Conn, exchange func() error) error {
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return err
	}
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return err
		}
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
		close(done)
	})
	err := exchange()
	closedByContext := !stop()
	if closedByContext {
		<-done
	}
	cause := ctx.Err()
	// The socket deadline may fire before the context timer publishes Err.
	// Its source is still the caller's deadline; retain any independent fatal.
	if cause == nil && hasDeadline && !time.Now().Before(deadline) {
		cause = context.DeadlineExceeded
	}
	if cause != nil {
		var causes []error
		for _, failure := range netproxy.Failures(err) {
			if closedByContext && (failure.Scope == netproxy.ScopeUnknown || failure.Scope == netproxy.ScopeOperation) && handshakeClosed(failure.Cause) {
				failure.Scope, failure.Origin = netproxy.ScopeOperation, netproxy.OriginLocalCleanup
			}
			causes = append(causes, &failure)
		}
		causes = append(causes, netproxy.WrapFailure(cause, netproxy.Failure{Phase: netproxy.OpHandshake, Scope: netproxy.ScopeOperation, Origin: netproxy.OriginCaller}))
		err = errors.Join(causes...)
	}
	if lease := netproxy.DependencyOf(conn); !lease.Valid() {
		err = errors.Join(err, lease.Cause())
	}
	if err == nil {
		err = conn.SetDeadline(time.Time{})
	}
	if err != nil {
		_ = conn.Close()
	}
	return err
}

// The cancellation callback supplies the local-close provenance. Do not use
// errors.Is here: independent QUIC connection failures also match net.ErrClosed.
func handshakeClosed(err error) bool {
	switch err {
	case net.ErrClosed, io.ErrClosedPipe:
		return true
	}
	switch err := err.(type) {
	case interface{ Unwrap() error }:
		// Protocols add context with %w (for example, "socks5 read reply").
		// Follow the concrete chain without treating compatibility Is methods
		// as proof of a local close.
		return handshakeClosed(err.Unwrap())
	}
	return false
}
