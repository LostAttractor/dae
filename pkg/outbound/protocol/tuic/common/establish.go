// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"crypto/tls"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/quic-go"
)

// QUICHooks describes protocol-specific setup before publishing a connection.
// Authenticate must finish only the synchronous part of authentication. A
// protocol may start its continuing authentication worker after publication.
type QUICHooks struct {
	TLSConfig            *tls.Config
	QUICConfig           *quic.Config
	Early                bool
	CongestionController string
	CWND                 int
	Authenticate         func(context.Context, *quic.Conn) error
	AuthenticationError  quic.ApplicationErrorCode
}

type EstablishedQUIC struct {
	Conn      *quic.Conn
	Transport *quic.Transport
	Lease     *netproxy.Lease
}

// EstablishQUIC returns ownership only after handshake, authentication setup and
// dependency validation. Every failure closes both QUIC and its packet transport.
func EstablishQUIC(ctx context.Context, dialer netproxy.Dialer, dial DialFunc, ref netproxy.ResourceRef, hooks QUICHooks) (_ EstablishedQUIC, err error) {
	transport, addr, err := dial(ctx, dialer)
	if err != nil {
		return EstablishedQUIC{}, err
	}
	var conn *quic.Conn
	var code quic.ApplicationErrorCode
	var reason string
	defer func() {
		if err != nil {
			if conn != nil {
				_ = conn.CloseWithError(code, reason)
			}
			_ = transport.Close()
			_ = transport.Conn.Close()
		}
	}()
	if hooks.Early {
		conn, err = transport.DialEarly(ctx, addr, hooks.TLSConfig, hooks.QUICConfig)
	} else {
		conn, err = transport.Dial(ctx, addr, hooks.TLSConfig, hooks.QUICConfig)
	}
	if err != nil {
		return EstablishedQUIC{}, err
	}
	SetCongestionController(conn, hooks.CongestionController, hooks.CWND)
	if err = hooks.Authenticate(ctx, conn); err != nil {
		code, reason = hooks.AuthenticationError, "authentication failed"
		return EstablishedQUIC{}, WrapQUICError(err, ref, nil, netproxy.OpHandshake, nil)
	}
	if err = ctx.Err(); err != nil {
		reason = "establishment canceled"
		return EstablishedQUIC{}, err
	}
	lease := netproxy.NewLease(ref, netproxy.DependencyOf(transport.Conn))
	if !lease.Valid() {
		reason = "dependency invalidated during establishment"
		return EstablishedQUIC{}, lease.Cause()
	}
	return EstablishedQUIC{Conn: conn, Transport: transport, Lease: lease}, nil
}

// WatchFailure starts after the client has published its fields and readiness.
// Capture this connection's lease so cleanup cannot redirect its notification.
func (q EstablishedQUIC) WatchFailure(fail func(error)) {
	go func() {
		select {
		case <-q.Conn.Context().Done():
			fail(context.Cause(q.Conn.Context()))
		case <-q.Lease.Done():
			fail(q.Lease.Cause())
		}
	}()
}
