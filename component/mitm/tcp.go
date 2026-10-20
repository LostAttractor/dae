// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/internal/http2"
	"github.com/daeuniverse/dae/internal/pluginctx"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	logrus "github.com/sirupsen/logrus"
)

func (h *Host) ServeConn(conn net.Conn, flow plugin.Flow, plan UpstreamPlanner) (err error) {
	host, port := flow.Host, flow.Port
	original := conn
	if err := h.track(original); err != nil {
		_ = conn.Close()
		return err
	}
	defer h.untrack(original)
	flow.Source, _ = netip.ParseAddrPort(conn.RemoteAddr().String())
	flow.Destination, _ = netip.ParseAddrPort(conn.LocalAddr().String())
	diagnostic := false
	for _, scope := range h.diagnosticScopes {
		if scope.Match(host, port) {
			diagnostic = true
			break
		}
	}
	ctx, cancel := context.WithCancel(pluginctx.WithIDs(context.Background(), strconv.FormatUint(serial.Add(1), 10), ""))
	defer cancel()
	connection, _ := plugin.IDs(ctx)
	logger := h.options.Logger.WithFields(logrus.Fields{
		"connection_id": connection, "host": host, "port": port,
		"source": flow.Source, "destination": flow.Destination,
	})
	started := time.Now()
	defer func() {
		entry := logger.WithFields(logrus.Fields{"event": "mitm_connection_end", "elapsed_ms": time.Since(started).Milliseconds()})
		if err != nil {
			entry = entry.WithError(resource.RedactError(err))
		}
		entry.Trace("MITM TCP connection finished")
	}()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	first, err := reader.Peek(1)
	if err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Time{})
	conn = &bufferedConn{Conn: conn, reader: reader}
	scheme := "http"
	var state *tls.ConnectionState
	if first[0] == 0x16 {
		if h.options.Authority == nil {
			return errors.New("mitm: HTTPS requires a CA")
		}
		scheme = "https"
		cfg := h.interceptionTLSConfig(flow)
		cfg.NextProtos = []string{"h2", "http/1.1"}
		// Diagnostic replies close HTTP/1 connections so each browser test
		// exercises a fresh handshake and kernel admission after reload.
		if diagnostic {
			cfg.NextProtos = []string{"http/1.1"}
		}
		tlsConn := tls.Server(conn, cfg)
		handshake, stop := context.WithTimeout(ctx, 10*time.Second)
		err = tlsConn.HandshakeContext(handshake)
		stop()
		if err != nil {
			return fmt.Errorf("mitm TLS: %w", err)
		}
		conn = tlsConn
		s := tlsConn.ConnectionState()
		state = &s
		logger.WithFields(logrus.Fields{"event": "mitm_client_tls", "alpn": s.NegotiatedProtocol}).Trace("MITM client TLS handshake finished")
	}
	handler, closeTransport := h.HandlerForFlow(scheme, flow, plan)
	defer closeTransport()
	base := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          log.New(logWriter{logger, logrus.DebugLevel}, "", 0),
	}
	if diagnostic {
		// ReverseProxy removes hop-by-hop Connection headers from plugin replies.
		// Enforce fresh diagnostic connections at the actual downstream server.
		base.SetKeepAlivesEnabled(false)
	}
	if state != nil && state.NegotiatedProtocol == "h2" {
		base.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: 64, MaxReadFrameSize: 1 << 20, SendPingTimeout: 60 * time.Second}
		base.HTTP2.CountError = func(kind string) {
			logger.WithFields(logrus.Fields{"event": "mitm_http2_error", "reason": kind}).Debug("MITM client HTTP/2 error")
		}
		h2, err := http2.NewHTTPServer(base)
		if err != nil {
			return err
		}
		if err := h.attach(original, h2.Shutdown); err != nil {
			return err
		}
		h2.ServeConn(ctx, conn)
		return nil
	}
	if err := h.attach(original, base.Shutdown); err != nil {
		return err
	}
	listener := &singleConnListener{Conn: conn, done: make(chan struct{}), finished: make(chan struct{})}
	err = base.Serve(listener)
	if listener.accepted {
		<-listener.finished
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *bufferedConn) CloseWrite() error { return netproxy.CloseWrite(c.Conn) }

type singleConnListener struct {
	net.Conn
	once     sync.Once
	accepted bool
	done     chan struct{}
	finished chan struct{}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return &acceptedConn{Conn: l.Conn, listener: l}, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *singleConnListener) Addr() net.Addr { return l.LocalAddr() }
func (l *singleConnListener) Close() (err error) {
	// Closing a listener stops Accept; it must not close its active request.
	l.once.Do(func() { close(l.done) })
	return err
}

type acceptedConn struct {
	net.Conn
	listener *singleConnListener
	once     sync.Once
	err      error
}

func (c *acceptedConn) CloseWrite() error { return netproxy.CloseWrite(c.Conn) }

func (c *acceptedConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); close(c.listener.finished); _ = c.listener.Close() })
	return c.err
}
