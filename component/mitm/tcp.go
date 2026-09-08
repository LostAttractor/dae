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

	"github.com/daeuniverse/dae/component/mitm/plugin"
	logrus "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

func (h *Host) ServeConn(conn net.Conn, host string, port uint16, plan UpstreamPlanner) error {
	original := conn
	if err := h.track(original); err != nil {
		_ = conn.Close()
		return err
	}
	defer h.untrack(original)
	flow := plugin.Flow{Host: host, Port: port}
	flow.Source, _ = netip.ParseAddrPort(conn.RemoteAddr().String())
	flow.Destination, _ = netip.ParseAddrPort(conn.LocalAddr().String())
	ctx, cancel := context.WithCancel(plugin.WithIDs(context.Background(), strconv.FormatUint(serial.Add(1), 10), ""))
	defer cancel()
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
		cfg := h.options.Authority.TLSConfig(host)
		cfg.NextProtos = []string{"h2", "http/1.1"}
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
	}
	handler, closeTransport := h.HandlerForFlow(scheme, flow, plan)
	defer closeTransport()
	base := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          log.New(logWriter{h.options.Logger, logrus.DebugLevel}, "", 0),
	}
	h2 := &http2.Server{MaxConcurrentStreams: 64, IdleTimeout: 90 * time.Second, MaxReadFrameSize: 1 << 20}
	if err := http2.ConfigureServer(base, h2); err != nil {
		return err
	}
	if err := h.attach(original, base.Shutdown); err != nil {
		return err
	}
	if state != nil && state.NegotiatedProtocol == "h2" {
		// ConfigureServer binds h2 to base. Passing BaseConfig here makes
		// x/net's Go 1.27 adapter copy it, detaching Shutdown from this conn.
		h2.ServeConn(conn, &http2.ServeConnOpts{Context: ctx, Handler: handler})
		return nil
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

func (c *acceptedConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); close(c.listener.finished); _ = c.listener.Close() })
	return c.err
}
