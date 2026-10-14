// SPDX-License-Identifier: AGPL-3.0-only

package http2

import (
	"context"
	"crypto/tls"
	"log"
	"maps"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"
)

func init() {
	NoBody = http.NoBody
	LocalAddrContextKey = http.LocalAddrContextKey
}

// HTTPServer adapts the pinned protocol implementation to net/http. Configure
// the supplied server before construction; it must not change while serving.
// ServeConn owns accepted connections; Shutdown sends GOAWAY and joins them.
type HTTPServer struct {
	protocol Server
	base     *http.Server
	mu       sync.Mutex
	closed   bool
	serving  int
	conns    map[*serverConn]struct{}
	done     chan struct{}
	doneOnce sync.Once
}

func NewHTTPServer(base *http.Server) (*HTTPServer, error) {
	s := &HTTPServer{base: base, conns: make(map[*serverConn]struct{}), done: make(chan struct{})}
	tcfg := base.TLSConfig
	if tcfg == nil {
		tcfg = new(tls.Config)
	}
	if err := s.protocol.Configure(netHTTPConfig{s}, tcfg); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *HTTPServer) ServeConn(ctx context.Context, conn net.Conn) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = conn.Close()
		return
	}
	s.serving++
	s.mu.Unlock()
	var active *serverConn
	defer func() {
		s.mu.Lock()
		delete(s.conns, active)
		s.serving--
		if s.closed && s.serving == 0 {
			s.doneOnce.Do(func() { close(s.done) })
		}
		s.mu.Unlock()
	}()
	ctx = context.WithValue(ctx, http.ServerContextKey, s.base)
	ctx = context.WithValue(ctx, http.LocalAddrContextKey, conn.LocalAddr())
	s.protocol.serveConn(conn, &ServeConnOpts{
		Context: ctx, BaseConfig: netHTTPConfig{s}, Handler: netHTTPHandler{s.base.Handler},
	}, func(sc *serverConn) {
		// Publish before protocol setup so a concurrent Shutdown cannot miss
		// a connection accepted just before it closed admission.
		s.mu.Lock()
		active = sc
		s.conns[sc] = struct{}{}
		closed := s.closed
		s.mu.Unlock()
		if closed {
			sc.startGracefulShutdown()
		}
	})
}

func (s *HTTPServer) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	connections := slices.Collect(maps.Keys(s.conns))
	if s.serving == 0 {
		s.doneOnce.Do(func() { close(s.done) })
	}
	s.mu.Unlock()
	for _, conn := range connections {
		conn.startGracefulShutdown()
	}
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type netHTTPConfig struct{ server *HTTPServer }

func (c netHTTPConfig) MaxHeaderBytes() int { return c.server.base.MaxHeaderBytes }
func (c netHTTPConfig) MaxHeaderValueCount() int {
	if count := c.server.base.MaxHeaderValueCount; count > 0 {
		return count
	}
	return http.DefaultMaxHeaderValueCount
}
func (c netHTTPConfig) ConnState(conn net.Conn, state ConnState) {
	if notify := c.server.base.ConnState; notify != nil {
		notify(conn, http.ConnState(state))
	}
}
func (c netHTTPConfig) DoKeepAlives() bool {
	c.server.mu.Lock()
	defer c.server.mu.Unlock()
	return !c.server.closed
}
func (c netHTTPConfig) WriteTimeout() time.Duration    { return c.server.base.WriteTimeout }
func (c netHTTPConfig) SendPingTimeout() time.Duration { return c.server.base.ReadTimeout }
func (c netHTTPConfig) ErrorLog() *log.Logger          { return c.server.base.ErrorLog }
func (c netHTTPConfig) ReadTimeout() time.Duration     { return c.server.base.ReadTimeout }
func (c netHTTPConfig) DisableClientPriority() bool    { return c.server.base.DisableClientPriority }
func (c netHTTPConfig) IdleTimeout() time.Duration     { return c.server.base.IdleTimeout }
func (c netHTTPConfig) HTTP2Config() Config {
	if c.server.base.HTTP2 == nil {
		return Config{}
	}
	return Config(*c.server.base.HTTP2)
}

type netHTTPHandler struct{ handler http.Handler }

func (h netHTTPHandler) ServeHTTP(w *ResponseWriter, req *ServerRequest) {
	r := (&http.Request{
		Proto: req.Proto, ProtoMajor: req.ProtoMajor, ProtoMinor: req.ProtoMinor,
		Method: req.Method, URL: req.URL, Header: http.Header(req.Header),
		RequestURI: req.RequestURI, Trailer: http.Header(req.Trailer), Body: req.Body,
		Host: req.Host, ContentLength: req.ContentLength, RemoteAddr: req.RemoteAddr,
		TLS: req.TLS, MultipartForm: req.MultipartForm,
	}).WithContext(req.Context)
	handler := h.handler
	if handler == nil {
		handler = http.DefaultServeMux
	}
	handler.ServeHTTP(netHTTPResponseWriter{w}, r)
}

type netHTTPResponseWriter struct{ *ResponseWriter }

func (w netHTTPResponseWriter) Header() http.Header { return http.Header(w.ResponseWriter.Header()) }
func (w netHTTPResponseWriter) Flush()              { _ = w.ResponseWriter.FlushError() }
func (w netHTTPResponseWriter) Push(target string, opts *http.PushOptions) error {
	var method string
	var header Header
	if opts != nil {
		method, header = opts.Method, Header(opts.Header)
	}
	err := w.ResponseWriter.Push(target, method, header)
	if err == ErrNotSupported {
		return http.ErrNotSupported
	}
	return err
}
