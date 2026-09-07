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
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/component/mitm/plugin"
	"golang.org/x/net/http2"
)

var serial atomic.Uint64

func (h *Host) ServeConn(conn net.Conn, host string, port uint16, dial DialContext) error {
	defer conn.Close()
	original := conn
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return net.ErrClosed
	}
	h.connections[original] = nil
	h.serving.Add(1)
	h.mu.Unlock()
	defer h.serving.Done()
	defer func() { h.mu.Lock(); delete(h.connections, original); h.mu.Unlock() }()
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
		cfg := h.options.Authority.TLSConfig()
		getCertificate := cfg.GetCertificate
		cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if !strings.EqualFold(strings.TrimSuffix(hello.ServerName, "."), strings.TrimSuffix(host, ".")) {
				return nil, errors.New("mitm: TLS SNI changed after routing")
			}
			return getCertificate(hello)
		}
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
	handler, closeTransport := h.HandlerForFlow(scheme, flow, dial)
	defer closeTransport()
	base := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          log.New(logWriter{h}, "", 0),
	}
	h2 := &http2.Server{MaxConcurrentStreams: 64, IdleTimeout: 90 * time.Second, MaxReadFrameSize: 1 << 20}
	if err := http2.ConfigureServer(base, h2); err != nil {
		return err
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return net.ErrClosed
	}
	h.connections[original] = base
	h.mu.Unlock()
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Handler has a connection-local transport pool: different original flows,
// destinations, outbound policies and TLS identities cannot share its sockets.
func (h *Host) Handler(scheme, host string, port uint16, dial DialContext) (http.Handler, func()) {
	return h.HandlerForFlow(scheme, plugin.Flow{Host: host, Port: port}, dial)
}

func (h *Host) HandlerForFlow(scheme string, flow plugin.Flow, dial DialContext) (http.Handler, func()) {
	host, port := flow.Host, flow.Port
	transport := &http.Transport{
		DialContext:            dial,
		ForceAttemptHTTP2:      true,
		DisableCompression:     true,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		IdleConnTimeout:        90 * time.Second,
		MaxIdleConnsPerHost:    8,
		MaxResponseHeaderBytes: 1 << 20,
	}
	if h.options.UpstreamTLSConfig != nil {
		transport.TLSClientConfig = h.options.UpstreamTLSConfig.Clone()
	}
	client := &http.Client{Transport: transport}
	chain := h.chain(flow, func(e *plugin.Exchange) (*http.Response, error) { return transport.RoundTrip(e.Request) })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			http.Error(w, "MITM is draining", http.StatusServiceUnavailable)
			return
		}
		h.requests.Add(1)
		h.mu.Unlock()
		defer h.requests.Done()
		ctx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(h.forceContext, cancel)
		defer func() { stop(); cancel() }()
		r = r.WithContext(ctx)
		if r.Method == http.MethodConnect {
			http.Error(w, "CONNECT is not supported on the transparent listener", 405)
			return
		}
		if !sameAuthority(r.Host, host, port, scheme) {
			http.Error(w, "Request authority differs from intercepted destination", 421)
			return
		}
		r.URL.Scheme, r.URL.Host = scheme, r.Host
		r.RequestURI = ""
		connection, _ := plugin.IDs(r.Context())
		r = r.WithContext(plugin.WithIDs(r.Context(), connection, strconv.FormatUint(serial.Add(1), 10)))
		controller := http.NewResponseController(w)
		defer controller.SetReadDeadline(time.Time{})
		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) { req.RemoteAddr = "" },
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				response, err := chain(&plugin.Exchange{Request: req, Client: client, SetReadDeadline: controller.SetReadDeadline})
				_ = controller.SetReadDeadline(time.Time{})
				if err != nil {
					return nil, err
				}
				response.Request = req
				return response, nil
			}),
			ModifyResponse: func(response *http.Response) error {
				if len(response.Trailer) > 0 {
					response.Header.Del("Content-Length")
					response.ContentLength = -1
				}
				response.Header.Del("Alt-Svc")
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				if errors.Is(err, plugin.ErrAbort) {
					panic(http.ErrAbortHandler)
				}
				status := http.StatusBadGateway
				var failure *plugin.HTTPError
				if errors.As(err, &failure) {
					status = failure.Status
				}
				http.Error(w, "MITM upstream processing failed", status)
			}, ErrorLog: log.New(logWriter{h}, "", 0),
		}
		proxy.ServeHTTP(w, r)
	}), transport.CloseIdleConnections
}

func sameAuthority(authority, host string, port uint16, scheme string) bool {
	u, err := url.Parse(scheme + "://" + authority)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	p := u.Port()
	if p == "" {
		p = "80"
		if scheme == "https" {
			p = "443"
		}
	}
	return strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), strings.TrimSuffix(host, ".")) && p == strconv.Itoa(int(port))
}

type logWriter struct{ host *Host }

func (w logWriter) Write(p []byte) (int, error) {
	if w.host.options.Log != nil {
		w.host.options.Log(string(p))
	}
	return len(p), nil
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
