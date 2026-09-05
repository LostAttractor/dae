// SPDX-License-Identifier: AGPL-3.0-only

package surgemodule

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/component/mitmca"
	"golang.org/x/net/http2"
)

type DialContext func(context.Context, string, string) (net.Conn, error)

type requestIDKey struct{}

var nextRequestID atomic.Uint64

type EngineOptions struct {
	Modules []*Module

	Authority            *mitmca.Authority
	Runtime              *Runtime
	MaxBodySize          int64
	MaxConcurrentScripts int
	ScriptTimeout        time.Duration
	UpstreamTLSConfig    *tls.Config
	Log                  func(string)
	// Trace receives automatic diagnostics concurrently from connections. A nil
	// callback disables tracing. TraceEnabled optionally avoids formatting when
	// the daemon's current log level filters out these diagnostics.
	Trace        func(string)
	TraceEnabled func() bool
}

// Engine applies module rules to intercepted HTTP connections. Client selection
// and outbound routing are decided by the caller before ServeConn.
type Engine struct {
	options EngineOptions
	slots   chan struct{}
}

func NewEngine(o EngineOptions) (*Engine, error) {
	for _, module := range o.Modules {
		if len(module.Hostnames) != 0 && o.Authority == nil {
			return nil, fmt.Errorf("surge module %q: MITM requires ca_cert and ca_key; generate them with dae mitm ca generate", module.Name)
		}
		if len(module.Scripts) != 0 && o.Runtime == nil {
			return nil, errors.New("surge: HTTP scripts require a QuickJS runtime")
		}
	}
	if o.MaxBodySize <= 0 || o.MaxConcurrentScripts <= 0 || o.ScriptTimeout <= 0 {
		return nil, errors.New("surge: positive body, concurrency and timeout limits are required")
	}
	return &Engine{options: o, slots: make(chan struct{}, o.MaxConcurrentScripts)}, nil
}

// Authority is the CA used by this engine, including its public certificate.
func (e *Engine) Authority() *mitmca.Authority { return e.options.Authority }

// Hostnames returns the union of positive patterns for kernel capture. Local
// exclusions cannot be flattened into this list: Match evaluates them within
// each module after the connection reaches userspace.
func (e *Engine) Hostnames() []string {
	var hosts []string
	seen := make(map[string]bool)
	for _, module := range e.options.Modules {
		for _, host := range module.Hostnames {
			if strings.HasPrefix(host, "-") || seen[host] {
				continue
			}
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// ModuleRules returns supported routing rules in module/profile order.
func (e *Engine) ModuleRules() []ModuleRule {
	var rules []ModuleRule
	for _, module := range e.options.Modules {
		rules = append(rules, module.Rules...)
	}
	return rules
}

// Match checks the destination against module hostnames. Port 80 uses the same
// explicit host allowlist as TLS, for http-request module rules.
func (e *Engine) Match(host string, port uint16) bool {
	if host == "" {
		return false
	}
	for _, module := range e.options.Modules {
		if module.matchConnection(host, port) {
			return true
		}
	}
	return false
}

// forConnection fixes HTTP processing to modules that allow the intercepted
// destination. Rewrites cannot activate a different module by changing URL or
// Host. The connection shares the engine's runtime, CA and concurrency limit.
func (e *Engine) forConnection(host string, port uint16) *Engine {
	scoped := *e
	scoped.options.Modules = nil
	for _, module := range e.options.Modules {
		if module.matchConnection(host, port) {
			scoped.options.Modules = append(scoped.options.Modules, module)
		}
	}
	return &scoped
}

// ServeConn terminates a connection selected for interception. dial must
// retain dae's selected outbound and original destination handling; it is never
// replaced with a process-global, unmarked net.Dialer.
func (e *Engine) ServeConn(conn net.Conn, host string, port uint16, dial DialContext) (err error) {
	defer conn.Close()
	connectionID := strconv.FormatUint(nextConnectionID.Add(1), 10)
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), connectionIDKey{}, connectionID))
	defer cancel()
	started := time.Now()
	e.trace(ctx, "mitm_start", "host", host, "port", port, "source", conn.RemoteAddr())
	defer func() {
		outcome := "closed"
		if err != nil {
			outcome = "failed"
		}
		e.trace(ctx, "mitm_end", "host", host, "port", port, "outcome", outcome, "elapsed_ms", time.Since(started).Milliseconds())
		if err != nil {
			err = fmt.Errorf("surge connection_id=%s host=%q port=%d: %w", connectionID, host, port, err)
		}
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
		scheme = "https"
		cfg := e.options.Authority.TLSConfig()
		getCertificate := cfg.GetCertificate
		cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if !strings.EqualFold(strings.TrimSuffix(hello.ServerName, "."), strings.TrimSuffix(host, ".")) {
				return nil, errors.New("surge: TLS SNI changed after routing")
			}
			return getCertificate(hello)
		}
		cfg.NextProtos = []string{"h2", "http/1.1"}
		tlsConn := tls.Server(conn, cfg)
		handshakeCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		err = tlsConn.HandshakeContext(handshakeCtx)
		stop()
		if err != nil {
			e.trace(ctx, "tls_handshake_failed", "host", host, "port", port, "reason", traceErrorReason(err))
			return fmt.Errorf("surge TLS handshake: %w", err)
		}
		conn = tlsConn
		s := tlsConn.ConnectionState()
		state = &s
		e.trace(ctx, "tls_ready", "host", host, "port", port, "protocol", s.NegotiatedProtocol, "tls_version", tls.VersionName(s.Version))
	} else {
		e.trace(ctx, "http_ready", "host", host, "port", port)
	}
	handler, closeTransport := e.Handler(scheme, host, port, dial)
	defer closeTransport()
	if state != nil && state.NegotiatedProtocol == "h2" {
		server := &http2.Server{MaxConcurrentStreams: 64, IdleTimeout: 90 * time.Second, MaxReadFrameSize: 1 << 20}
		server.ServeConn(conn, &http2.ServeConnOpts{Context: ctx, Handler: handler, BaseConfig: &http.Server{MaxHeaderBytes: 1 << 20}})
		return nil
	}
	listener := &singleConnListener{Conn: conn, done: make(chan struct{})}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout: 60 * time.Second,
		IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20,
		BaseContext: func(net.Listener) context.Context { return ctx },
		ErrorLog:    log.New(engineLogWriter{e}, "", 0),
	}
	err = server.Serve(listener)
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Handler is also useful to embed or test the HTTP processing independently
// from the transparent TCP listener. Call close when that connection ends.
func (e *Engine) Handler(scheme, host string, port uint16, dial DialContext) (http.Handler, func()) {
	e = e.forConnection(host, port)
	transport := &http.Transport{
		DialContext: dial, ForceAttemptHTTP2: true, DisableCompression: true,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout: 90 * time.Second, MaxIdleConnsPerHost: 8,
		MaxResponseHeaderBytes: 1 << 20,
	}
	if e.options.UpstreamTLSConfig != nil {
		transport.TLSClientConfig = e.options.UpstreamTLSConfig.Clone()
	}
	client := &http.Client{Transport: transport, Timeout: e.options.ScriptTimeout}
	proxy := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			// Suppress ReverseProxy's implicit X-Forwarded-For append while
			// retaining any forwarding headers the client already supplied.
			r.RemoteAddr = ""
		},
		Transport: transport,
		ModifyResponse: func(response *http.Response) error {
			e.traceRequest(response.Request, "upstream_response", "status", response.StatusCode)
			if err := e.processResponse(response, client); err != nil {
				return err
			}
			if len(response.Trailer) != 0 {
				// HTTP/1.1 needs chunked framing to send trailers, even when
				// a buffered script result has a known body length.
				response.Header.Del("Content-Length")
				response.ContentLength = -1
			}
			// HTTP/3 bypasses the TCP interception path. Do not advertise it.
			response.Header.Del("Alt-Svc")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			e.traceRequest(r, "upstream_failed", "reason", traceErrorReason(err))
			if errors.Is(err, errScriptAbort) {
				panic(http.ErrAbortHandler)
			}
			e.logRequest(r, "surge proxy: "+err.Error())
			http.Error(w, "Surge upstream processing failed", http.StatusBadGateway)
		},
		ErrorLog: log.New(engineLogWriter{e}, "", 0),
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			http.Error(w, "CONNECT is not supported on the transparent listener", http.StatusMethodNotAllowed)
			return
		}
		// HTTP/2 connection coalescing must not expose hosts outside this
		// connection's SNI and the configured MITM scope.
		if !sameAuthority(r.Host, host, port, scheme) {
			http.Error(w, "Request authority differs from intercepted destination", http.StatusMisdirectedRequest)
			return
		}
		r.URL.Scheme, r.URL.Host = scheme, r.Host
		r.RequestURI = ""
		r = r.WithContext(context.WithValue(r.Context(), requestIDKey{}, strconv.FormatUint(nextRequestID.Add(1), 10)))
		e.traceRequest(r, "request_begin", "protocol", r.Proto)
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(time.Now().Add(e.options.ScriptTimeout))
		response, err := e.processRequest(r, client)
		_ = controller.SetReadDeadline(time.Time{})
		if err != nil {
			e.traceRequest(r, "request_failed", "reason", traceErrorReason(err))
			if errors.Is(err, errScriptAbort) {
				panic(http.ErrAbortHandler)
			}
			e.logRequest(r, "surge request: "+err.Error())
			status := http.StatusBadGateway
			if errors.Is(err, errBodyTooLarge) {
				status = http.StatusRequestEntityTooLarge
			}
			http.Error(w, "Surge request processing failed", status)
			return
		}
		if response != nil {
			e.traceRequest(r, "response_local", "status", response.StatusCode, "body_bytes", response.ContentLength)
			defer response.Body.Close()
			for k, values := range response.Header {
				for _, v := range values {
					w.Header().Add(k, v)
				}
			}
			for k := range response.Trailer {
				w.Header().Add("Trailer", k)
			}
			w.WriteHeader(response.StatusCode)
			if responseHasBody(r.Method, response.StatusCode) {
				_, _ = io.Copy(w, response.Body)
			}
			for k, values := range response.Trailer {
				w.Header()[k] = values
			}
			return
		}
		e.traceRequest(r, "request_forward")
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

func (e *Engine) log(message string) {
	if e.options.Log != nil {
		e.options.Log(message)
	}
}

type engineLogWriter struct{ engine *Engine }

func (w engineLogWriter) Write(p []byte) (int, error) { w.engine.log(string(p)); return len(p), nil }

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
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *singleConnListener) Addr() net.Addr { return l.LocalAddr() }
func (l *singleConnListener) Close() (err error) {
	l.once.Do(func() {
		err = l.Conn.Close()
		close(l.done)
	})
	return err
}
