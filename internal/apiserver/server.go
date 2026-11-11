// SPDX-License-Identifier: AGPL-3.0-only

// Package apiserver serves the daemon API over TCP and Unix sockets. It owns
// routing, request validation, and draining across reloads. Runtime operations
// are supplied through stores; this package does not import control or clients.
package apiserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	localca "github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/internal/handoff"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
)

type Server struct {
	raw           net.Listener
	held          *handoff.Listener
	listener      net.Listener
	http          *http.Server
	cancel        context.CancelFunc
	initGate      sync.Once
	planeRequests *semaphore.Weighted
	mu            sync.RWMutex
	handler       http.Handler
	tls           *apiTLSIdentity
	daemonMu      sync.RWMutex
	daemonHandler http.Handler
}

type tlsGenerationKey struct{}
type tlsConnectionGeneration struct {
	identity    *apiTLSIdentity
	certificate uint64
}
type tlsIdentityKey struct{}

// Listen reserves the address immediately. Requests return 503 until SetHandler.
func Listen(network, address string) (*Server, error) {
	return listen(network, address, false)
}

// ListenHeld reserves a new candidate address without serving before commit.
func ListenHeld(network, address string) (*Server, error) {
	return listen(network, address, true)
}

func listen(network, address string, hold bool) (*Server, error) {
	var listener net.Listener
	var err error
	if network == "unix" {
		listener, err = listenUnix(address)
	} else {
		// Declare TCP; Go listeners otherwise default to MPTCP.
		var config net.ListenConfig
		config.SetMultipathTCP(false)
		listener, err = config.Listen(context.Background(), network, address)
	}
	if err != nil {
		return nil, err
	}
	raw := listener
	if admin, ok := raw.(*unixAdminListener); ok {
		raw = admin.Listener
	}
	var held *handoff.Listener
	if hold {
		held = handoff.Hold(listener)
		listener = held
	}
	return serveListener(listener, raw, network, held), nil
}

func FromFile(file *os.File, network string) (*Server, error) {
	raw, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}
	if local, ok := raw.(*net.UnixListener); ok {
		local.SetUnlinkOnClose(false)
	}
	held := handoff.Hold(raw)
	var listener net.Listener = held
	if network == "unix" {
		listener = &unixAdminListener{Listener: held, uid: uint32(os.Geteuid())}
	}
	return serveListener(listener, raw, network, held), nil
}

func serveListener(listener, raw net.Listener, network string, held *handoff.Listener) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{listener: listener, raw: raw, held: held, cancel: cancel}
	if network != "unix" {
		listener = newProtocolListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: s.tlsConfig})
		s.listener = listener
	}
	s.http = &http.Server{Handler: s, BaseContext: func(net.Listener) context.Context { return ctx }, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	if network != "unix" {
		s.http.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, tlsGenerationKey{}, new(tlsConnectionGeneration))
		}
	} else {
		s.http.ConnContext = unixConnContext
	}
	go func() {
		if err := s.http.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			log.WithError(err).Error("API server stopped")
		}
	}()
	return s
}

func (s *Server) File() (*os.File, error) {
	if s == nil {
		return nil, nil
	}
	return handoff.DupSocket(s.raw.(syscall.Conn), "api")
}

func (s *Server) Activate() {
	if s != nil && s.held != nil {
		s.held.Activate()
	}
}

// An inherited Unix descriptor must not unlink the serving path on rejection.
func (s *Server) SetOwnership(owned bool) {
	if s == nil {
		return
	}
	if local, ok := s.raw.(*net.UnixListener); ok {
		local.SetUnlinkOnClose(owned)
	}
}

func (s *Server) tlsConfig(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.tls == nil {
		return nil, fmt.Errorf("API HTTPS is unavailable")
	}
	generation, ok := hello.Context().Value(tlsGenerationKey{}).(*tlsConnectionGeneration)
	if !ok {
		return nil, fmt.Errorf("missing API connection context")
	}
	generation.identity = s.tls
	return s.tls.config, nil
}

func (s *Server) Addr() net.Addr { return s.listener.Addr() }

// SetOperations installs daemon-owned routes on the local socket. These do not
// touch a plane and remain available while its handler is drained or replaced.
// Remote requests continue to use the plane's current authorization policy.
func (s *Server) SetOperations(store OperationStore) {
	if s == nil {
		return
	}
	s.daemonMu.Lock()
	defer s.daemonMu.Unlock()
	s.daemonHandler = nil
	if store != nil {
		s.daemonHandler = NewHandler(Options{Operations: store})
	}
}

// SetHandler waits for all requests using the previous handler to finish.
// Passing nil drains the control plane before the daemon closes it, preserving
// the TLS identity and pending certificate challenges until Configure or Close.
func (s *Server) SetHandler(handler http.Handler) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handler = handler
}

// Pause drains plane requests without discarding the handler or its TLS state.
// Local operation routes remain available. Canceling the wait reopens admission.
func (s *Server) Pause(ctx context.Context) (resume func(), err error) {
	gate := s.requestGate()
	if err := gate.Acquire(ctx, math.MaxInt64); err != nil {
		return nil, context.Cause(ctx)
	}
	return func() { gate.Release(math.MaxInt64) }, nil
}

func (s *Server) requestGate() *semaphore.Weighted {
	s.initGate.Do(func() { s.planeRequests = semaphore.NewWeighted(math.MaxInt64) })
	return s.planeRequests
}

// Configure publishes one handler for HTTP and HTTPS after draining prior
// requests. A nil authority disables HTTPS; changing its identity retires old TLS
// connections so a previous CA handshake cannot authenticate new CA metadata.
// directory owns persistent API leaves, partitioned by CA and connected IP.
func (s *Server) Configure(handler http.Handler, authority *localca.Authority, directory string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handler = handler
	if authority == nil {
		s.tls.retire()
		s.tls = nil
	} else if s.tls == nil || s.tls.authority.Fingerprint() != authority.Fingerprint() || s.tls.directory != directory {
		s.tls.retire()
		s.tls = newAPITLSIdentity(authority, directory)
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if localAPISocket(r) && operationPath(r.URL.Path) {
		s.daemonMu.RLock()
		defer s.daemonMu.RUnlock()
		if s.daemonHandler != nil {
			s.daemonHandler.ServeHTTP(w, r)
			return
		}
	}
	gate := s.requestGate()
	if !gate.TryAcquire(1) {
		unavailable(w)
		return
	}
	defer gate.Release(1)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r.TLS != nil {
		generation, ok := r.Context().Value(tlsGenerationKey{}).(*tlsConnectionGeneration)
		if !ok || s.tls == nil || generation.identity != s.tls {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Connection", "close")
			http.Error(w, "API configuration changed; start a new connection", http.StatusServiceUnavailable)
			return
		}
	}
	if s.handler == nil {
		unavailable(w)
		return
	}
	s.handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tlsIdentityKey{}, s.tls)))
}

func unavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`{"error":"API is starting or reloading"}`))
}

// Stop closes ingress and cancels requests. Close joins their state mutations
// before the owner releases the control plane.
func (s *Server) Stop() {
	if s == nil {
		return
	}
	// Interrupt requests before joining them. A handler may be waiting for
	// cancellation or blocked reading/writing its connection while holding mu.
	s.cancel()
	_ = s.http.Close()
	// Also close when Serve has not yet registered the listener. UnixListener
	// owns unlinking, so repeated Close cannot unlink a replacement daemon's socket.
	_ = s.listener.Close()
}

func (s *Server) Close() {
	s.Stop()
	s.Configure(nil, nil, "")
	s.SetOperations(nil)
}
