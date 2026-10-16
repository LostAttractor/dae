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
	"net"
	"net/http"
	"sync"
	"time"

	localca "github.com/daeuniverse/dae/component/ca"
	log "github.com/sirupsen/logrus"
)

type Server struct {
	listener      net.Listener
	http          *http.Server
	cancel        context.CancelFunc
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
	var listener net.Listener
	var err error
	if network == "unix" {
		listener, err = listenUnix(address)
	} else {
		listener, err = net.Listen(network, address)
	}
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{listener: listener, cancel: cancel}
	if network != "unix" {
		listener = newProtocolListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: s.tlsConfig})
		s.listener = listener
	}
	s.http = &http.Server{Handler: s, BaseContext: func(net.Listener) context.Context { return ctx }, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	if network != "unix" {
		s.http.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, tlsGenerationKey{}, new(tlsConnectionGeneration))
		}
	}
	go func() {
		if err := s.http.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			log.WithError(err).Error("API server stopped")
		}
	}()
	return s, nil
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
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"API is starting or reloading"}`))
		return
	}
	s.handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tlsIdentityKey{}, s.tls)))
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
