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

	log "github.com/sirupsen/logrus"
)

type Server struct {
	listener net.Listener
	http     *http.Server
	cancel   context.CancelFunc
	mu       sync.RWMutex
	handler  http.Handler
	secure   TLSHandler
}

// TLSHandler serves only the HTTPS branch of a shared TCP API listener.
type TLSHandler interface {
	http.Handler
	TLSConfig(*tls.ClientHelloInfo) (*tls.Config, error)
	TLSGeneration() string
}

type tlsGenerationKey struct{}
type tlsConnectionGeneration struct{ value string }

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
	provider := s.secure
	if provider == nil {
		return nil, fmt.Errorf("certificate test is starting or reloading")
	}
	generation, ok := hello.Context().Value(tlsGenerationKey{}).(*tlsConnectionGeneration)
	if !ok {
		return nil, fmt.Errorf("missing certificate test connection context")
	}
	generation.value = provider.TLSGeneration()
	return provider.TLSConfig(hello)
}

func (s *Server) Addr() net.Addr { return s.listener.Addr() }

// SetHandler waits for all requests using the previous handler to finish.
// Passing nil drains the control plane before the daemon closes it.
func (s *Server) SetHandler(handler http.Handler) {
	s.SetHandlers(handler, nil)
}

// SetHandlers publishes both protocol branches atomically after draining their
// prior requests. A nil TLS handler rejects HTTPS while retaining ordinary HTTP.
func (s *Server) SetHandlers(handler http.Handler, secure TLSHandler) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handler = handler
	s.secure = secure
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r.TLS != nil {
		generation, ok := r.Context().Value(tlsGenerationKey{}).(*tlsConnectionGeneration)
		if !ok || s.secure == nil || generation.value == "" || generation.value != s.secure.TLSGeneration() {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Connection", "close")
			http.Error(w, "certificate test configuration changed; start a new connection", http.StatusServiceUnavailable)
			return
		}
		s.secure.ServeHTTP(w, r)
		return
	}
	if s.handler == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"API is starting or reloading"}`))
		return
	}
	s.handler.ServeHTTP(w, r)
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
	s.SetHandler(nil)
}
