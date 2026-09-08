// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// The listener belongs to the daemon, so reloading a control plane can reuse
// its port. A handler switch waits for requests using the old plane to finish.
type apiServer struct {
	port     uint16
	listener net.Listener
	server   *http.Server
	mu       sync.RWMutex
	handler  http.Handler
}

// Reserve a changed port before retiring the active plane. Until publication,
// a new listener reports unavailable and an existing listener remains intact.
func prepareAPIServer(current *apiServer, port uint16) (*apiServer, error) {
	if port == 0 {
		return nil, nil
	}
	if current != nil && current.port == port {
		return current, nil
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(int(port))))
	if err != nil {
		return nil, fmt.Errorf("global.api_port: %w", err)
	}
	s := &apiServer{port: port, listener: listener}
	s.server = &http.Server{
		Handler: s, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10,
	}
	go func() {
		if err := s.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			log.WithError(err).Error("HTTP API server stopped")
		}
	}()
	return s, nil
}

func (s *apiServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.handler == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"HTTP API is starting or reloading"}`))
		return
	}
	s.handler.ServeHTTP(w, r)
}

func (s *apiServer) setHandler(handler http.Handler) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handler = handler
}

func (s *apiServer) Close() {
	if s == nil {
		return
	}
	s.setHandler(nil)
	stopHTTPServer("HTTP API", s.server, s.listener)
}
