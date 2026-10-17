// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

type observabilityServer struct {
	name     string
	handler  http.Handler
	active   func(bool)
	server   *http.Server
	listener net.Listener
	port     uint16
}

var (
	metricsRegistry = prometheus.NewRegistry()
	pluginMetrics   mitm.Metrics
	observabilityMu sync.Mutex
	pprofService    = observabilityServer{name: "pprof", handler: http.DefaultServeMux, active: func(enabled bool) {
		rate := 0
		if enabled {
			rate = 1
		}
		runtime.SetBlockProfileRate(rate)
		runtime.SetMutexProfileFraction(rate)
	}}
	metricsService = observabilityServer{name: "metrics", handler: promhttp.HandlerFor(
		prometheus.Gatherers{metricsRegistry, &pluginMetrics}, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError})}
)

func init() {
	metricsRegistry.MustRegister(stats.DefaultStore)
}

// Metrics and profiling have no state to commit; interrupted clients can retry.
func stopHTTPServer(name string, server *http.Server, listener net.Listener) {
	if server == nil {
		return
	}
	if err := server.Close(); err != nil {
		log.WithError(err).WithField("server", name).Error("Could not close HTTP server")
	}
	// Serve may not have registered the listener yet.
	_ = listener.Close()
}

func serveHTTP(name string, server *http.Server, listener net.Listener, clearCurrent func(*http.Server)) {
	err := server.Serve(listener)
	clearCurrent(server)
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		log.WithError(err).WithField("server", name).Error("HTTP server stopped unexpectedly")
		stopHTTPServer(name, server, listener)
	}
}

func (s *observabilityServer) setActive(enabled bool) {
	if s.active != nil {
		s.active(enabled)
	}
}

func (s *observabilityServer) clear(server *http.Server) {
	observabilityMu.Lock()
	defer observabilityMu.Unlock()
	if s.server == server {
		s.server, s.listener, s.port = nil, nil, 0
		s.setActive(false)
	}
}

func reconfigureObservabilityServers(pprofTarget, metricsTarget uint16) {
	observabilityMu.Lock()
	currentPprof := pprofService.port
	currentMetrics := metricsService.port
	observabilityMu.Unlock()

	// Release a port first when the other service needs to take it over.
	if pprofTarget != 0 && pprofTarget == currentMetrics && metricsTarget != currentMetrics {
		startMetricsServer(0)
	}
	if metricsTarget != 0 && metricsTarget == currentPprof && pprofTarget != currentPprof {
		startPprofServer(0)
	}
	startPprofServer(pprofTarget)
	startMetricsServer(metricsTarget)
}

func startPprofServer(port uint16) { pprofService.start(port) }

// The registry remains stable across control-plane reloads.
func startMetricsServer(port uint16) { metricsService.start(port) }

func (s *observabilityServer) start(port uint16) {
	observabilityMu.Lock()
	if s.server != nil && s.port == port && port != 0 {
		observabilityMu.Unlock()
		return
	}
	old, oldListener := s.server, s.listener
	if port == 0 {
		s.server, s.listener, s.port = nil, nil, 0
		s.setActive(false)
		observabilityMu.Unlock()
		stopHTTPServer(s.name, old, oldListener)
		return
	}
	server := &http.Server{
		Addr:              fmt.Sprintf("localhost:%d", port),
		Handler:           s.handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		observabilityMu.Unlock()
		log.WithError(err).WithField("server", s.name).Warn("Failed to start HTTP server")
		return
	}
	s.server, s.listener, s.port = server, listener, port
	s.setActive(true)
	go serveHTTP(s.name, server, listener, s.clear)
	observabilityMu.Unlock()
	stopHTTPServer(s.name, old, oldListener)
}
