// SPDX-License-Identifier: AGPL-3.0-only

package cmd

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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var (
	pprofServer     *http.Server
	metricsServer   *http.Server
	pprofListener   net.Listener
	metricsListener net.Listener
	pprofPort       uint16
	// metricsPort is the port metricsServer listens on; 0 means disabled.
	metricsPort     uint16
	metricsRegistry = prometheus.NewRegistry()
	observabilityMu sync.Mutex
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

func clearPprofServer(server *http.Server) {
	observabilityMu.Lock()
	defer observabilityMu.Unlock()
	if pprofServer == server {
		pprofServer = nil
		pprofListener = nil
		pprofPort = 0
		runtime.SetBlockProfileRate(0)
		runtime.SetMutexProfileFraction(0)
	}
}

func clearMetricsServer(server *http.Server) {
	observabilityMu.Lock()
	defer observabilityMu.Unlock()
	if metricsServer == server {
		metricsServer = nil
		metricsListener = nil
		metricsPort = 0
	}
}

func reconfigureObservabilityServers(pprofTarget, metricsTarget uint16) {
	observabilityMu.Lock()
	currentPprof := pprofPort
	currentMetrics := metricsPort
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

func startPprofServer(port uint16) {
	observabilityMu.Lock()
	if pprofServer != nil && pprofPort == port && port != 0 {
		observabilityMu.Unlock()
		return
	}
	if port == 0 {
		old := pprofServer
		oldListener := pprofListener
		pprofServer = nil
		pprofListener = nil
		pprofPort = 0
		runtime.SetBlockProfileRate(0)
		runtime.SetMutexProfileFraction(0)
		observabilityMu.Unlock()
		stopHTTPServer("pprof", old, oldListener)
		return
	}
	server := &http.Server{
		Addr:              fmt.Sprintf("localhost:%d", port),
		Handler:           http.DefaultServeMux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		observabilityMu.Unlock()
		log.Warnf("Failed to start pprof server: %v", err)
		return
	}
	old := pprofServer
	oldListener := pprofListener
	pprofServer = server
	pprofListener = listener
	pprofPort = port
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)
	go serveHTTP("pprof", server, listener, clearPprofServer)
	observabilityMu.Unlock()
	stopHTTPServer("pprof", old, oldListener)
}

// startMetricsServer restarts the metrics server only when its process-level
// listener changes. The registry is stable across control-plane reloads.
func startMetricsServer(port uint16) {
	observabilityMu.Lock()
	if metricsServer != nil && metricsPort == port && port != 0 {
		observabilityMu.Unlock()
		return
	}

	if port == 0 {
		old := metricsServer
		oldListener := metricsListener
		metricsServer = nil
		metricsListener = nil
		metricsPort = 0
		observabilityMu.Unlock()
		stopHTTPServer("metrics", old, oldListener)
		return
	}

	server := &http.Server{
		Addr: fmt.Sprintf("localhost:%d", port),
		Handler: promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{
			ErrorHandling: promhttp.ContinueOnError,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		observabilityMu.Unlock()
		log.Warnf("Failed to start metrics server: %v", err)
		return
	}
	old := metricsServer
	oldListener := metricsListener
	metricsServer = server
	metricsListener = listener
	metricsPort = port
	go serveHTTP("metrics", server, listener, clearMetricsServer)
	observabilityMu.Unlock()
	stopHTTPServer("metrics", old, oldListener)
}
