// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"sync"
	"sync/atomic"
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
	server   *http.Server
	listener net.Listener
	port     uint16
	dispatch *atomic.Pointer[http.Handler]
}

var (
	metricsRegistry = prometheus.NewRegistry()
	pluginMetrics   mitm.Metrics
	observabilityMu sync.Mutex
	pprofService    = observabilityServer{name: "pprof", handler: http.HandlerFunc(servePprof)}
	metricsService  = observabilityServer{name: "metrics", handler: promhttp.HandlerFor(
		prometheus.Gatherers{metricsRegistry, &pluginMetrics}, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError})}
	// Recording every blocking and contention event costs a few percent of
	// CPU, so each runs only while a delta profile of it is captured.
	contentionProfiles = map[string]*profileWindows{
		"/debug/pprof/block": {record: runtime.SetBlockProfileRate},
		"/debug/pprof/mutex": {record: func(rate int) { runtime.SetMutexProfileFraction(rate) }},
	}
)

// profileWindows counts the captures of one profile in progress.
type profileWindows struct {
	mu     sync.Mutex
	active int
	record func(rate int)
}

func (p *profileWindows) open() (done func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active++
	if p.active == 1 {
		p.record(1)
	}
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.active--
		if p.active == 0 {
			p.record(0)
		}
	}
}

// servePprof records block and mutex events while ?seconds=N captures them.
// The capture returns when it completes, the client disconnects or the
// server closes. Profiles without seconds report the windows recorded so far.
func servePprof(w http.ResponseWriter, r *http.Request) {
	if profile := contentionProfiles[r.URL.Path]; profile != nil && r.FormValue("seconds") != "" {
		defer profile.open()()
	}
	http.DefaultServeMux.ServeHTTP(w, r)
}

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

// A prepared update reserves every new port before publishing any change.
// Existing bindings can move between services without releasing their ports.
type observabilityUpdate struct {
	targets [2]observabilityServer
	opened  []net.Listener
}

func prepareObservabilityServers(pprofTarget, metricsTarget uint16) (*observabilityUpdate, error) {
	if pprofTarget != 0 && pprofTarget == metricsTarget {
		return nil, fmt.Errorf("pprof and metrics cannot share port %d", pprofTarget)
	}
	observabilityMu.Lock()
	defer observabilityMu.Unlock()
	update := &observabilityUpdate{}
	current := [2]*observabilityServer{&pprofService, &metricsService}
	for i, port := range [2]uint16{pprofTarget, metricsTarget} {
		if port == 0 {
			continue
		}
		for _, service := range current {
			if service.server != nil && service.port == port {
				update.targets[i] = *service
				break
			}
		}
		if update.targets[i].server != nil {
			continue
		}
		address := fmt.Sprintf("localhost:%d", port)
		// Declare TCP; Go listeners otherwise default to MPTCP.
		var config net.ListenConfig
		config.SetMultipathTCP(false)
		listener, err := config.Listen(context.Background(), "tcp", address)
		if err != nil {
			update.Close()
			return nil, fmt.Errorf("listen for %s: %w", current[i].name, err)
		}
		dispatch := new(atomic.Pointer[http.Handler])
		dispatch.Store(&current[i].handler)
		server := &http.Server{Addr: address, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { (*dispatch.Load()).ServeHTTP(w, r) }),
		}
		update.targets[i] = observabilityServer{server: server, listener: listener, port: port, dispatch: dispatch}
		update.opened = append(update.opened, listener)
	}
	return update, nil
}

func (u *observabilityUpdate) Close() {
	for _, listener := range u.opened {
		_ = listener.Close()
	}
	u.opened = nil
}

func (u *observabilityUpdate) Commit() {
	observabilityMu.Lock()
	old := [2]observabilityServer{pprofService, metricsService}
	for i, service := range [2]*observabilityServer{&pprofService, &metricsService} {
		target := u.targets[i]
		service.server, service.listener, service.port, service.dispatch = target.server, target.listener, target.port, target.dispatch
		if service.dispatch != nil {
			service.dispatch.Store(&service.handler)
		}
	}
	for _, listener := range u.opened {
		for _, service := range [2]*observabilityServer{&pprofService, &metricsService} {
			if service.listener == listener {
				go serveHTTP(service.name, service.server, listener, clearObservabilityServer)
			}
		}
	}
	u.opened = nil
	observabilityMu.Unlock()
	for _, previous := range old {
		if previous.server != nil && previous.server != u.targets[0].server && previous.server != u.targets[1].server {
			stopHTTPServer(previous.name, previous.server, previous.listener)
		}
	}
}

func clearObservabilityServer(server *http.Server) {
	observabilityMu.Lock()
	defer observabilityMu.Unlock()
	for _, service := range [2]*observabilityServer{&pprofService, &metricsService} {
		if service.server == server {
			service.server, service.listener, service.port, service.dispatch = nil, nil, 0, nil
		}
	}
}

func reconfigureObservabilityServers(pprofTarget, metricsTarget uint16) error {
	update, err := prepareObservabilityServers(pprofTarget, metricsTarget)
	if err != nil {
		return err
	}
	update.Commit()
	return nil
}

func startPprofServer(port uint16) error {
	observabilityMu.Lock()
	metricsPort := metricsService.port
	observabilityMu.Unlock()
	return reconfigureObservabilityServers(port, metricsPort)
}

func startMetricsServer(port uint16) error {
	observabilityMu.Lock()
	pprofPort := pprofService.port
	observabilityMu.Unlock()
	return reconfigureObservabilityServers(pprofPort, port)
}
