/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package daemon

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/control"
)

func observabilityState() (pprof *http.Server, pprofListenPort uint16, metrics *http.Server, metricsListenPort uint16) {
	observabilityMu.Lock()
	defer observabilityMu.Unlock()
	return pprofService.server, pprofService.port, metricsService.server, metricsService.port
}

func freeLocalPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func closedLocalListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return listener
}

func TestPprofServerKeepsListenerWhenPortIsUnchanged(t *testing.T) {
	startPprofServer(0)
	t.Cleanup(func() { startPprofServer(0) })
	port := freeLocalPort(t)
	startPprofServer(port)
	server, _, _, _ := observabilityState()
	if server == nil {
		t.Fatal("pprof server did not start")
	}
	startPprofServer(port)
	current, _, _, _ := observabilityState()
	if current != server {
		t.Fatal("pprof server restarted on an unchanged port")
	}
}

func TestMetricsPortChangeBindFailureKeepsOldServer(t *testing.T) {
	startMetricsServer(0)
	t.Cleanup(func() { startMetricsServer(0) })
	oldPort := freeLocalPort(t)
	startMetricsServer(oldPort)
	_, _, oldServer, _ := observabilityState()
	if oldServer == nil {
		t.Fatal("metrics server did not start")
	}

	occupied, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	occupiedPort := uint16(occupied.Addr().(*net.TCPAddr).Port)
	if err := startMetricsServer(occupiedPort); err == nil {
		t.Fatal("occupied port was accepted")
	}
	_, _, current, currentPort := observabilityState()
	if current != oldServer || currentPort != oldPort {
		t.Fatal("failed port change replaced the working metrics server")
	}
}

func TestMetricsServerContinuesAfterExternalCounterFailure(t *testing.T) {
	startMetricsServer(0)
	t.Cleanup(func() { startMetricsServer(0) })
	connection := stats.DefaultStore.OpenConnection(stats.Path{
		NodeID:   t.Name(),
		Outbound: t.Name(),
		Network:  common.NetworkTCP4,
	}, false)
	_ = connection.UpdateCounters(api.TrafficCounters{}, errors.New("counter source failed"))
	t.Cleanup(func() { _ = connection.Close() })

	port := freeLocalPort(t)
	startMetricsServer(port)
	response, err := http.Get("http://localhost:" + fmt.Sprint(port))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("metrics status = %s, body = %s", response.Status, body)
	}
	if !strings.Contains(string(body), "dae_external_counter_read_errors_total") {
		t.Fatalf("metrics response omitted external counter errors: %s", body)
	}
}

func TestPprofUnexpectedExitAllowsSamePortRestart(t *testing.T) {
	startPprofServer(0)
	t.Cleanup(func() { startPprofServer(0) })
	port := freeLocalPort(t)
	server := new(http.Server)
	observabilityMu.Lock()
	pprofService.server = server
	pprofService.port = port
	observabilityMu.Unlock()

	serveHTTP("pprof", server, closedLocalListener(t), clearObservabilityServer)
	current, currentPort, _, _ := observabilityState()
	if current != nil || currentPort != 0 {
		t.Fatal("unexpected exit did not clear the pprof server")
	}

	startPprofServer(port)
	current, currentPort, _, _ = observabilityState()
	if current == nil || current == server || currentPort != port {
		t.Fatal("pprof server did not restart on the same port")
	}
}

func TestMetricsUnexpectedExitAllowsSamePortRestart(t *testing.T) {
	startMetricsServer(0)
	t.Cleanup(func() { startMetricsServer(0) })
	port := freeLocalPort(t)
	server := new(http.Server)
	observabilityMu.Lock()
	metricsService.server = server
	metricsService.port = port
	observabilityMu.Unlock()

	serveHTTP("metrics", server, closedLocalListener(t), clearObservabilityServer)
	_, _, current, currentPort := observabilityState()
	if current != nil || currentPort != 0 {
		t.Fatal("unexpected exit did not clear the metrics server")
	}

	startMetricsServer(port)
	_, _, current, currentPort = observabilityState()
	if current == nil || current == server || currentPort != port {
		t.Fatal("metrics server did not restart on the same port")
	}
}

func TestObservabilityServersCanSwapPorts(t *testing.T) {
	startPprofServer(0)
	startMetricsServer(0)
	t.Cleanup(func() {
		startPprofServer(0)
		startMetricsServer(0)
	})
	pprofInitial := freeLocalPort(t)
	metricsInitial := freeLocalPort(t)
	for metricsInitial == pprofInitial {
		metricsInitial = freeLocalPort(t)
	}
	startPprofServer(pprofInitial)
	startMetricsServer(metricsInitial)

	if err := reconfigureObservabilityServers(metricsInitial, pprofInitial); err != nil {
		t.Fatal(err)
	}
	pprof, pprofPort, metrics, metricsPort := observabilityState()
	if pprof == nil || metrics == nil || pprofPort != metricsInitial || metricsPort != pprofInitial {
		t.Fatalf("swapped observability state = pprof %v:%d, metrics %v:%d", pprof, pprofPort, metrics, metricsPort)
	}
	for _, test := range []struct {
		port       uint16
		path, want string
	}{
		{pprofPort, "/debug/pprof/", "Types of profiles available"},
		{metricsPort, "/metrics", "dae_process_timestamp_seconds"},
	} {
		response, err := http.Get(fmt.Sprintf("http://localhost:%d%s", test.port, test.path))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || !strings.Contains(string(body), test.want) {
			t.Fatalf("swapped service handler: %s, %v", body, err)
		}
	}

}

func TestStopHTTPServerDoesNotDrainRequests(t *testing.T) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(handlerStarted)
		<-releaseHandler
	})}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		_, _ = http.Get("http://" + listener.Addr().String())
	}()
	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("request did not reach blocking handler")
	}

	started := time.Now()
	stopHTTPServer("test", server, listener)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("forced server shutdown took %v", elapsed)
	}
	close(releaseHandler)
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("request did not exit after forced server close")
	}
	select {
	case err := <-serveDone:
		if err != nil && err != http.ErrServerClosed && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not exit after forced server close")
	}
}

func TestObservabilityPreparationRollback(t *testing.T) {
	if err := reconfigureObservabilityServers(0, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reconfigureObservabilityServers(0, 0) })
	oldPort := freeLocalPort(t)
	if err := startMetricsServer(oldPort); err != nil {
		t.Fatal(err)
	}
	_, _, oldServer, _ := observabilityState()
	occupied, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	pprofTarget := freeLocalPort(t)
	metricsTarget := uint16(occupied.Addr().(*net.TCPAddr).Port)
	app := &application{conf: mitmConfigForTest(t, ""), datapath: control.NewRuntime()}
	defer app.datapath.Close()
	app.conf.Global.MetricsPort = oldPort
	next := *app.conf
	next.Global.PprofPort, next.Global.MetricsPort = pprofTarget, metricsTarget
	if _, err := app.apply(t.Context(), &next, false, false, false); err == nil {
		t.Fatal("reload accepted occupied metrics port")
	}
	pprof, _, current, currentPort := observabilityState()
	if app.conf.Global.MetricsPort != oldPort || pprof != nil || current != oldServer || currentPort != oldPort {
		t.Fatal("rejected reload changed configuration or live listeners")
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", pprofTarget))
	if err != nil {
		t.Fatalf("rejected preparation leaked reserved pprof port: %v", err)
	}
	listener.Close()
	update, err := prepareObservabilityServers(oldPort, 0)
	if err != nil {
		t.Fatal(err)
	}
	update.Close()
	_, _, current, _ = observabilityState()
	if current != oldServer {
		t.Fatal("discarding port transfer changed active metrics server")
	}
}
