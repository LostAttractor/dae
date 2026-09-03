/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
)

func observabilityState() (pprof *http.Server, pprofListenPort uint16, metrics *http.Server, metricsListenPort uint16) {
	observabilityMu.Lock()
	defer observabilityMu.Unlock()
	return pprofServer, pprofPort, metricsServer, metricsPort
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
	startMetricsServer(occupiedPort)
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
	if err := connection.AttachExternalCounters(func() (stats.TrafficCounters, error) {
		return stats.TrafficCounters{}, errors.New("counter source failed")
	}); err != nil {
		t.Fatal(err)
	}
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
	pprofServer = server
	pprofPort = port
	observabilityMu.Unlock()

	serveHTTP("pprof", server, closedLocalListener(t), clearPprofServer)
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
	metricsServer = server
	metricsPort = port
	observabilityMu.Unlock()

	serveHTTP("metrics", server, closedLocalListener(t), clearMetricsServer)
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

	reconfigureObservabilityServers(metricsInitial, pprofInitial)
	pprof, pprofPort, metrics, metricsPort := observabilityState()
	if pprof == nil || metrics == nil || pprofPort != metricsInitial || metricsPort != pprofInitial {
		t.Fatalf("swapped observability state = pprof %v:%d, metrics %v:%d", pprof, pprofPort, metrics, metricsPort)
	}
}

func TestStopHTTPServerForcesCloseAfterTimeout(t *testing.T) {
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
	stopHTTPServerWithin("test", server, listener, 25*time.Millisecond)
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
