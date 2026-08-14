/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func observabilityState() (pprof *http.Server, pprofListenPort uint16, metrics *http.Server, metricsListenPort uint16) {
	observabilityMu.Lock()
	defer observabilityMu.Unlock()
	return pprofServer, pprofPort, prometheusServer, prometheusPort
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
	startPrometheusServer(0, nil)
	t.Cleanup(func() { startPrometheusServer(0, nil) })
	oldPort := freeLocalPort(t)
	startPrometheusServer(oldPort, prometheus.NewRegistry())
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
	startPrometheusServer(occupiedPort, prometheus.NewRegistry())
	_, _, current, currentPort := observabilityState()
	if current != oldServer || currentPort != oldPort {
		t.Fatal("failed port change replaced the working metrics server")
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
	startPrometheusServer(0, nil)
	t.Cleanup(func() { startPrometheusServer(0, nil) })
	port := freeLocalPort(t)
	server := new(http.Server)
	observabilityMu.Lock()
	prometheusServer = server
	prometheusPort = port
	observabilityMu.Unlock()

	serveHTTP("metrics", server, closedLocalListener(t), clearPrometheusServer)
	_, _, current, currentPort := observabilityState()
	if current != nil || currentPort != 0 {
		t.Fatal("unexpected exit did not clear the metrics server")
	}

	startPrometheusServer(port, prometheus.NewRegistry())
	_, _, current, currentPort = observabilityState()
	if current == nil || current == server || currentPort != port {
		t.Fatal("metrics server did not restart on the same port")
	}
}

func TestObservabilityServersCanSwapPorts(t *testing.T) {
	startPprofServer(0)
	startPrometheusServer(0, nil)
	t.Cleanup(func() {
		startPprofServer(0)
		startPrometheusServer(0, nil)
	})
	pprofInitial := freeLocalPort(t)
	metricsInitial := freeLocalPort(t)
	for metricsInitial == pprofInitial {
		metricsInitial = freeLocalPort(t)
	}
	startPprofServer(pprofInitial)
	startPrometheusServer(metricsInitial, prometheus.NewRegistry())

	reconfigureObservabilityServers(metricsInitial, pprofInitial, prometheus.NewRegistry())
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
