/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"syscall"
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

// Keep the port bound until preparation takes ownership of its real listener.
func freeLocalPort(t *testing.T) uint16 {
	t.Helper()
	port, _ := reserveObservabilityPort(t)
	return port
}

func reserveObservabilityPort(t *testing.T) (uint16, net.Listener) {
	t.Helper()
	listen := listenObservability
	listener, err := listen("localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	reserved := true
	listenObservability = func(address string) (net.Listener, error) {
		if reserved && address == fmt.Sprintf("localhost:%d", port) {
			reserved = false
			return listener, nil
		}
		return listen(address)
	}
	t.Cleanup(func() {
		listenObservability = listen
		if reserved {
			_ = listener.Close()
		}
	})
	return port, listener
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

func TestObservabilityPreparationTakesHeldListener(t *testing.T) {
	port, listener := reserveObservabilityPort(t)
	unexpected, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if unexpected != nil {
		_ = unexpected.Close()
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("reserved port was not held: %v", err)
	}
	update, err := prepareObservabilityServers(port, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer update.Close()
	if update.targets[0].listener != listener {
		t.Fatal("preparation did not take the reserved listener")
	}
}

func TestObservabilityListenersDeclareTCP(t *testing.T) {
	t.Setenv("GODEBUG", "multipathtcp=1")
	update, err := prepareObservabilityServers(freeLocalPort(t), freeLocalPort(t))
	if err != nil {
		t.Fatal(err)
	}
	defer update.Close()
	for _, listener := range update.opened {
		raw, err := listener.(*net.TCPListener).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		protocol := -1
		_ = raw.Control(func(fd uintptr) {
			protocol, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PROTOCOL)
		})
		if protocol != syscall.IPPROTO_TCP {
			t.Fatalf("observability listener protocol %d", protocol)
		}
	}
}

func activeCaptures(path string) int {
	profile := contentionProfiles[path]
	profile.mu.Lock()
	defer profile.mu.Unlock()
	return profile.active
}

func waitCaptures(t *testing.T, path string, want int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); activeCaptures(path) != want; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%s captures = %d, want %d", path, activeCaptures(path), want)
		}
	}
}

func TestPprofRecordsContentionOnlyDuringCaptures(t *testing.T) {
	startPprofServer(0)
	t.Cleanup(func() { startPprofServer(0) })
	port := freeLocalPort(t)
	startPprofServer(port)
	if fraction := runtime.SetMutexProfileFraction(-1); fraction != 0 {
		t.Fatalf("enabling pprof set the mutex fraction to %d", fraction)
	}
	capture := func(path string) (context.CancelFunc, <-chan struct{}) {
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://localhost:%d%s?seconds=30", port, path), nil)
			if response, err := http.DefaultClient.Do(request); err == nil {
				_ = response.Body.Close()
			}
		}()
		return cancel, done
	}
	first, firstDone := capture("/debug/pprof/mutex")
	second, secondDone := capture("/debug/pprof/mutex")
	waitCaptures(t, "/debug/pprof/mutex", 2)
	if fraction := runtime.SetMutexProfileFraction(-1); fraction != 1 {
		t.Fatalf("capture recorded with mutex fraction %d", fraction)
	}
	// A client disconnect ends its capture; the overlapping one continues.
	first()
	<-firstDone
	waitCaptures(t, "/debug/pprof/mutex", 1)
	if fraction := runtime.SetMutexProfileFraction(-1); fraction != 1 {
		t.Fatal("an ended capture stopped another")
	}
	// Closing the server ends the remaining captures.
	_, blockDone := capture("/debug/pprof/block")
	waitCaptures(t, "/debug/pprof/block", 1)
	startPprofServer(0)
	waitCaptures(t, "/debug/pprof/mutex", 0)
	waitCaptures(t, "/debug/pprof/block", 0)
	second()
	<-secondDone
	<-blockDone
	if fraction := runtime.SetMutexProfileFraction(-1); fraction != 0 {
		t.Fatalf("mutex fraction %d after the last capture", fraction)
	}
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
	pprofTarget, reservedPprof := reserveObservabilityPort(t)
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
	if err := reservedPprof.(*net.TCPListener).SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("rejected preparation leaked reserved pprof listener: %v", err)
	}
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

func TestPrepareInheritedObservabilityClosesAllInheritedFDs(t *testing.T) {
	if err := reconfigureObservabilityServers(0, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reconfigureObservabilityServers(0, 0) })
	toFD := func() (uint16, *os.File) {
		l, err := net.Listen("tcp", "localhost:0")
		if err != nil {
			t.Fatal(err)
		}
		tcp := l.(*net.TCPListener)
		port := uint16(tcp.Addr().(*net.TCPAddr).Port)
		file, err := tcp.File()
		_ = tcp.Close()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		return port, file
	}
	claimedPort, claimedFile := toFD()
	unusedPort, unusedFile := toFD()
	update, err := prepareInheritedObservability(claimedPort, 0, map[uint16]*os.File{
		claimedPort: claimedFile,
		unusedPort:  unusedFile,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer update.Close()
	for name, file := range map[string]*os.File{"claimed": claimedFile, "unused": unusedFile} {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("%s inherited observability FD remained open: %v", name, err)
		}
	}
	update.Commit()
	update.Activate()
	response, err := http.Get(fmt.Sprintf("http://localhost:%d/debug/pprof/", claimedPort))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("claimed inherited pprof status = %s", response.Status)
	}

	_, errFile := toFD()
	if _, err := prepareInheritedObservability(1, 1, map[uint16]*os.File{1: errFile}, true); err == nil {
		t.Fatal("shared port error should reject call")
	}
	if _, err := errFile.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("error path leaked inherited observability FD: %v", err)
	}
}

func TestReplaceSwapsManagementAndMetricsPorts(t *testing.T) {
	take := func(address string) (uint16, *os.File) {
		t.Helper()
		ln, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		file, err := ln.(*net.TCPListener).File()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { file.Close() })
		return uint16(ln.Addr().(*net.TCPAddr).Port), file
	}
	apiPort, wildcard := take(":0")
	metricsPort, loopback := take("localhost:0")
	incoming := &replacementState{files: map[string]*os.File{"management": wildcard}}
	retained, err := incoming.takeManagement(metricsPort)
	if err != nil || retained != nil {
		t.Fatalf("kept old wildcard binding: %v, %v", retained, err)
	}
	obs, err := prepareInheritedObservability(0, apiPort, map[uint16]*os.File{metricsPort: loopback}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer obs.Close()
	if !obs.targets[1].listener.Addr().(*net.TCPAddr).IP.IsLoopback() {
		t.Fatal("metrics inherited a wildcard listener")
	}
	server, err := prepareAPIServer(nil, metricsPort, true)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if !server.Addr().(*net.TCPAddr).IP.IsUnspecified() {
		t.Fatal("management inherited a loopback listener")
	}
}
