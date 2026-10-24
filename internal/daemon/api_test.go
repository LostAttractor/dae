// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/internal/apiserver"
)

func prepareAPIOnUnusedPort(t *testing.T, current *apiserver.Server) *apiserver.Server {
	t.Helper()
	for range 10 {
		server, _, err := prepareAPIServer(current, localAPIConfig(freeLocalPort(t)), nil, nil, false)
		if errors.Is(err, syscall.EADDRINUSE) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	t.Fatal("API port was taken during all 10 bind attempts")
	return nil
}

func TestAPIServerReloadAndPortChanges(t *testing.T) {
	server := prepareAPIOnUnusedPort(t, nil)
	port := uint16(server.Addr().(*net.TCPAddr).Port)
	t.Cleanup(server.Close)
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	t.Cleanup(client.CloseIdleConnections)
	check := func(s *apiserver.Server, code int, want string) {
		t.Helper()
		response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/device", s.Addr().(*net.TCPAddr).Port))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != code || (want != "" && string(body) != want) {
			t.Fatalf("response = %d %q, %v; want %d %q", response.StatusCode, body, err, code, want)
		}
	}
	handler := func(body string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) })
	}
	check(server, http.StatusServiceUnavailable, "")
	server.SetHandler(handler("old CA and settings"))

	// Building a candidate must not change the active page or its settings.
	same, _, err := prepareAPIServer(server, localAPIConfig(port), nil, nil, false)
	if err != nil || same != server {
		t.Fatalf("unchanged port replaced listener: %v", err)
	}
	check(server, http.StatusOK, "old CA and settings")
	server.SetHandler(nil)
	check(server, http.StatusServiceUnavailable, "")
	same.SetHandler(handler("new CA and settings"))
	check(server, http.StatusOK, "new CA and settings")

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	port = uint16(occupied.Addr().(*net.TCPAddr).Port)
	if _, _, err := prepareAPIServer(server, localAPIConfig(port), nil, nil, false); err == nil {
		t.Fatal("occupied port accepted")
	}
	check(server, http.StatusOK, "new CA and settings")

	next := prepareAPIOnUnusedPort(t, server)
	t.Cleanup(next.Close)
	check(next, http.StatusServiceUnavailable, "")
	check(server, http.StatusOK, "new CA and settings")
	server.Close()
	next.SetHandler(handler("changed port"))
	check(next, http.StatusOK, "changed port")

	if result, _, err := prepareAPIServer(next, config.API{}, nil, nil, false); result != nil || err != nil {
		t.Fatalf("disabled server = %v, %v", result, err)
	}
	next.Close()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", next.Addr().(*net.TCPAddr).Port), time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("closed portal still accepts connections")
	}
}

func localAPIConfig(port uint16) config.API {
	return config.API{Listen: fmt.Sprintf("127.0.0.1:%d", port)}
}

func TestWebSwitchPreservesAPIAndMonitoring(t *testing.T) {
	handler := daemonAPIHandler(apiserver.NewHandler(apiserver.Options{
		AdminKey: "admin", Pprof: true,
		Status:  func() *api.StatusSnapshot { return &api.StatusSnapshot{} },
		Metrics: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "metric 1\n") }),
	}), false)
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	for _, path := range []string{"/", "/api/status", "/metrics", "/debug/pprof/goroutine?debug=1"} {
		r, _ := http.NewRequestWithContext(t.Context(), "GET", server.URL+path, nil)
		r.Header.Set("Authorization", "Bearer admin")
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		want := 200
		if path == "/" {
			want = 404
		}
		if response.StatusCode != want {
			t.Fatalf("%s: %d", path, response.StatusCode)
		}
	}
}
