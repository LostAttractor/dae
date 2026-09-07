// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/internal/apiserver"
)

func TestAPIServerReloadAndPortChanges(t *testing.T) {
	port := freeLocalPort(t)
	server, err := prepareAPIServer(nil, port)
	if err != nil {
		t.Fatal(err)
	}
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
	same, err := prepareAPIServer(server, port)
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
	if _, err := prepareAPIServer(server, port); err == nil {
		t.Fatal("occupied port accepted")
	}
	check(server, http.StatusOK, "new CA and settings")

	port = freeLocalPort(t)
	next, err := prepareAPIServer(server, port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(next.Close)
	check(next, http.StatusServiceUnavailable, "")
	check(server, http.StatusOK, "new CA and settings")
	server.Close()
	next.SetHandler(handler("changed port"))
	check(next, http.StatusOK, "changed port")

	if result, err := prepareAPIServer(next, 0); result != nil || err != nil {
		t.Fatalf("disabled server = %v, %v", result, err)
	}
	next.Close()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", next.Addr().(*net.TCPAddr).Port), time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("closed portal still accepts connections")
	}
}

func TestAPIPortServesWebAndReservesAPIRoutes(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(fmt.Sprint("external=", external), func(t *testing.T) {
			directory := ""
			if external {
				directory = t.TempDir()
				if err := os.WriteFile(filepath.Join(directory, "index.html"), []byte("independent UI"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(directory, "chunks"), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, "chunks", "new.js"), []byte("export const ready = true;"), 0644); err != nil {
					t.Fatal(err)
				}
				// Even a conflicting static file cannot shadow an API/certificate operation.
				if err := os.WriteFile(filepath.Join(directory, "ca.pem"), []byte("wrong certificate"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("DAE_WEB_ROOT", directory)
			server, err := prepareAPIServer(nil, freeLocalPort(t))
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			server.SetHandler(daemonAPIHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"source":"API"}`)
			})))
			client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
			defer client.CloseIdleConnections()
			for _, path := range []string{"/", "/api/status", "/api/selectors", "/ca.pem", "/chunks/new.js", "/webui.go"} {
				r, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d%s", server.Addr().(*net.TCPAddr).Port, path))
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(r.Body)
				r.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				switch path {
				case "/":
					if r.StatusCode != 200 {
						t.Fatal("Web unavailable on api_port", r.StatusCode)
					}
					if external && string(body) != "independent UI" {
						t.Fatal("external UI not served")
					}
					if !external && !strings.Contains(string(body), "app.js") {
						t.Fatal("embedded UI not served")
					}
				case "/api/status", "/api/selectors", "/ca.pem":
					if string(body) != `{"source":"API"}` {
						t.Fatalf("static files shadowed %s: %s", path, body)
					}
				case "/chunks/new.js":
					want := 404
					if external {
						want = 200
					}
					if r.StatusCode != want {
						t.Fatal("new UI assets require daemon changes")
					}
				case "/webui.go":
					if r.StatusCode != 404 {
						t.Fatal("Go source exposed as a Web asset")
					}
				}
			}
		})
	}
}
