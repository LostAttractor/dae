// SPDX-License-Identifier: AGPL-3.0-only
//go:build !no_webui

package daemon

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/internal/apiserver"
)

func TestAPIPortServesWebAndReservesAPIRoutes(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(fmt.Sprint("external=", external), func(t *testing.T) {
			directory := ""
			if external {
				directory = t.TempDir()
				if err := os.WriteFile(filepath.Join(directory, "dae-web.json"), []byte(`{"api_origin":""}`), 0644); err != nil {
					t.Fatal(err)
				}
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
			server := prepareAPIOnUnusedPort(t, nil)
			defer server.Close()
			server.SetHandler(daemonAPIHandler(apiserver.NewHandler(apiserver.Options{
				AllowLANAnonymous: true,
				ResolveClient: func(netip.AddrPort, netip.AddrPort) (api.ClientIdentity, error) {
					return api.ClientIdentity{}, nil
				},
				Status:       func() *api.StatusSnapshot { return &api.StatusSnapshot{Version: "API"} },
				Certificates: &apiserver.Certificates{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "certificate API") })},
			}), true))
			client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
			defer client.CloseIdleConnections()
			for _, path := range []string{"/", "/api/status", "/api/certificate/ca.pem", "/chunks/new.js", "/webui.go", "/Makefile", "/README.md", "/src/app.js"} {
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
						t.Fatal("Web unavailable on api.listen", r.StatusCode)
					}
					if external && string(body) != "independent UI" {
						t.Fatal("external UI not served")
					}
					if !external && !strings.Contains(r.Header.Get("Content-Type"), "text/html") {
						t.Fatal("embedded UI not served")
					}
				case "/api/status":
					if r.StatusCode != http.StatusForbidden || !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
						t.Fatalf("expected API denial for plaintext management: %d %s", r.StatusCode, body)
					}
				case "/api/certificate/ca.pem":
					if r.StatusCode != 200 || !strings.Contains(string(body), "API") {
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
				case "/webui.go", "/Makefile", "/README.md", "/src/app.js":
					if r.StatusCode != 404 {
						t.Fatalf("development file exposed as a Web asset: %s", path)
					}
				}
			}
		})
	}
}
