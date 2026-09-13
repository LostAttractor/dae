// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apiclient "github.com/daeuniverse/dae/api/client"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/internal/apiserver"
)

func TestPublicClientWithTCPAndUnixAPI(t *testing.T) {
	store, err := settings.Open(filepath.Join(t.TempDir(), "runtime-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	plane := newAPITestPlane(t, store)
	socket := filepath.Join(t.TempDir(), "dae.sock")
	local, err := apiserver.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	info, err := os.Stat(socket)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("socket permissions", info, err)
	}
	local.SetHandler(plane.APIHandler("integration-test"))
	server := httptest.NewServer(plane.apiHandler("integration-test", testClientMAC))
	defer server.Close()
	for _, endpoint := range []string{server.URL, "unix://" + socket} {
		t.Run(endpoint, func(t *testing.T) {
			token := "test-secret"
			if strings.HasPrefix(endpoint, "unix:") {
				token = ""
			}
			client, err := apiclient.New(apiclient.Options{Endpoint: endpoint, Token: token})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx := context.Background()
			status, err := client.Status(ctx)
			if err != nil || status.Version != "integration-test" || len(status.Groups) != 1 {
				t.Fatal(status, err)
			}
			selectors, err := client.Selectors(ctx)
			if err != nil || len(selectors.Selectors) != 1 || !selectors.AdminEnabled {
				t.Fatal(selectors, err)
			}
			id := selectors.Selectors[0].Nodes[1].ID
			selected, err := client.SelectNode(ctx, "proxy", id)
			if err != nil || selected.NodeID != id || !selected.Overridden {
				t.Fatal(selected, err)
			}
			reset, err := client.ResetSelector(ctx, "proxy")
			if err != nil || reset.Overridden {
				t.Fatal(reset, err)
			}
			if token != "" {
				device, err := client.SetMembership(ctx, "gaming", true)
				if err != nil || device.MAC == "" {
					t.Fatal(device, err)
				}
				if _, err := client.SetMembership(ctx, "gaming", false); err != nil {
					t.Fatal(err)
				}
			} else {
				// A local transport cannot impersonate a device by supplying a body/header.
				if _, err := client.Device(ctx); err == nil {
					t.Fatal("Unix socket identified a LAN device")
				}
				local.SetHandler(nil)
				_, err := client.Status(ctx)
				if unavailable, ok := errors.AsType[*apiclient.Error](err); !ok || unavailable.StatusCode != 503 {
					t.Fatalf("reload: %v", err)
				}
				local.SetHandler(plane.APIHandler("integration-test"))
				if _, err := client.Status(ctx); err != nil {
					t.Fatal("client did not recover after reload", err)
				}
			}
		})
	}
	// The local listener exposes only the canonical API route.
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get("http://unix/status")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 404 {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("removed legacy status: %d %s", response.StatusCode, body)
	}
}

func TestStatusAdministrationBoundary(t *testing.T) {
	store, err := settings.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	plane := newAPITestPlane(t, store)
	handler := plane.apiHandler("test", testClientMAC)
	for _, test := range []struct {
		token string
		want  int
	}{{"", 401}, {"wrong", 401}, {"test-secret", 200}} {
		w := apiTestRequest(handler, "GET", "/api/status", "", test.token)
		if w.Code != test.want {
			t.Fatalf("status: %d %s", w.Code, w.Body.String())
		}
	}
	plane.apiToken = ""
	handler = plane.apiHandler("test", testClientMAC)
	if w := apiTestRequest(handler, "GET", "/api/status", "", ""); w.Code != 403 {
		t.Fatal("status exposed without configured token")
	}
	// Forwarding headers never grant the Unix socket's local administration privilege.
	r := httptest.NewRequest("GET", "http://192.0.2.1:9080/api/status", nil)
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9080}))
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	r.Header.Set("X-Dae-Local", "1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("forwarded headers granted local privileges")
	}
	for _, path := range []string{"/", "/app.js"} {
		if w := apiTestRequest(handler, "GET", path, "", ""); w.Code != 404 {
			t.Fatal("control plane still serves frontend assets")
		}
	}
}

func TestCertificateAPI(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if err := mitmca.Generate(cert, key, "API certificate", time.Hour); err != nil {
		t.Fatal(err)
	}
	authority, err := mitmca.Load(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	host, err := mitm.New(mitm.Options{Authority: authority})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	plane := &ControlPlane{mitmHost: host}
	handler := plane.APIHandler("test")
	server := httptest.NewServer(handler)
	defer server.Close()
	client, err := apiclient.New(apiclient.Options{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	identity, err := client.Certificate(context.Background())
	if err != nil || identity.Name != "API certificate" || identity.Fingerprint != authority.Fingerprint() {
		t.Fatalf("public certificate identity: %+v, %v", identity, err)
	}
	for _, test := range []struct {
		method, path, body string
		code               int
	}{
		{"GET", "/api/certificate", "{}", 400},
		{"GET", "/api/certificate", strings.Repeat("x", 1025), 413},
		{"GET", "/api/certificate?extra=1", "", 400},
		{"POST", "/api/certificate", "", 405},
	} {
		if response := apiTestRequest(handler, test.method, test.path, test.body, ""); response.Code != test.code {
			t.Errorf("%s %s: got %d, want %d", test.method, test.path, response.Code, test.code)
		}
	}
	response, err := server.Client().Head(server.URL + "/api/certificate")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 || len(body) != 0 || response.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("HEAD certificate: status=%d body=%q error=%v", response.StatusCode, body, err)
	}
}
