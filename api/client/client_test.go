// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/internal/testutil"
)

func TestSettingsRequests(t *testing.T) {
	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("missing write credentials")
		}
		body, _ := io.ReadAll(r.Body)
		switch requests {
		case 1:
			if r.Method != "PUT" || r.URL.EscapedPath() != "/api/selectors/proxy%2F%E9%A6%99%E6%B8%AF" || string(body) != `{"node_id":"node"}` || r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("unexpected selector request: %s %s %s", r.Method, r.URL.EscapedPath(), body)
			}
			_, _ = io.WriteString(w, `{"name":"proxy/香港","node_id":"node","future_field":true}`)
		case 2, 3:
			if r.Method != "DELETE" || len(body) != 0 {
				t.Error("delete must have no body")
			}
			_, _ = io.WriteString(w, `{}`)
		case 4, 5:
			if r.URL.Path != "/api/device/mitm" || r.Header.Get("X-Dae-MITM") != "fingerprint" {
				t.Error("missing MITM confirmation")
			}
			if requests == 4 && (r.Method != "PUT" || string(body) != `{"enabled":false}`) {
				t.Error("false override lost")
			}
			if requests == 5 && (r.Method != "DELETE" || len(body) != 0) {
				t.Error("reset must not send JSON null")
			}
			_, _ = io.WriteString(w, `{}`)
		case 6, 7:
			want := `{"outbound":"proxy/香港","node_id":"node"}`
			if requests == 7 {
				want = `{"outbound":"proxy/香港"}`
			}
			if r.Method != "POST" || r.URL.Path != "/api/probes" || string(body) != want || r.Header.Get("X-Dae-API") != "1" || r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("unexpected probe request: %s %s %s", r.Method, r.URL.EscapedPath(), body)
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"outbound":"proxy/香港","node_ids":["node"]}`)
		}
	}))
	defer server.Close()
	c, err := New(Options{Endpoint: server.URL, RootCAs: testutil.TLSRoots(server), APIKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()
	selected, err := c.SelectNode(ctx, "proxy/香港", "node")
	if err != nil || selected.NodeID != "node" {
		t.Fatal(selected, err)
	}
	if _, err := c.ResetSelector(ctx, "proxy/香港"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetMembership(ctx, "work", false); err != nil {
		t.Fatal(err)
	}
	disabled := false
	if _, err := c.SetMITM(ctx, disabled, "fingerprint"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ResetMITM(ctx, "fingerprint"); err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"node", ""} {
		if accepted, err := c.Probe(t.Context(), api.ProbeRequest{Outbound: "proxy/香港", NodeID: node}); err != nil || accepted.Outbound != "proxy/香港" || len(accepted.NodeIDs) != 1 {
			t.Fatal(accepted, err)
		}
	}
	if requests != 7 {
		t.Fatalf("requests = %d", requests)
	}
}

func TestErrorsCancellationAndRedirects(t *testing.T) {
	redirected := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected = true }))
	defer target.Close()
	for _, code := range []int{401, 403, 409, 503, 302} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if code == 302 {
					w.Header().Set("Location", target.URL)
				}
				w.WriteHeader(code)
				_, _ = io.WriteString(w, `{"error":"try again"}`)
			}))
			defer server.Close()
			c, err := New(Options{Endpoint: server.URL, RootCAs: testutil.TLSRoots(server), APIKey: "secret"})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_, err = c.Status(context.Background())
			if apiErr, ok := errors.AsType[*Error](err); !ok || apiErr.StatusCode != code || apiErr.Message != "try again" {
				t.Fatalf("unexpected error: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err = c.Status(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
		})
	}
	if redirected {
		t.Fatal("followed redirect with credentials")
	}
}

func TestClientTimeout(t *testing.T) {
	for _, test := range []struct {
		name          string
		timeout, want time.Duration
	}{
		{"default", 0, DefaultTimeout},
		{"explicit", 250 * time.Millisecond, 250 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, err := New(Options{Timeout: test.timeout})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if c.http.Timeout != test.want {
				t.Fatalf("timeout = %v, want %v", c.http.Timeout, test.want)
			}
		})
	}
}

func TestEndpointNormalization(t *testing.T) {
	for _, test := range []struct{ endpoint, want string }{
		{"HTTPS://API.Example:00443/", "https://api.example"},
		{"http://API.Example:00080/", "http://api.example"},
		{"https://127.0.0.1:00443", "https://127.0.0.1"},
		{"https://127.0.0.1:09443/", "https://127.0.0.1:9443"},
		{"http://127.0.0.1:08080", "http://127.0.0.1:8080"},
		{"https://[0:0:0:0:0:0:0:1]:00443/", "https://[::1]"},
		{"https://[2001:0DB8:0:0:0:0:0:1]:09443", "https://[2001:db8::1]:9443"},
		{"http://[2001:DB8::1]:00080/", "http://[2001:db8::1]"},
		{"https://[0:0:0:0:0:FFFF:7F00:1]:443", "https://[::ffff:127.0.0.1]"},
		{"https://[FE80::1%25LAN]:00443/", "https://[fe80::1%25LAN]"},
		{"https://[fe80::1%25LAN]:09080", "https://[fe80::1%25LAN]:9080"},
		{"unix:///tmp/dae.sock", "http://localhost"},
	} {
		t.Run(test.endpoint, func(t *testing.T) {
			c, err := New(Options{Endpoint: test.endpoint})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if c.base != test.want {
				t.Fatalf("base = %q, want %q", c.base, test.want)
			}
		})
	}
}

func TestEndpointValidation(t *testing.T) {
	for _, endpoint := range []string{
		"/var/run/dae.sock", "unix://host/tmp/sock", "unix:///", "http://user:pass@127.0.0.1",
		"http://127.0.0.1/api", "http://127.0.0.1?", "http://127.0.0.1/#token", "https://127.0.0.1#",
		"https://:443", "https://127.0.0.1:", "https://127.0.0.1:0", "https://127.0.0.1:65536",
		"https://[not-an-ip]", "https://[127.0.0.1]", "https://::1", "https://[2001:db8::1%25eth0]", "https://[fe80::1%25LAN]:", "https://*.example",
	} {
		if c, err := New(Options{Endpoint: endpoint}); err == nil {
			c.Close()
			t.Errorf("accepted %s", endpoint)
		}
	}
	if _, err := New(Options{Timeout: -time.Second}); err == nil {
		t.Error("negative timeout accepted")
	}
}

func TestScopedEndpointOrigin(t *testing.T) {
	c, err := New(Options{Endpoint: "https://[fe80::1%25LAN]:9080"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.origin != "https://[fe80::1]:9080" {
		t.Fatalf("challenge origin = %q", c.origin)
	}
}

func TestClientDoesNotDependOnDefaultTransport(t *testing.T) {
	// Applications may wrap the process-wide transport for logging or tracing.
	previous := http.DefaultTransport
	http.DefaultTransport = &struct{ http.RoundTripper }{previous}
	defer func() { http.DefaultTransport = previous }()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"schema":16}`)
	}))
	defer server.Close()
	c, err := New(Options{Endpoint: server.URL, RootCAs: testutil.TLSRoots(server)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOversizedErrorKeepsHTTPStatus(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, strings.Repeat("x", (8<<10)+1))
	}))
	defer server.Close()
	c, err := New(Options{Endpoint: server.URL, RootCAs: testutil.TLSRoots(server)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	result, err := c.Status(context.Background())
	if apiErr, ok := errors.AsType[*Error](err); result != nil || !ok || apiErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("oversized error lost HTTP status: %v", err)
	}
}

func TestStatusAcceptsChangingHealthAndRejectsInvalidEnvelope(t *testing.T) {
	for _, test := range []struct {
		name, body string
		wantError  bool
	}{
		{"health transition", `{"schema":16,"version":"test","groups":[{"name":"proxy","selected_node_ids":["node","","",""],"nodes":[{"id":"node","healthy":false}]}]}`, false},
		{"unavailable table usage", `{"schema":16,"tables":[{"name":"tcp_flow_map","scope":"kernel","on_full":"evict","used":0,"limit":16,"error":"read map: permission denied"}]}`, false},
		{"unsupported schema", `{"schema":99}`, true},
		{"registry counts unavailable", `{"schema":9,"tables":[{"name":"domain-registry","used":6896,"limit":0,"breakdown":{"gc":0}}]}`, true},
		{"missing schema", `{}`, true},
		{"null", `null`, true},
		{"old per-path fallback schema", `{"schema":10}`, true},
		{"duplicate key", `{"schema":16,"schema":16}`, true},
		{"trailing JSON", `{"schema":16} {}`, true},
		{"old domain-only tables schema", `{"schema":14}`, true},
		{"old registry pair usage schema", `{"schema":15,"tables":[{"name":"domain-registry","used":6896,"limit":0}]}`, true},
		{"wrong type", `{"schema":"16"}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, test.body) }))
			defer server.Close()
			c, err := New(Options{Endpoint: server.URL, RootCAs: testutil.TLSRoots(server)})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			result, err := c.Status(context.Background())
			if (err != nil) != test.wantError {
				t.Fatalf("result=%+v error=%v", result, err)
			}
			if err != nil && result != nil {
				t.Fatal("failed request returned a success-shaped result")
			}
		})
	}
}

func TestUnixDoesNotSendRemoteAPIKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if values := r.Header.Values("Authorization"); len(values) != 0 {
			t.Error("Unix socket received Authorization")
		}
		io.WriteString(w, `{}`)
	})}
	go server.Serve(ln)
	defer server.Close()
	c, err := New(Options{Endpoint: "unix://" + path, APIKey: "remote-only"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Certificate(t.Context()); err != nil {
		t.Fatal(err)
	}
}
