// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSettingsRequests(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		}
	}))
	defer server.Close()
	c, err := New(Options{Endpoint: server.URL, Token: "secret"})
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
	if requests != 5 {
		t.Fatalf("requests = %d", requests)
	}
}

func TestErrorsCancellationAndRedirects(t *testing.T) {
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected = true }))
	defer target.Close()
	for _, code := range []int{401, 403, 409, 503, 302} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if code == 302 {
					w.Header().Set("Location", target.URL)
				}
				w.WriteHeader(code)
				_, _ = io.WriteString(w, `{"error":"try again"}`)
			}))
			defer server.Close()
			c, err := New(Options{Endpoint: server.URL, Token: "secret"})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_, err = c.Status(context.Background())
			var apiErr *Error
			if !errors.As(err, &apiErr) || apiErr.StatusCode != code || apiErr.Message != "try again" {
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

func TestEndpointValidation(t *testing.T) {
	for _, endpoint := range []string{"/var/run/dae.sock", "unix://host/tmp/sock", "unix:///", "http://user:pass@127.0.0.1", "http://127.0.0.1/api", "http://127.0.0.1?", "http://127.0.0.1/#token"} {
		if c, err := New(Options{Endpoint: endpoint}); err == nil {
			c.Close()
			t.Errorf("accepted %s", endpoint)
		}
	}
	if _, err := New(Options{Timeout: -time.Second}); err == nil {
		t.Error("negative timeout accepted")
	}
}

func TestClientDoesNotDependOnDefaultTransport(t *testing.T) {
	// Applications may wrap the process-wide transport for logging or tracing.
	previous := http.DefaultTransport
	http.DefaultTransport = &struct{ http.RoundTripper }{previous}
	defer func() { http.DefaultTransport = previous }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"schema":7}`)
	}))
	defer server.Close()
	c, err := New(Options{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOversizedErrorKeepsHTTPStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, strings.Repeat("x", (8<<10)+1))
	}))
	defer server.Close()
	c, err := New(Options{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	result, err := c.Status(context.Background())
	var apiErr *Error
	if result != nil || !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("oversized error lost HTTP status: %v", err)
	}
}

func TestStatusAcceptsChangingHealthAndRejectsInvalidEnvelope(t *testing.T) {
	for _, test := range []struct {
		name, body string
		wantError  bool
	}{
		{"health transition", `{"schema":7,"version":"test","groups":[{"name":"proxy","selected_node_ids":["node","","",""],"nodes":[{"id":"node","healthy":false}]}]}`, false},
		{"unsupported schema", `{"schema":99}`, true},
		{"missing schema", `{}`, true},
		{"null", `null`, true},
		{"duplicate key", `{"schema":7,"schema":7}`, true},
		{"trailing JSON", `{"schema":7} {}`, true},
		{"wrong type", `{"schema":"7"}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, test.body) }))
			defer server.Close()
			c, err := New(Options{Endpoint: server.URL})
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
