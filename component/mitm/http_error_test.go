// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/plugin"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

func TestUpstreamFailureDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		canceled bool
		log      bool
	}{
		{"eof", io.EOF, false, true},
		{"closed upstream", net.ErrClosed, false, true},
		{"deadline", context.DeadlineExceeded, false, true},
		{"url credentials", &url.Error{Op: "Post", URL: "https://user:secret@example.com/private?token=secret", Err: io.EOF}, false, true},
		{"client canceled", context.Canceled, true, false},
		{"real HTTP error response", nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger := log.New()
			logger.SetOutput(io.Discard)
			logger.SetLevel(log.DebugLevel)
			hook := logtest.NewLocal(logger)
			h := testHost(t, Options{Logger: log.NewEntry(logger)})
			transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if tc.err != nil {
					return nil, tc.err
				}
				rsp := response("upstream response")
				rsp.StatusCode = http.StatusBadGateway
				return rsp, nil
			})
			handler := h.handlerForFlow("https", plugin.Flow{Host: "example.com", Port: 443}, transport, http.DefaultClient)
			r := httptest.NewRequest("POST", "https://example.com/private?token=secret", nil)
			ctx, cancel := context.WithCancel(plugin.WithIDs(r.Context(), "connection-1", ""))
			defer cancel()
			if tc.canceled {
				cancel()
			}
			r = r.WithContext(ctx)
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, r)
			logs := hook.AllEntries()
			if result.Code != http.StatusBadGateway {
				t.Fatalf("unexpected response: %d", result.Code)
			}
			if tc.log {
				if len(logs) != 1 {
					t.Fatalf("missing failure diagnostic: %v", logs)
				}
				for field, want := range map[string]string{"event": "upstream_error", "connection_id": "connection-1", "method": "POST", "host": "example.com"} {
					if logs[0].Data[field] != want {
						t.Errorf("%s = %v, want %s", field, logs[0].Data[field], want)
					}
				}
				if logs[0].Level != log.DebugLevel || logs[0].Data["request_id"] == "" {
					t.Fatalf("missing request correlation or wrong log level: %v", logs[0])
				}
				message := logs[0].Data["error"].(error).Error()
				if strings.Contains(message, "secret") || strings.Contains(message, "/private") {
					t.Fatalf("exposed URL secrets: %s", message)
				}
			} else if len(logs) != 0 {
				t.Fatalf("logged a canceled request or ordinary HTTP response: %v", logs)
			}
			if tc.err == nil && result.Body.String() != "upstream response" {
				t.Fatal("replaced the real upstream HTTP error response")
			}
		})
	}
}

func TestLocalPluginErrorIsNotAnUpstreamFailure(t *testing.T) {
	p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("example.com")}}}, wrap: func(_ plugin.Flow, _ plugin.Handler) plugin.Handler {
		return func(*plugin.Exchange) (*http.Response, error) {
			return nil, &plugin.HTTPError{Status: 413, Err: errors.New("plugin rejected body")}
		}
	}}
	logger := log.New()
	logger.SetOutput(io.Discard)
	logger.SetLevel(log.DebugLevel)
	hook := logtest.NewLocal(logger)
	h := testHost(t, Options{Authority: &mitmca.Authority{}, Logger: log.NewEntry(logger)}, Instance{Plugin: p})
	handler := h.handlerForFlow("http", plugin.Flow{Host: "example.com", Port: 80}, roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("reached upstream after plugin error")
		return nil, nil
	}), http.DefaultClient)
	r := httptest.NewRecorder()
	handler.ServeHTTP(r, httptest.NewRequest("POST", "http://example.com/", nil))
	if r.Code != 413 {
		t.Fatalf("lost plugin HTTP error: %d", r.Code)
	}
	if logs := hook.AllEntries(); len(logs) != 0 {
		t.Fatalf("misclassified plugin failure: %v", logs)
	}
}
