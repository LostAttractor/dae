// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
)

// HTTP permits an empty Request.Host to mean URL.Host. Binding a fronted URL
// to its ingress must preserve that wire authority and the plugin's URL view.
func TestFrontedRequestPreservesPluginView(t *testing.T) {
	for _, clearHost := range []bool{false, true} {
		t.Run(fmt.Sprintf("clear_host=%t", clearHost), func(t *testing.T) {
			const businessURL = "https://business.example/path?key=value"
			p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("business.example")}}}}
			p.wrap = func(_ plugin.Flow, next plugin.Handler) plugin.Handler {
				return func(e *plugin.Exchange) (*http.Response, error) {
					if clearHost {
						e.Request.Host = ""
					}
					resp, err := next(e)
					if err == nil && (resp.Request != e.Request || resp.Request.URL.String() != businessURL) {
						t.Errorf("response hook saw transport request instead of business request: %s", resp.Request.URL)
					}
					return resp, err
				}
			}
			ca, _ := http3TestAuthority(t)
			h := testHost(t, Options{Authority: ca}, Instance{Plugin: p})
			handler := h.handlerForFlow("https", plugin.Flow{Host: "ingress.example", Port: 443}, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				authority := r.Host
				if authority == "" {
					authority = r.URL.Host
				}
				if r.URL.Hostname() != "ingress.example" || authority != "business.example" {
					t.Errorf("network/HTTP targets changed: %s / %s", r.URL.Host, authority)
				}
				resp := response("ok")
				resp.Request = r
				return resp, nil
			}), http.DefaultClient)
			r := httptest.NewRequest(http.MethodGet, businessURL, nil)
			r.ProtoMajor, r.Proto = 2, "HTTP/2.0"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != 200 || w.Body.String() != "ok" {
				t.Fatalf("fronted response: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestConnectionPlanRetriesInvalidSelection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	defer upstream.Close()
	var plans atomic.Int32
	h := testHost(t, Options{})
	transport := h.connectionTransport("http", plugin.Flow{Host: "example.com", Port: 80}, func(*http.Request) (UpstreamPlan, error) {
		plan := UpstreamPlan{Key: "original"}
		if plans.Add(1) != 1 {
			plan.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", upstream.Listener.Addr().String())
			}
		}
		return plan, nil
	}, false)
	defer transport.close()
	for attempt := range 3 {
		r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil)
		resp, err := transport.RoundTrip(r)
		if attempt == 0 {
			if err == nil {
				resp.Body.Close()
				t.Fatal("incomplete plan forwarded a request")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || string(body) != "ok" {
			t.Fatalf("retry response: %d %q %v", resp.StatusCode, body, err)
		}
	}
	if plans.Load() != 2 {
		t.Fatalf("invalid plan was cached or valid plan reselected: %d", plans.Load())
	}
}
