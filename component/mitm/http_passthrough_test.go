// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
)

func TestPassthroughPreservesForwardingHeaders(t *testing.T) {
	for _, supplied := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "supplied"}[supplied], func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://example.com/rpc?signature=a%2Fb&key=1;2", strings.NewReader("request"))
			r.RemoteAddr = "192.0.2.10:12345"
			r.Header.Set("Te", "trailers")
			if supplied {
				r.Header["X-Forwarded-For"] = []string{"198.51.100.1", "198.51.100.2"}
				r.Header.Set("Forwarded", "for=198.51.100.1;proto=https")
				r.Header.Set("X-Forwarded-Host", "original.example")
				r.Header.Set("X-Forwarded-Proto", "https")
			}
			original := r.Header.Clone()
			h := testHost(t, Options{})
			handler := h.handlerForFlow("https", plugin.Flow{Host: "example.com", Port: 443}, roundTripFunc(func(req *http.Request) (*http.Response, error) {
				for _, name := range []string{"X-Forwarded-For", "Forwarded", "X-Forwarded-Host", "X-Forwarded-Proto", "Te"} {
					if !reflect.DeepEqual(req.Header.Values(name), original.Values(name)) {
						t.Errorf("%s changed: got %q want %q", name, req.Header.Values(name), original.Values(name))
					}
				}
				if req.URL.RawQuery != r.URL.RawQuery {
					t.Errorf("changed signed query: %q", req.URL.RawQuery)
				}
				body, err := io.ReadAll(req.Body)
				_ = req.Body.Close()
				if err != nil || string(body) != "request" {
					t.Errorf("body = %q, %v", body, err)
				}
				return response("ok"), nil
			}), http.DefaultClient)
			handler.ServeHTTP(httptest.NewRecorder(), r)
			if r.RemoteAddr != "192.0.2.10:12345" || !reflect.DeepEqual(r.Header, original) {
				t.Fatal("mutated incoming request")
			}
		})
	}
}
