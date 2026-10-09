// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
)

type resourceStoreTest struct{ calls int }

func (s *resourceStoreTest) RefreshResources() (api.ResourceRefreshStatus, error) {
	s.calls++
	return api.ResourceRefreshStatus{State: "queued"}, nil
}
func (s *resourceStoreTest) ResourceRefreshStatus() api.ResourceRefreshStatus {
	return api.ResourceRefreshStatus{State: "idle"}
}

func TestResourceRefreshAPIValidation(t *testing.T) {
	for _, test := range []struct {
		name, method, key, marker, origin, body string
		want, calls                             int
	}{
		{"accepted", "POST", "secret", "1", "", "", 202, 1},
		{"status", "GET", "secret", "", "", "", 200, 0},
		{"no auth", "POST", "", "1", "", "", 401, 0},
		{"no marker", "POST", "secret", "", "", "", 403, 0},
		{"cross origin", "POST", "secret", "1", "http://evil.example", "", 403, 0},
		{"unexpected body", "POST", "secret", "1", "", "{}", 400, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &resourceStoreTest{}
			handler := NewHandler(Options{APIKey: "secret", Resources: store})
			path := "/api/resources"
			if test.method == "POST" {
				path += "/refresh"
			}
			r := httptest.NewRequest(test.method, "http://192.0.2.1:8081"+path, strings.NewReader(test.body))
			r = r.WithContext(context.WithValue(t.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 8081}))
			if test.key != "" {
				r.Header.Set("Authorization", "Bearer "+test.key)
			}
			r.Header.Set("X-Dae-API", test.marker)
			if test.origin != "" {
				r.Header.Set("Origin", test.origin)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != test.want || store.calls != test.calls {
				t.Fatalf("status=%d calls=%d body=%s", w.Code, store.calls, w.Body)
			}
		})
	}
}
