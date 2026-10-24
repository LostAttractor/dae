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

func (s *resourceStoreTest) SubmitOperation(api.OperationRequest) (api.Operation, error) {
	s.calls++
	return api.Operation{ID: "operation", Kind: "refresh", State: "queued"}, nil
}
func (s *resourceStoreTest) ResourceRefreshStatus() api.ResourceRefreshStatus {
	return api.ResourceRefreshStatus{}
}

func TestResourceRefreshAPIValidation(t *testing.T) {
	for _, test := range []struct {
		name, method, key, marker, origin, body string
		want, calls                             int
	}{
		{"accepted", "POST", "secret", "1", "", "", 202, 1},
		{"status", "GET", "secret", "", "", "", 200, 0},
		{"head status", "HEAD", "secret", "", "", "", 200, 0},
		{"no auth", "POST", "", "1", "", "", 401, 0},
		{"no marker", "POST", "secret", "", "", "", 403, 0},
		{"cross origin", "POST", "secret", "1", "http://independent.example", "", 403, 0},
		{"unexpected body", "POST", "secret", "1", "", "{}", 400, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &resourceStoreTest{}
			handler := NewHandler(Options{AdminKey: "secret", Operations: store})
			path := "/api/resources"
			if test.method == "POST" {
				path += "/refresh"
			}
			r := httptest.NewRequest(test.method, "https://192.0.2.1:8081"+path, strings.NewReader(test.body))
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

func (s *resourceStoreTest) Operation(id string) (api.Operation, bool) {
	return api.Operation{ID: "operation", Kind: "refresh", State: "queued"}, id == "operation"
}

func TestReadOnlyOperationRoutesNeverSubmit(t *testing.T) {
	for _, transport := range []string{"tcp", "unix"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			for _, test := range []struct {
				path, body string
				status     int
			}{
				{"/api/resources", "", 200},
				{"/api/resources", `{}`, 400},
				{"/api/operations/operation", "", 200},
				{"/api/operations/missing", "", 404},
				{"/api/operations/missing", `{"kind":"reload"}`, 400},
			} {
				t.Run(transport+"/"+method+test.path+test.body, func(t *testing.T) {
					store := &resourceStoreTest{}
					var handler http.Handler = NewHandler(Options{AdminKey: "secret", Operations: store})
					r := httptest.NewRequestWithContext(t.Context(), method, "https://192.0.2.1:9080"+test.path, strings.NewReader(test.body))
					var local net.Addr = &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9080}
					if transport == "unix" {
						local = &net.UnixAddr{Net: "unix", Name: "dae.sock"}
						server := &Server{}
						server.SetLocalServices(LocalServices{Operations: store})
						handler = server
					}
					r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, local))
					r.Header.Set("Authorization", "Bearer secret")
					r.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, r)
					if w.Code != test.status || store.calls != 0 {
						t.Fatalf("status=%d writes=%d body=%s", w.Code, store.calls, w.Body)
					}
				})
			}
		}
	}
}
