// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStatusRecoveryValidation(t *testing.T) {
	for _, test := range []struct {
		name, node string
		valid      bool
	}{
		{"invented deadline", `{"recovery":{"phase":"connecting","retry_at":"2027-01-01T00:00:00Z"}}`, false},
		{"invalid session", `{"session_detail":{"state":"ready"}}`, false},
		{"actual deadline", `{"recovery":{"phase":"backoff","retry_at":"2027-01-01T00:00:00Z"}}`, true},
		{"library recovery", `{"session_detail":{"state":"connecting"},"recovery":{"executor":"library_managed","phase":"connecting"}}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `{"schema":7,"groups":[{"nodes":[`+test.node+`]}]}`)
			}))
			defer server.Close()
			c, err := New(Options{Endpoint: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err = c.Status(context.Background()); (err == nil) != test.valid {
				t.Fatalf("valid=%v error=%v", test.valid, err)
			}
		})
	}
}
