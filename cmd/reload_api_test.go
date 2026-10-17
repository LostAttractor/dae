// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"bytes"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
)

func TestReloadCommandsUseConfiguredAPI(t *testing.T) {
	for _, kind := range []string{"reload", "suspend"} {
		for _, explicit := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "/environment", true: "/flag"}[explicit], func(t *testing.T) {
				t.Setenv("DAE_API_KEY", "command-test-key")
				requests := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests++
					if r.Header.Get("Authorization") != "Bearer command-test-key" {
						t.Error("missing configured API credential")
					}
					switch r.Method + " " + r.URL.Path {
					case "POST /api/operations":
						var request api.OperationRequest
						if err := json.UnmarshalRead(r.Body, &request); err != nil {
							t.Error(err)
						}
						if request.Kind != kind || !request.Abort || request.ExpectedPID != 123 {
							t.Errorf("operation request = %+v", request)
						}
						w.WriteHeader(http.StatusAccepted)
						_ = json.MarshalWrite(w, api.Operation{ID: "mine", Kind: kind, State: "queued"})
					case "GET /api/operations/mine":
						_ = json.MarshalWrite(w, api.Operation{ID: "mine", Kind: kind, State: "completed", Result: "finished"})
					default:
						t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				defer server.Close()
				t.Setenv("DAE_API_ENDPOINT", server.URL)
				args := []string{"123", "--abort"}
				if explicit {
					t.Setenv("DAE_API_ENDPOINT", "unix:///unused/dae.sock")
					args = append(args, "--api", server.URL)
				}
				command := newReloadCommand(kind == "suspend")
				var output bytes.Buffer
				command.SetOut(&output)
				command.SetErr(&output)
				command.SetArgs(args)
				if err := command.ExecuteContext(t.Context()); err != nil {
					t.Fatal(err)
				}
				if requests != 2 || !strings.Contains(output.String(), "finished") {
					t.Fatalf("requests=%d, output=%q", requests, output.String())
				}
			})
		}
	}
}
