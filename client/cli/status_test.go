// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	jsonv1 "encoding/json"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
)

func TestStatusCommandUsesConfiguredAPIAndOutput(t *testing.T) {
	t.Setenv("DAE_API_KEY", "cli-secret")
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != "GET" || r.URL.Path != "/api/status" || r.Header.Get("Authorization") != "Bearer cli-secret" {
			t.Errorf("wrong API request: %s %s", r.Method, r.URL.Path)
		}
		snapshot := api.StatusSnapshot{Schema: api.StatusSchemaVersion, Version: "cli-daemon", StartedAt: time.Now(), Groups: []api.GroupStatus{{Name: "direct", TargetKind: "builtin"}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, snapshot, jsonv1.FormatDurationAsNano(true))
	}))
	defer server.Close()
	t.Setenv("DAE_API_ENDPOINT", server.URL)
	for _, mode := range []string{"", "--verbose", "--recent", "--json"} {
		cmd := NewStatusCommand()
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		var args []string
		if mode != "" {
			args = []string{mode}
		}
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), "cli-daemon") {
			t.Fatalf("mode %s ignored command output: %s", mode, output.String())
		}
	}
	before := requests
	cmd := NewStatusCommand()
	cmd.SetArgs([]string{"--verbose", "--recent"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || requests != before {
		t.Fatal("invalid flags reached the API")
	}
	surge := NewMITMCommand()
	var output bytes.Buffer
	surge.SetOut(&output)
	surge.SetArgs([]string{"surge", "status"})
	if err := surge.Execute(); err != nil || !strings.Contains(output.String(), "disabled") {
		t.Fatal(output.String(), err)
	}
}
