// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	jsonv1 "encoding/json"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/internal/testutil"
)

func TestStatusCommandUsesConfiguredAPIAndOutput(t *testing.T) {
	t.Setenv("DAE_API_KEY", "cli-secret")
	requests := 0
	tables := []api.TableUsage{
		{Name: "tcp_flow_map", Scope: "kernel", OnFull: "evict", Used: 3, Limit: 16, Error: "read map: permission denied", Alert: new(api.TableAlert{Level: api.GroupHealthWarning, Message: "usage unavailable"})},
		{Name: "udp-sources", Scope: "userspace", OnFull: "reject", Used: 6, Limit: 8, Alert: new(api.TableAlert{Level: api.GroupHealthWarning, Message: "capacity pressure"})},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != "GET" || r.URL.Path != "/api/status" || r.Header.Get("Authorization") != "Bearer cli-secret" {
			t.Errorf("wrong API request: %s %s", r.Method, r.URL.Path)
		}
		snapshot := api.StatusSnapshot{Schema: api.StatusSchemaVersion, Version: "cli-daemon", StartedAt: time.Now(), Tables: tables, Groups: []api.GroupStatus{{Name: "direct", TargetKind: "builtin"}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, snapshot, jsonv1.FormatDurationAsNano(true))
	}))
	defer server.Close()
	t.Setenv("DAE_API_CA", testutil.TLSFile(t, server))
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
		before := requests
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		if requests != before+1 || !strings.Contains(output.String(), "cli-daemon") {
			t.Fatalf("mode %s did not render one API snapshot: %s", mode, output.String())
		}
		if mode == "--json" {
			var snapshot api.StatusSnapshot
			if err := json.Unmarshal(output.Bytes(), &snapshot, jsonv1.FormatDurationAsNano(true)); err != nil || snapshot.Schema != api.StatusSchemaVersion || !reflect.DeepEqual(snapshot.Tables, tables) {
				t.Fatalf("JSON changed table usage: %+v, %v", snapshot.Tables, err)
			}
		} else {
			for _, want := range []string{"Kernel tables:", "Userspace tables:", "tcp_flow_map", "udp-sources", "unavailable: read map: permission denied"} {
				if !strings.Contains(output.String(), want) {
					t.Errorf("mode %s missing %q: %s", mode, want, output.String())
				}
			}
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
	plugins := NewMITMCommand(nil)
	var output bytes.Buffer
	plugins.SetOut(&output)
	plugins.SetArgs([]string{"status"})
	if err := plugins.Execute(); err != nil || !strings.Contains(output.String(), "no configured instances") {
		t.Fatal(output.String(), err)
	}
}

func TestUnixConnectionIgnoresRemoteCredentialFiles(t *testing.T) {
	c := Connection{endpoint: "unix:///unused.sock", keyFile: "missing-key", caFile: "missing-ca"}
	remote, err := c.Open()
	if err != nil {
		t.Fatal(err)
	}
	remote.Close()
}
