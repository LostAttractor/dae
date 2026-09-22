// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"context"
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/spf13/cobra"
)

func TestMITMCommandsUseAPIAndScopeReports(t *testing.T) {
	t.Setenv("DAE_API_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("DAE_API_KEY", "report-secret")
	instances := []api.PluginInstanceStatus{
		{ID: "personal", Type: "surge", State: "active", Details: jsonv1.RawMessage(`{"enabled":true,"modules":[{"name":"shared","state":"cached","warnings":["offline"]}]}`)},
		{ID: "work", Type: "surge", State: "active", Details: jsonv1.RawMessage(`{"enabled":true,"modules":[{"name":"shared","state":"loaded"}]}`)},
		{ID: "native", Type: "demo", State: "active", Details: jsonv1.RawMessage(`{"running":7,"tasks":[{"name":"hidden-in-summary"}]}`)},
	}
	memory := api.BufferMemoryStatus{Limit: 64 << 20, Used: 1 << 20, Peak: 2 << 20, Denied: 3}
	for i := range instances {
		instances[i].BufferMemory = &memory
	}
	var queries atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries.Add(1)
		if r.Method != "GET" || r.URL.Path != "/api/status" || r.Header.Get("Authorization") != "Bearer report-secret" {
			t.Errorf("unexpected API request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.MarshalWrite(w, api.StatusSnapshot{Schema: api.StatusSchemaVersion, Plugins: instances})
	}))
	defer server.Close()
	for _, test := range []struct {
		name, want, absent string
		args               []string
		count              int
		wantError          bool
	}{
		{name: "all JSON", args: []string{"status", "--json"}, count: 3},
		{name: "verbose JSON", args: []string{"status", "--json", "-v"}, count: 3},
		{name: "all verbose", args: []string{"status", "--verbose"}, want: "hidden-in-summary"},
		{name: "verbose Surge instance", args: []string{"status", "-v", "--instance", "personal"}, want: "personal/shared: offline", absent: "native"},
		{name: "verbose native instance", args: []string{"status", "-v", "--instance", "native"}, want: "hidden-in-summary", absent: "personal"},
		{name: "instance JSON", args: []string{"surge", "status", "--json", "--instance", "personal"}, count: 1, absent: "work"},
		{name: "native summary", args: []string{"status", "--instance", "native"}, want: "running=7", absent: "hidden-in-summary"},
		{name: "Surge table", args: []string{"surge", "status"}, want: "personal/shared: offline", absent: "native"},
		{name: "wrong type", args: []string{"surge", "status", "--instance", "native"}, wantError: true},
		{name: "missing instance", args: []string{"status", "--instance", "absent"}, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := queries.Load()
			command := NewMITMCommand()
			var output bytes.Buffer
			command.SetOut(&output)
			command.SetErr(&output)
			command.SetArgs(append(test.args, "--api", server.URL, "--timeout", "1s"))
			err := command.Execute()
			if got := queries.Load() - before; got != 1 {
				t.Fatalf("queried daemon %d times, want one snapshot", got)
			}
			if (err != nil) != test.wantError {
				t.Fatalf("error=%v output=%s", err, output.String())
			}
			if test.wantError {
				return
			}
			if !strings.Contains(output.String(), test.want) || (test.absent != "" && strings.Contains(output.String(), test.absent)) {
				t.Fatalf("unexpected report: %s", output.String())
			}
			if test.count > 0 {
				var reports []api.PluginInstanceStatus
				if err := json.Unmarshal(output.Bytes(), &reports); err != nil || len(reports) != test.count || len(reports[0].Details) == 0 {
					t.Fatalf("raw reports lost details: %v %s", err, output.String())
				}
				for _, report := range reports {
					if report.BufferMemory == nil || *report.BufferMemory != memory {
						t.Fatalf("raw report lost buffer memory statistics: %+v", report.BufferMemory)
					}
				}
			} else if test.args[0] == "status" {
				const summary = "Body buffers (process): 1.00 / 64.00 MiB; peak=2.00 MiB; denied=3"
				if strings.Count(output.String(), summary) != 1 {
					t.Fatalf("process memory summary missing or duplicated: %s", output.String())
				}
			}
		})
	}
}

func TestReportCommandsPreserveCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fetch := func(ctx context.Context) ([]api.PluginInstanceStatus, error) { return nil, ctx.Err() }
	for _, command := range []*cobra.Command{NewMITMStatusCommand(fetch, nil), NewSurgeStatusCommand(fetch)} {
		command.SetContext(ctx)
		command.SetArgs(nil)
		command.SetOut(&bytes.Buffer{})
		command.SetErr(&bytes.Buffer{})
		if err := command.Execute(); !errors.Is(err, context.Canceled) {
			t.Fatalf("lost cancellation: %v", err)
		}
	}
}
