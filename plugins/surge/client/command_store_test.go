// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"bytes"
	"context"
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/client/cli"
)

func TestStoreMigrationCommandUsesAPI(t *testing.T) {
	t.Setenv("DAE_API_KEY", "store-secret")
	for _, test := range []struct {
		name, instance, from, to, errorText string
		count, status, queries, mutations   int
		raw                                 bool
	}{
		{name: "automatic", count: 1, queries: 1, mutations: 1},
		{name: "selected JSON", count: 2, instance: "personal", raw: true, queries: 1, mutations: 1},
		{name: "none", count: 0, queries: 1, errorText: "exactly one"},
		{name: "multiple", count: 2, queries: 1, errorText: "--instance"},
		{name: "missing instance", count: 1, instance: "missing", queries: 1, errorText: "not configured for this command"},
		{name: "invalid", count: 1, from: "local", errorText: "distinct nonzero"},
		{name: "same", count: 1, to: "02:00:00:00:00:aa", errorText: "distinct nonzero"},
		{name: "zero source", count: 1, from: "00:00:00:00:00:00", errorText: "distinct nonzero"},
		{name: "zero target", count: 1, to: "00:00:00:00:00:00", errorText: "distinct nonzero"},
		{name: "multicast source", count: 1, from: "03:00:00:00:00:aa", errorText: "distinct nonzero"},
		{name: "broadcast target", count: 1, to: "ff:ff:ff:ff:ff:ff", errorText: "distinct nonzero"},
		{name: "eui64 source", count: 1, from: "02:00:00:00:00:00:00:aa", errorText: "distinct nonzero"},
		{name: "eui64 target", count: 1, to: "02:00:00:00:00:00:00:bb", errorText: "distinct nonzero"},
		{name: "conflict", count: 1, queries: 1, mutations: 1, status: 409, errorText: "target partition already exists"},
		{name: "published", count: 1, queries: 1, mutations: 1, status: 500, errorText: "was published, but durability is unconfirmed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var queries, mutations atomic.Int32
			instances := []api.PluginInstanceStatus{{ID: "personal", Type: "surge"}, {ID: "work", Type: "surge"}}
			instances = append(instances[:test.count:test.count], api.PluginInstanceStatus{ID: "other", Type: "demo"})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer store-secret" {
					t.Errorf("missing credentials")
				}
				switch r.Method + " " + r.URL.Path {
				case "GET /api/status":
					queries.Add(1)
					if err := json.MarshalWrite(w, api.StatusSnapshot{Schema: api.StatusSchemaVersion, Plugins: instances}, jsonv1.FormatDurationAsNano(true)); err != nil {
						t.Error(err)
					}
				case "POST /api/plugins/personal/store/migrate":
					mutations.Add(1)
					if r.Header.Get("X-Dae-API") != "1" {
						t.Error("missing mutation marker")
					}
					var request api.ScriptStoreMigrateRequest
					if err := json.UnmarshalRead(r.Body, &request); err != nil || request.FromMAC != "02:00:00:00:00:aa" || request.ToMAC != "02:00:00:00:00:bb" {
						t.Errorf("request order/normalization: %+v %v", request, err)
					}
					if test.status != 0 {
						w.WriteHeader(test.status)
						_ = json.MarshalWrite(w, map[string]string{"error": test.errorText})
						return
					}
					_ = json.MarshalWrite(w, api.ScriptStoreMigrateResponse{Instance: "personal", FromMAC: request.FromMAC, ToMAC: request.ToMAC, KeysMoved: 7})
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			command := cli.NewMITMCommand(map[string]cli.MITMCommands{"surge": Commands})
			var output bytes.Buffer
			command.SetOut(&output)
			command.SetErr(io.Discard)
			from, to := test.from, test.to
			if from == "" {
				from = "02-00-00-00-00-AA"
			}
			if to == "" {
				to = "02:00:00:00:00:bb"
			}
			args := []string{"surge", "store", "migrate", from, to, "--api", server.URL}
			if test.instance != "" {
				args = append(args, "--instance", test.instance)
			}
			if test.raw {
				args = append(args, "--json")
			}
			command.SetArgs(args)
			err := command.ExecuteContext(t.Context())
			if queries.Load() != int32(test.queries) || mutations.Load() != int32(test.mutations) {
				t.Fatalf("requests: queries=%d mutations=%d", queries.Load(), mutations.Load())
			}
			if test.errorText != "" {
				if err == nil || !strings.Contains(err.Error(), test.errorText) || output.Len() != 0 {
					t.Fatalf("error=%v output=%s", err, &output)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.raw {
				var response api.ScriptStoreMigrateResponse
				if err := json.Unmarshal(output.Bytes(), &response); err != nil || response.KeysMoved != 7 || response.Instance != "personal" {
					t.Fatalf("JSON result: %s %v", &output, err)
				}
			} else if !strings.Contains(output.String(), "Moved 7 keys in personal from 02:00:00:00:00:aa to 02:00:00:00:00:bb.") {
				t.Fatalf("text result: %s", &output)
			}
		})
	}
}

func TestStoreMigrationCommandNilCallbacksAndTerminalText(t *testing.T) {
	fetch := func(context.Context) (api.PluginStatus, error) {
		return api.PluginStatus{Plugins: []api.PluginInstanceStatus{{ID: "one"}}}, nil
	}
	migrate := func(context.Context, string, api.ScriptStoreMigrateRequest) (*api.ScriptStoreMigrateResponse, error) {
		return &api.ScriptStoreMigrateResponse{Instance: "evil\x1b[31m\ninstance", FromMAC: "old\nmac", ToMAC: "new\x1b[2Jmac"}, nil
	}
	for _, test := range []struct {
		name    string
		fetch   cli.MITMSource
		migrate cli.ScriptStoreMigrator
		fail    bool
	}{
		{"no fetch", nil, migrate, true}, {"no migrator", fetch, nil, true}, {"terminal", fetch, migrate, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := NewSurgeStoreCommand(test.fetch, test.migrate)
			var output bytes.Buffer
			command.SetOut(&output)
			command.SetErr(io.Discard)
			command.SetArgs([]string{"migrate", "02:00:00:00:00:aa", "02:00:00:00:00:bb"})
			err := command.ExecuteContext(t.Context())
			if (err != nil) != test.fail || test.fail && !strings.Contains(err.Error(), "unavailable") {
				t.Fatalf("nil callback: %v", err)
			}
			if !test.fail && (strings.Contains(output.String(), "\x1b") || strings.Count(output.String(), "\n") != 1) {
				t.Fatalf("unsafe terminal text: %q", output.String())
			}
		})
	}
}
