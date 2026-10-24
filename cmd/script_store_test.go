// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/client/cli"
	"github.com/daeuniverse/dae/common/persist"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/internal/apiserver"
	"github.com/daeuniverse/dae/internal/testutil"
	"github.com/daeuniverse/dae/plugins/surge"
)

type commandStoreMigrator func(context.Context, string, api.ScriptStoreMigrateRequest) (api.ScriptStoreMigrateResponse, error)

func (f commandStoreMigrator) MigrateScriptStore(ctx context.Context, instance string, request api.ScriptStoreMigrateRequest) (api.ScriptStoreMigrateResponse, error) {
	return f(ctx, instance, request)
}

func TestSurgeStoreMigrationDaemonCommandAPI(t *testing.T) {
	t.Setenv("DAE_API_KEY", "secret")
	for _, published := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "published"}[published], func(t *testing.T) {
			var mutations atomic.Int32
			server := httptest.NewTLSServer(apiserver.NewHandler(apiserver.Options{AdminKey: "secret", Status: func() *api.StatusSnapshot {
				return &api.StatusSnapshot{Schema: api.StatusSchemaVersion, Plugins: []api.PluginInstanceStatus{{ID: "personal", Type: "surge"}}}
			}, ScriptStorage: commandStoreMigrator(func(_ context.Context, instance string, request api.ScriptStoreMigrateRequest) (api.ScriptStoreMigrateResponse, error) {
				mutations.Add(1)
				if instance != "personal" || request.FromMAC != "02:00:00:00:00:aa" || request.ToMAC != "02:00:00:00:00:bb" {
					t.Errorf("wrong request: %s %+v", instance, request)
				}
				if published {
					return api.ScriptStoreMigrateResponse{}, persist.AfterPublish(io.ErrUnexpectedEOF)
				}
				return api.ScriptStoreMigrateResponse{Instance: instance, FromMAC: request.FromMAC, ToMAC: request.ToMAC, KeysMoved: 3}, nil
			})}))
			defer server.Close()
			t.Setenv("DAE_API_CA", testutil.TLSFile(t, server))
			var connection cli.Connection
			definition := surge.Plugin
			definition.Configure = func(plugin.Spec) (plugin.Factory, error) {
				t.Fatal("command initialized a local runtime")
				return nil, nil
			}
			command := newPluginsCommand(map[string]plugin.Definition{"surge": definition}, plugin.CommandServices{Status: connection.MITM, MigrateScriptStore: connection.MigrateScriptStore})
			connection.Bind(command.PersistentFlags())
			var output bytes.Buffer
			command.SetOut(&output)
			command.SetErr(io.Discard)
			command.SetArgs([]string{"surge", "store", "migrate", "02-00-00-00-00-AA", "02:00:00:00:00:bb", "--instance", "personal", "--json", "--api", server.URL})
			err := command.ExecuteContext(t.Context())
			if mutations.Load() != 1 {
				t.Fatalf("mutation count: %d", mutations.Load())
			}
			if published {
				if err == nil || !strings.Contains(err.Error(), "was published, but durability is unconfirmed") || output.Len() != 0 {
					t.Fatalf("published result: %v %s", err, &output)
				}
			} else {
				var response api.ScriptStoreMigrateResponse
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(output.Bytes(), &response); err != nil || response.KeysMoved != 3 || response.Instance != "personal" {
					t.Fatalf("result: %s %v", &output, err)
				}
			}
		})
	}
}
