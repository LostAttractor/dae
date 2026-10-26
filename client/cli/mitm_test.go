// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/spf13/cobra"
)

func TestMITMVerboseDisabledSelectionPreservesSnapshot(t *testing.T) {
	snapshot := api.PluginStatus{CompiledPlugins: []string{"fixture", "unused"}, BufferMemory: api.BufferMemoryStatus{Limit: 4096},
		Plugins: []api.PluginInstanceStatus{{ID: "disabled", Type: "fixture", State: "disabled", HTTPReason: "disabled"}, {ID: "other", Type: "other"}}}
	fetch := func(context.Context) (api.PluginStatus, error) { return snapshot, nil }
	called := false
	command := NewMITMStatusCommand(SelectMITM(fetch, "", new("disabled")), func(kind string, scoped MITMSource) (*cobra.Command, bool) {
		return NewMITMPluginCommand(kind, scoped, func(selected MITMSource) []*cobra.Command {
			return []*cobra.Command{NewReportCommand(selected, func(_ *cobra.Command, got api.PluginStatus) error {
				called = true
				if !reflect.DeepEqual(got.CompiledPlugins, snapshot.CompiledPlugins) || got.BufferMemory != snapshot.BufferMemory || len(got.Plugins) != 1 || got.Plugins[0].ID != "disabled" {
					t.Fatalf("filtered renderer lost snapshot: %+v", got)
				}
				return nil
			})}
		})
	})
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"--verbose"})
	if err := command.ExecuteContext(t.Context()); err != nil || !called {
		t.Fatalf("disabled selection failed: %v, %s", err, &output)
	}
	for _, want := range []string{"Compiled plugins: fixture, unused", "disabled", "ENABLED", "HTTP", "SCOPES (EFF/DECL)"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q: %s", want, &output)
		}
	}
}

func TestMITMProcessMemorySurvivesEmptySelection(t *testing.T) {
	memory := api.BufferMemoryStatus{Limit: 64 << 20, Used: 1 << 20, Peak: 2 << 20, Denied: 3}
	for _, instances := range [][]api.PluginInstanceStatus{nil, {{ID: "other", Type: "other"}}} {
		for _, raw := range []bool{false, true} {
			fetch := func(context.Context) (api.PluginStatus, error) {
				return api.PluginStatus{CompiledPlugins: []string{"selected", "other"}, BufferMemory: memory, Plugins: instances}, nil
			}
			command := NewMITMStatusCommand(SelectMITM(fetch, "selected", new("")), nil)
			var output bytes.Buffer
			command.SetOut(&output)
			command.SetErr(&output)
			args := []string{}
			if raw {
				args = append(args, "--json")
			}
			command.SetArgs(args)
			if err := command.ExecuteContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			if raw {
				var got api.PluginStatus
				if err := json.Unmarshal(output.Bytes(), &got); err != nil || got.BufferMemory != memory || len(got.Plugins) != 0 || !reflect.DeepEqual(got.CompiledPlugins, []string{"selected", "other"}) {
					t.Fatalf("empty selection lost process status: %s (%v)", &output, err)
				}
			} else if !strings.Contains(output.String(), "1.00 / 64.00 MiB") || !strings.Contains(output.String(), "no configured instances") {
				t.Fatalf("empty selection hides process budget: %s", &output)
			}
		}
	}
}
