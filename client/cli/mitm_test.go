// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
)

func TestMITMProcessMemorySurvivesEmptySelection(t *testing.T) {
	memory := api.BufferMemoryStatus{Limit: 64 << 20, Used: 1 << 20, Peak: 2 << 20, Denied: 3}
	for _, instances := range [][]api.PluginInstanceStatus{nil, {{ID: "other", Type: "other"}}} {
		for _, raw := range []bool{false, true} {
			fetch := func(context.Context) (api.PluginStatus, error) {
				return api.PluginStatus{BufferMemory: memory, Plugins: instances}, nil
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
				if err := json.Unmarshal(output.Bytes(), &got); err != nil || got.BufferMemory != memory || len(got.Plugins) != 0 {
					t.Fatalf("empty selection lost process status: %s (%v)", &output, err)
				}
			} else if !strings.Contains(output.String(), "1.00 / 64.00 MiB") || !strings.Contains(output.String(), "no active plugin instances") {
				t.Fatalf("empty selection hides process budget: %s", &output)
			}
		}
	}
}
