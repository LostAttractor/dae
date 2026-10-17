// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"strings"
	"testing"
	"unicode"

	"github.com/daeuniverse/dae/api"
	surgeapi "github.com/daeuniverse/dae/plugins/surge/api"
)

func TestSurgeTextSinksRemoveTerminalControlsAndPreserveJSON(t *testing.T) {
	const payload = "name\x1b]52;c;YWJj\a\r\u009b2J"
	task := api.ScriptTaskStatus{Name: "probe", Type: "generic"}
	status := surgeapi.SurgeStatus{Enabled: true,
		Modules:       []surgeapi.ModuleStatus{{Name: payload, Error: payload, Warnings: []string{payload}, Tasks: []api.ScriptTaskStatus{task}}},
		Runtimes:      []surgeapi.SurgeRuntimeStatus{{Instance: payload, Backend: payload}},
		Notifications: []surgeapi.SurgeNotification{{Module: payload, Title: payload, Body: payload}},
	}
	details, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	fetch := func(context.Context) (api.PluginStatus, error) {
		return api.PluginStatus{Plugins: []api.PluginInstanceStatus{{ID: "surge", Type: "surge", Details: details}}}, nil
	}
	trigger := func(_ context.Context, _ string, request api.ScriptRunRequest) (*api.ScriptRunResponse, error) {
		if request.Module != payload {
			t.Fatal("display sanitization altered the API request")
		}
		return &api.ScriptRunResponse{Instance: "surge", Module: payload, Status: task, Run: 1}, nil
	}
	assertSafe := func(output string) {
		t.Helper()
		for _, r := range output {
			if unicode.IsControl(r) && r != '\n' && r != '\t' {
				t.Fatalf("terminal control in output: %q", output)
			}
		}
	}
	assertSafe(RenderSurge(status, true))
	for _, raw := range []bool{false, true} {
		command := NewSurgeRunCommand(fetch, trigger)
		var output bytes.Buffer
		command.SetOut(&output)
		command.SetErr(&output)
		args := []string{"probe"}
		if raw {
			args = append(args, "--json")
		}
		command.SetArgs(args)
		if err := command.ExecuteContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		if raw {
			var response api.ScriptRunResponse
			if err := json.Unmarshal(output.Bytes(), &response); err != nil || response.Module != payload {
				t.Fatalf("JSON lost original text: %s %v", output.String(), err)
			}
		} else {
			assertSafe(output.String())
			if !strings.HasPrefix(output.String(), "Accepted generic surge/name") {
				t.Fatalf("lost acceptance: %s", output.String())
			}
		}
	}
}
