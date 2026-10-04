// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/mitm/surge"
	"github.com/daeuniverse/dae/component/plugin"
)

func TestSurgeRunCommandSelection(t *testing.T) {
	snapshot := []plugin.InstanceStatus{
		{ID: "personal", Type: "surge", Details: []byte(`{"enabled":true,"modules":[{"name":"account","tasks":[{"name":"sign","type":"cron"}]},{"name":"another","tasks":[{"name":"sign","type":"generic"}]}]}`)},
		{ID: "work", Type: "surge", Details: []byte(`{"enabled":true,"modules":[{"name":"account","tasks":[{"name":"sign","type":"cron"}]}]}`)},
	}
	for _, test := range []struct {
		name, instance, module, script, errorText string
		scriptType                                string
		fetchErr, triggerErr                      error
		calls                                     int
		raw                                       bool
	}{
		{name: "selected", instance: "work", module: "account", script: "sign", scriptType: "cron", calls: 1},
		{name: "selected JSON", instance: "work", module: "account", script: "sign", scriptType: "cron", calls: 1, raw: true},
		{name: "generic", instance: "personal", module: "another", script: "sign", scriptType: "generic", calls: 1},
		{name: "generic JSON", instance: "personal", module: "another", script: "sign", scriptType: "generic", calls: 1, raw: true},
		{name: "ambiguous instance", module: "account", script: "sign", errorText: "ambiguous"},
		{name: "ambiguous module", instance: "personal", script: "sign", errorText: "ambiguous"},
		{name: "missing", instance: "work", script: "other", errorText: "not found"},
		{name: "missing name", errorText: "surge list"},
		{name: "API failure", script: "sign", fetchErr: errors.New("daemon unavailable"), errorText: "daemon unavailable"},
		{name: "trigger conflict", instance: "work", module: "account", script: "sign", calls: 1, triggerErr: plugin.ErrScriptBusy, errorText: plugin.ErrScriptBusy.Error()},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			definition := surge.Plugin
			definition.Configure = func(plugin.Spec) (plugin.Factory, error) {
				t.Fatal("run command initialized a local plugin")
				return nil, nil
			}
			command := newPluginsCommand(map[string]plugin.Definition{"surge": definition}, plugin.CommandServices{
				Status: func(context.Context) ([]plugin.InstanceStatus, error) { return snapshot, test.fetchErr },
				TriggerScript: func(ctx context.Context, instance string, request api.ScriptRunRequest) (*api.ScriptRunResponse, error) {
					calls++
					if ctx != t.Context() || instance != test.instance || request.Module != test.module || request.Script != test.script {
						t.Errorf("wrong execution request: %s %+v", instance, request)
					}
					if test.triggerErr != nil {
						return nil, test.triggerErr
					}
					return &api.ScriptRunResponse{Instance: instance, Module: request.Module, Run: 2, Status: api.ScriptTaskStatus{Name: request.Script, Type: test.scriptType, State: "waiting", LastTrigger: "http-api"}}, nil
				},
			})
			var output bytes.Buffer
			command.SetOut(&output)
			command.SetErr(io.Discard)
			args := []string{"surge", "run", "--instance", test.instance, "--module", test.module}
			if test.script != "" {
				args = append(args, test.script)
			}
			if test.raw {
				args = append(args, "--json")
			}
			command.SetArgs(args)
			err := command.ExecuteContext(t.Context())
			if (err != nil) != (test.errorText != "") || err != nil && !strings.Contains(err.Error(), test.errorText) || calls != test.calls {
				t.Fatalf("error=%v calls=%d output=%s", err, calls, &output)
			}
			if err != nil {
				if output.Len() != 0 {
					t.Fatalf("failed request printed an acceptance: %s", &output)
				}
				return
			}
			if test.raw {
				var response api.ScriptRunResponse
				if err := json.Unmarshal(output.Bytes(), &response); err != nil || response.Instance != test.instance || response.Module != test.module || response.Run != 2 || response.Status.Type != test.scriptType || response.Status.State != "waiting" || response.Status.LastTrigger != "http-api" || response.Status.LastResult != "" {
					t.Fatalf("invalid acceptance snapshot: %+v %v", response, err)
				}
			} else if !strings.Contains(output.String(), fmt.Sprintf("Accepted %s %s/%s/%s (run 2)", test.scriptType, test.instance, test.module, test.script)) {
				t.Fatalf("missing acceptance: %s", &output)
			}
		})
	}
}

func TestSurgeListCommandDiscovery(t *testing.T) {
	snapshot := []plugin.InstanceStatus{
		{ID: "personal", Type: "surge", Details: []byte(`{"enabled":true,"modules":[{"name":"account","tasks":[{"name":"签到任务","type":"cron","cronexp":"5 9 * * *","state":"scheduled"}]},{"name":"another","tasks":[{"name":"签到任务","type":"generic","state":"ready"}]},{"name":"http-only","scripts":1}],"notifications":[{"title":"private-notification"}]}`)},
		{ID: "work", Type: "surge", Details: []byte(`{"enabled":true,"modules":[{"name":"account","tasks":[{"name":"签到任务","type":"cron","cronexp":"5 9 * * *","state":"running"}]}]}`)},
	}
	for _, test := range []struct {
		name                    string
		args                    []string
		want, absent, errorText string
		count, queries          int
		raw                     bool
		fetchErr                error
	}{
		{name: "all", count: 3, queries: 1, want: "generic", absent: "http-only"},
		{name: "instance", args: []string{"--instance", "work"}, count: 1, queries: 1, want: "running", absent: "personal"},
		{name: "module", args: []string{"--module", "account"}, count: 2, queries: 1, want: "personal", absent: "another"},
		{name: "all JSON", raw: true, count: 3, queries: 1},
		{name: "selected JSON", args: []string{"--instance", "personal", "--module", "another"}, raw: true, count: 1, queries: 1, want: `"state":"ready"`, absent: "cronexp"},
		{name: "empty JSON", args: []string{"--module", "missing"}, raw: true, queries: 1, want: "[]"},
		{name: "empty", args: []string{"--module", "missing"}, queries: 1, want: "No configured Surge script tasks"},
		{name: "missing instance", args: []string{"--instance", "missing"}, queries: 1, errorText: "not active"},
		{name: "daemon error", queries: 1, fetchErr: errors.New("daemon unavailable"), errorText: "daemon unavailable"},
		{name: "unexpected argument", args: []string{"script"}, errorText: "unknown command"},
	} {
		t.Run(test.name, func(t *testing.T) {
			queries := 0
			definition := surge.Plugin
			definition.Configure = func(plugin.Spec) (plugin.Factory, error) {
				t.Fatal("list initialized a local plugin")
				return nil, nil
			}
			command := newPluginsCommand(map[string]plugin.Definition{"surge": definition}, plugin.CommandServices{
				Status: func(ctx context.Context) ([]plugin.InstanceStatus, error) {
					queries++
					if ctx != t.Context() {
						t.Error("list lost the caller context")
					}
					return snapshot, test.fetchErr
				},
				TriggerScript: func(context.Context, string, api.ScriptRunRequest) (*api.ScriptRunResponse, error) {
					t.Fatal("list triggered a script")
					return nil, nil
				},
			})
			var output bytes.Buffer
			command.SetOut(&output)
			command.SetErr(io.Discard)
			args := append([]string{"surge", "list"}, test.args...)
			if test.raw {
				args = append(args, "--json")
			}
			command.SetArgs(args)
			err := command.ExecuteContext(t.Context())
			if (err != nil) != (test.errorText != "") || err != nil && !strings.Contains(err.Error(), test.errorText) || queries != test.queries {
				t.Fatalf("error=%v queries=%d output=%s", err, queries, &output)
			}
			if err != nil {
				if output.Len() != 0 {
					t.Fatalf("failed discovery printed tasks: %s", &output)
				}
				return
			}
			if !strings.Contains(output.String(), test.want) || test.absent != "" && strings.Contains(output.String(), test.absent) || strings.Contains(output.String(), "private-notification") {
				t.Fatalf("unexpected task list: %s", &output)
			}
			if test.raw {
				var tasks []struct {
					Instance string `json:"instance"`
					Module   string `json:"module"`
					Name     string `json:"name"`
					Type     string `json:"type"`
					State    string `json:"state"`
					CronExp  string `json:"cronexp"`
				}
				if err := json.Unmarshal(output.Bytes(), &tasks); err != nil || len(tasks) != test.count {
					t.Fatalf("invalid task JSON: %s %v", &output, err)
				}
				for _, task := range tasks {
					if task.Instance == "" || task.Module == "" || task.Name != "签到任务" || task.State == "" || task.Type != "generic" && (task.Type != "cron" || task.CronExp == "") {
						t.Fatalf("task lost selectors/metadata: %+v", task)
					}
				}
			} else if test.count > 0 {
				if strings.Count(output.String(), "签到任务") != test.count || !strings.Contains(output.String(), "run <SCRIPT> --instance <INSTANCE> --module <MODULE>") {
					t.Fatalf("missing tasks or execution instructions: %s", &output)
				}
			}
		})
	}
}
