// SPDX-License-Identifier: AGPL-3.0-only
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/daeuniverse/dae/component/mitm/surge"
	"github.com/spf13/cobra"
)

func TestMITMPluginCommandsUseDaemonReportsWithoutSetup(t *testing.T) {
	var queried bool
	services := plugin.CommandServices{Status: func(ctx context.Context) ([]plugin.InstanceStatus, error) {
		queried = true
		return []plugin.InstanceStatus{
			{ID: "personal", Type: "custom", State: "active", Details: json.RawMessage(`{"running":1}`)},
			{ID: "work", Type: "custom", State: "active", Details: json.RawMessage(`{"running":2}`)},
			{ID: "other", Type: "demo", State: "active"},
		}, nil
	}}
	definitions := map[string]plugin.Definition{
		"surge": surge.Plugin,
		"demo":  {},
		"custom": {
			Setup: func(context.Context, plugin.Spec, plugin.Services) (plugin.Plugin, error) {
				t.Fatal("CLI initialized a runtime plugin")
				return nil, nil
			},
			Commands: func(s plugin.CommandServices) []*cobra.Command {
				return []*cobra.Command{{Use: "inspect", RunE: func(cmd *cobra.Command, _ []string) error {
					status, err := s.Status(cmd.Context())
					if err != nil {
						return err
					}
					return json.NewEncoder(cmd.OutOrStdout()).Encode(status)
				}}}
			},
		},
	}
	command := newMITMCommand(definitions, services)
	if queried {
		t.Fatal("command registration queried daemon")
	}
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"custom", "inspect", "--instance", "work"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !queried || !strings.Contains(output.String(), `"work"`) || strings.Contains(output.String(), `"personal"`) || strings.Contains(output.String(), `"other"`) {
		t.Fatalf("scope leaked: %s", output.String())
	}
	for _, path := range [][]string{{"status"}, {"demo", "status"}, {"custom", "status"}, {"surge", "status"}, {"surge", "configure"}, {"ca", "info"}} {
		child, rest, err := command.Find(path)
		if err != nil || len(rest) != 0 || child.RunE == nil {
			t.Fatalf("missing %v: %v", path, err)
		}
	}
	root := &cobra.Command{Use: "dae"}
	root.AddCommand(command)
	if _, _, err := root.Find([]string{"surge", "status"}); err == nil {
		t.Fatal("legacy dae surge command survived")
	}
}

func TestMITMStatusAggregationAndErrors(t *testing.T) {
	for _, args := range [][]string{{"status", "--json"}, {"demo", "status", "--json"}, {"status", "--instance", "missing"}} {
		command := newMITMCommand(map[string]plugin.Definition{"demo": {}}, plugin.CommandServices{Status: func(context.Context) ([]plugin.InstanceStatus, error) {
			return []plugin.InstanceStatus{{ID: "demo", Type: "demo", State: "active", Details: json.RawMessage(`{"running":1}`)}}, nil
		}})
		var output bytes.Buffer
		command.SetOut(&output)
		command.SetErr(&output)
		command.SetArgs(args)
		err := command.Execute()
		if args[len(args)-1] == "missing" {
			if err == nil {
				t.Fatal("missing instance accepted")
			}
			continue
		}
		var got []plugin.InstanceStatus
		if err != nil || json.Unmarshal(output.Bytes(), &got) != nil || len(got) != 1 || got[0].ID != "demo" {
			t.Fatalf("bad JSON: %v %s", err, output.String())
		}
	}
	sentinel := errors.New("daemon unavailable")
	command := newMITMStatusCommand(func(context.Context) ([]plugin.InstanceStatus, error) { return nil, sentinel })
	if err := command.Execute(); !errors.Is(err, sentinel) {
		t.Fatalf("lost status failure: %v", err)
	}
}
