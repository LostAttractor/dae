// SPDX-License-Identifier: AGPL-3.0-only
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/client/cli"
	"github.com/daeuniverse/dae/component/mitm/surge"
	"github.com/daeuniverse/dae/component/plugin"
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
			Configure: func(plugin.Spec) (plugin.Factory, error) {
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
	command := newPluginsCommand(definitions, services)
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
	for _, path := range [][]string{{"status"}, {"demo", "status"}, {"custom", "status"}, {"surge", "status"}, {"surge", "configure"}} {
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
		command := newPluginsCommand(map[string]plugin.Definition{"demo": {}}, plugin.CommandServices{Status: func(context.Context) ([]plugin.InstanceStatus, error) {
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
	command := cli.NewMITMStatusCommand(func(context.Context) ([]plugin.InstanceStatus, error) { return nil, sentinel }, nil)
	if err := command.Execute(); !errors.Is(err, sentinel) {
		t.Fatalf("lost status failure: %v", err)
	}
}

func TestMITMVerboseStatusUsesOneSnapshotAndPluginCommands(t *testing.T) {
	statuses := []plugin.InstanceStatus{
		{ID: "personal", Type: "custom", State: "active"},
		{ID: "work", Type: "custom", State: "active"},
		{ID: "modules", Type: "surge", State: "active", Details: json.RawMessage(`{"enabled":true,"modules":[{"name":"bilihelper","state":"loaded","warnings":["unsupported rule"]}],"notifications":[{"module":"bilihelper","script":"job","title":"notice-4"},{"module":"bilihelper","script":"job","title":"notice-3"},{"module":"bilihelper","script":"job","title":"notice-2"},{"module":"bilihelper","script":"job","title":"oldest-notice"}]}`)},
		{ID: "fallback", Type: "raw", State: "active", Details: json.RawMessage(`{"jobs":[{"phase":"nested detail"}]}`)},
		{ID: "remote", Type: "uncompiled", State: "active", Details: json.RawMessage(`{"result":{"message":"unknown plugin detail"}}`)},
	}
	for _, test := range []struct {
		name, instance string
		args           []string
		renders        int
		want, absent   []string
		json           bool
	}{
		{name: "overview", args: []string{"status"}, absent: []string{"model=k3", "Surge modules:", "nested detail"}},
		{name: "verbose", args: []string{"status", "--verbose"}, renders: 1, want: []string{"INSTANCE", "Custom personal: model=k3", "Custom work: model=k3", "Surge modules:", "modules/bilihelper: unsupported rule", "nested detail", "unknown plugin detail", "oldest-notice"}, absent: []string{"older notifications hidden"}},
		{name: "Surge default", args: []string{"surge", "status"}, want: []string{"notice-4", "1 older notifications hidden"}, absent: []string{"oldest-notice"}},
		{name: "Surge verbose", args: []string{"surge", "status", "-v"}, want: []string{"notice-4", "oldest-notice"}, absent: []string{"older notifications hidden"}},
		{name: "instance", instance: "work", args: []string{"status", "-v", "--instance", "work"}, renders: 1, want: []string{"Custom work: model=k3"}, absent: []string{"personal", "bilihelper", "nested detail", "unknown plugin detail"}},
		{name: "generic plugin", args: []string{"raw", "status", "-v"}, want: []string{"nested detail"}, absent: []string{"personal", "bilihelper", "unknown plugin detail"}},
		{name: "json takes precedence", args: []string{"status", "--json", "-v"}, json: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			queries, renders := 0, 0
			type contextKey struct{}
			ctx := context.WithValue(t.Context(), contextKey{}, "snapshot")
			definitions := map[string]plugin.Definition{
				"surge": surge.Plugin,
				"raw": {Commands: func(plugin.CommandServices) []*cobra.Command {
					return []*cobra.Command{{Use: "inspect", Run: func(*cobra.Command, []string) { t.Fatal("ran a non-status command") }}}
				}},
				"custom": {
					Configure: func(plugin.Spec) (plugin.Factory, error) {
						t.Fatal("status initialized a runtime plugin")
						return nil, nil
					},
					Commands: func(services plugin.CommandServices) []*cobra.Command {
						prepared := false
						return []*cobra.Command{{Use: "status", Args: cobra.NoArgs,
							PreRun: func(*cobra.Command, []string) { prepared = true },
							RunE: func(cmd *cobra.Command, _ []string) error {
								renders++
								instance, _ := cmd.Flags().GetString("instance")
								if !prepared || cmd.Context().Value(contextKey{}) != "snapshot" || instance != test.instance || services.BaseDir != "/unused/cache" {
									t.Fatal("lost command lifecycle, context, selection or services")
								}
								instances, err := services.Status(cmd.Context())
								if err != nil {
									return err
								}
								// Even a renderer that reads twice must see the same snapshot.
								if _, err := services.Status(cmd.Context()); err != nil {
									return err
								}
								for _, instance := range instances {
									if instance.Type != "custom" {
										t.Fatal("plugin received another type's report")
									}
									fmt.Fprintf(cmd.OutOrStdout(), "Custom %s: model=k3\n", instance.ID)
								}
								return nil
							}}}
					},
				},
			}
			command := newPluginsCommand(definitions, plugin.CommandServices{BaseDir: "/unused/cache", Status: func(ctx context.Context) ([]plugin.InstanceStatus, error) {
				queries++
				return statuses, nil
			}})
			var output bytes.Buffer
			command.SetOut(&output)
			command.SetErr(&output)
			command.SetArgs(test.args)
			if err := command.ExecuteContext(ctx); err != nil {
				t.Fatal(err)
			}
			if queries != 1 || renders != test.renders {
				t.Fatalf("queries=%d renders=%d, want 1/%d", queries, renders, test.renders)
			}
			for _, want := range test.want {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("missing %q:\n%s", want, output.String())
				}
			}
			for _, absent := range test.absent {
				if strings.Contains(output.String(), absent) {
					t.Fatalf("unexpected %q:\n%s", absent, output.String())
				}
			}
			if test.json {
				var got []plugin.InstanceStatus
				if json.Unmarshal(output.Bytes(), &got) != nil || len(got) != len(statuses) {
					t.Fatalf("verbose altered JSON output: %s", output.String())
				}
			}
		})
	}
}

func TestMITMVerboseStatusKeepsReportsAfterRendererFailure(t *testing.T) {
	command := newPluginsCommand(map[string]plugin.Definition{"surge": surge.Plugin}, plugin.CommandServices{Status: func(context.Context) ([]plugin.InstanceStatus, error) {
		return []plugin.InstanceStatus{
			{ID: "broken", Type: "surge", Details: json.RawMessage(`{"enabled":"invalid"}`)},
			{ID: "healthy", Type: "surge", Details: json.RawMessage(`{"enabled":true,"modules":[{"name":"kept-module"}]}`)},
			{ID: "later", Type: "zeta", Details: json.RawMessage(`{"nested":{"message":"still shown"}}`)},
		}, nil
	}})
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"status", "-v"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "plugins.broken: invalid Surge status") {
		t.Fatalf("lost renderer failure: %v", err)
	}
	for _, want := range []string{`"enabled": "invalid"`, "kept-module", "still shown"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("renderer failure hid %q:\n%s", want, output.String())
		}
	}
}
