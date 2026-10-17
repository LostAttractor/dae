// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"context"
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/client/status"
	"github.com/spf13/cobra"
)

type MITMSource func(context.Context) (api.PluginStatus, error)

// MITMCommandFactory builds a fresh plugin command group from a scoped snapshot.
// The bool reports whether the group has a runnable custom status command.
// Command registration stays with the caller; no runtime plugin is prepared.
type MITMCommandFactory func(kind string, fetch MITMSource) (*cobra.Command, bool)

// SelectMITM scopes both built-in status commands and plugin-provided commands.
// The instance flag is read at execution time, after Cobra parses arguments.
func SelectMITM(fetch MITMSource, kind string, instance *string) MITMSource {
	return func(ctx context.Context) (api.PluginStatus, error) {
		instances, err := fetch(ctx)
		if err != nil {
			return api.PluginStatus{}, err
		}
		selected := make([]api.PluginInstanceStatus, 0)
		for _, value := range instances.Plugins {
			if (kind == "" || value.Type == kind) && (*instance == "" || value.ID == *instance) {
				selected = append(selected, value)
			}
		}
		if *instance != "" && len(selected) == 0 {
			return api.PluginStatus{}, fmt.Errorf("plugin instance %q is not active for this command", *instance)
		}
		instances.Plugins = selected
		return instances, nil
	}
}

// ScriptTrigger invokes the host's optional task execution capability.
type ScriptTrigger func(context.Context, string, api.ScriptRunRequest) (*api.ScriptRunResponse, error)

// MITMCommands registers a plugin's client commands without runtime resources.
type MITMCommands func(MITMSource, ScriptTrigger) []*cobra.Command

// NewMITMCommand exposes opaque reports and explicitly registered client commands.
func NewMITMCommand(commands map[string]MITMCommands) *cobra.Command {
	command := &cobra.Command{Use: "plugins", Short: "Inspect plugin reports through the dae API."}
	var connection Connection
	connection.Bind(command.PersistentFlags())
	var instance string
	command.PersistentFlags().StringVar(&instance, "instance", "", "Query only this plugin instance")
	factory := func(kind string, fetch MITMSource) (*cobra.Command, bool) {
		var register func(MITMSource) []*cobra.Command
		if create := commands[kind]; create != nil {
			register = func(scoped MITMSource) []*cobra.Command { return create(scoped, connection.TriggerScript) }
		}
		return NewMITMPluginCommand(kind, fetch, register)
	}
	command.AddCommand(NewMITMStatusCommand(SelectMITM(connection.MITM, "", &instance), factory))
	for _, kind := range slices.Sorted(maps.Keys(commands)) {
		group, _ := factory(kind, connection.MITM)
		command.AddCommand(group)
	}
	return command
}

// NewMITMPluginCommand scopes a fresh command group and supplies a generic
// status command when the plugin has no custom renderer.
func NewMITMPluginCommand(name string, fetch MITMSource, commands func(MITMSource) []*cobra.Command) (*cobra.Command, bool) {
	group := &cobra.Command{Use: name, Short: "Manage " + name + " plugins."}
	var id string
	group.PersistentFlags().StringVar(&id, "instance", "", "Query only this plugin instance")
	scoped := SelectMITM(fetch, name, &id)
	if commands != nil {
		group.AddCommand(commands(scoped)...)
	}
	for _, child := range group.Commands() {
		if child.Name() == "status" {
			return group, child.Runnable()
		}
	}
	group.AddCommand(NewMITMStatusCommand(scoped, nil))
	return group, false
}

func NewMITMStatusCommand(fetch MITMSource, commands MITMCommandFactory) *cobra.Command {
	var verbose bool
	command := NewReportCommand(fetch, func(cmd *cobra.Command, instances api.PluginStatus) error {
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), status.RenderMITM(instances, !verbose)); err != nil {
			return err
		}
		if verbose && len(instances.Plugins) > 0 {
			return renderMITMReports(cmd, commands, instances)
		}
		return nil
	})
	command.Flags().BoolVarP(&verbose, "verbose", "v", false, "Include each plugin's full status output")
	return command
}

// NewReportCommand preserves process statistics and opaque reports for JSON output.
func NewReportCommand(fetch MITMSource, render func(*cobra.Command, api.PluginStatus) error) *cobra.Command {
	var raw bool
	command := &cobra.Command{
		Use: "status", Short: "Show plugin instances and their reports.", Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			instances, err := WithProgress(cmd, "Fetching plugin status...", func() (api.PluginStatus, error) {
				return fetch(cmd.Context())
			})
			if err != nil {
				return err
			}
			if raw {
				return json.MarshalWrite(cmd.OutOrStdout(), instances)
			}
			return render(cmd, instances)
		},
	}
	command.Flags().BoolVar(&raw, "json", false, "Print full plugin reports as JSON")
	return command
}

// Use fresh commands and one daemon snapshot, preserving each plugin's command
// lifecycle without sharing flags or invoking runtime Setup.
func renderMITMReports(cmd *cobra.Command, commands MITMCommandFactory, statuses api.PluginStatus) error {
	byType := make(map[string][]api.PluginInstanceStatus)
	for _, status := range statuses.Plugins {
		byType[status.Type] = append(byType[status.Type], status)
	}
	var failures error
	for _, name := range slices.Sorted(maps.Keys(byType)) {
		if err := cmd.Context().Err(); err != nil {
			return errors.Join(failures, err)
		}
		instances := byType[name]
		var group *cobra.Command
		var custom bool
		if commands != nil {
			group, custom = commands(name, func(ctx context.Context) (api.PluginStatus, error) {
				return api.PluginStatus{Plugins: instances, BufferMemory: statuses.BufferMemory}, ctx.Err()
			})
		}
		var output bytes.Buffer
		var err error
		if custom {
			group.SilenceErrors, group.SilenceUsage = true, true
			group.SetIn(cmd.InOrStdin())
			group.SetOut(&output)
			group.SetErr(&output)
			args := []string{"status"}
			if statusCommand, _, err := group.Find(args); err == nil {
				if flag := statusCommand.Flags().Lookup("verbose"); flag != nil && flag.Value.Type() == "bool" {
					args = append(args, "--verbose")
				}
			}
			if instance, _ := cmd.Flags().GetString("instance"); instance != "" {
				args = append(args, "--instance", instance)
			}
			group.SetArgs(args)
			err = group.ExecuteContext(cmd.Context())
			if err != nil {
				failures = errors.Join(failures, fmt.Errorf("%s status: %w", name, err))
			}
		}
		if !custom || err != nil || output.Len() == 0 {
			// Keep unknown reports and reports rejected by an older renderer
			// visible, and continue displaying the other plugin types.
			if output.Len() > 0 {
				fmt.Fprintln(&output)
			}
			fmt.Fprintf(&output, "%s: full report\n", name)
			encoder := jsonv1.NewEncoder(&output)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(instances); err != nil {
				failures = errors.Join(failures, fmt.Errorf("%s report: %w", name, err))
			}
		}
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "\n%s\n", strings.TrimRight(output.String(), "\n")); err != nil {
			return errors.Join(failures, err)
		}
	}
	return failures
}
