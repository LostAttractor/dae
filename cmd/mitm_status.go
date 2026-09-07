// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	apiclient "github.com/daeuniverse/dae/api/client"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/daeuniverse/dae/pkg/clitable"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func fetchMITMStatus(ctx context.Context) ([]plugin.InstanceStatus, error) {
	client, err := apiclient.New(apiclient.Options{Endpoint: os.Getenv("DAE_API_ENDPOINT"), Token: os.Getenv("DAE_API_TOKEN")})
	if err != nil {
		return nil, err
	}
	defer client.Close()
	snapshot, err := client.Status(ctx)
	if err != nil {
		return nil, err
	}
	return snapshot.MITMPlugins, nil
}

func selectMITMStatus(fetch func(context.Context) ([]plugin.InstanceStatus, error), kind string, instance *string) func(context.Context) ([]plugin.InstanceStatus, error) {
	return func(ctx context.Context) ([]plugin.InstanceStatus, error) {
		statuses, err := fetch(ctx)
		if err != nil {
			return nil, err
		}
		selected := make([]plugin.InstanceStatus, 0)
		for _, status := range statuses {
			if (kind == "" || status.Type == kind) && (*instance == "" || status.ID == *instance) {
				selected = append(selected, status)
			}
		}
		if *instance != "" && len(selected) == 0 {
			return nil, fmt.Errorf("MITM instance %q is not active for this command", *instance)
		}
		return selected, nil
	}
}

func addMITMCommands(command *cobra.Command, definitions map[string]plugin.Definition, services plugin.CommandServices) {
	var instance string
	local := services
	local.Status = selectMITMStatus(services.Status, "", &instance)
	aggregate := newMITMStatusCommand(local, definitions)
	aggregate.Flags().StringVar(&instance, "instance", "", "Show only this instance")
	command.AddCommand(aggregate)
	names := make([]string, 0, len(definitions))
	for name := range definitions {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		group, _ := newMITMPluginCommand(name, definitions[name], services)
		command.AddCommand(group)
	}
}

func newMITMPluginCommand(name string, definition plugin.Definition, services plugin.CommandServices) (*cobra.Command, bool) {
	group := &cobra.Command{Use: name, Short: "Manage " + name + " MITM plugins."}
	var id string
	group.PersistentFlags().StringVar(&id, "instance", "", "Query only this plugin instance")
	services.Status = selectMITMStatus(services.Status, name, &id)
	if definition.Commands != nil {
		group.AddCommand(definition.Commands(services)...)
	}
	for _, child := range group.Commands() {
		if child.Name() == "status" {
			return group, child.Runnable()
		}
	}
	group.AddCommand(newMITMStatusCommand(services, nil))
	return group, false
}

func newMITMStatusCommand(services plugin.CommandServices, definitions map[string]plugin.Definition) *cobra.Command {
	var asJSON, verbose bool
	command := &cobra.Command{
		Use: "status", Short: "Show MITM instances and their plugin reports.", Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			statuses, err := services.Status(cmd.Context())
			if err != nil {
				return err
			}
			if asJSON {
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				return encoder.Encode(statuses)
			}
			if len(statuses) == 0 {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "MITM: no active plugin instances")
				return err
			}
			if memory := statuses[0].BufferMemory; memory != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Body buffers (process): %.2f / %.2f MiB; peak=%.2f MiB; denied=%d\n\n",
					float64(memory.Used)/(1<<20), float64(memory.Limit)/(1<<20), float64(memory.Peak)/(1<<20), memory.Denied)
			}
			rows := make([]table.Row, 0, len(statuses))
			for _, status := range statuses {
				rows = append(rows, table.Row{status.ID, status.Type, status.State, status.Scopes, status.DestinationRules})
			}
			writer := clitable.New()
			writer.AppendHeader(table.Row{"INSTANCE", "TYPE", "STATE", "SCOPES", "DNAT"})
			writer.AppendRows(rows)
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), text.StripEscape(writer.Render())); err != nil {
				return err
			}
			if verbose {
				return renderMITMReports(cmd, definitions, services, statuses)
			}
			for _, status := range statuses {
				if len(status.Details) != 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "\n%s: %s\n", status.ID, mitmReportSummary(status.Details))
				}
			}
			return nil
		},
	}
	command.Flags().BoolVar(&asJSON, "json", false, "Print full reports as JSON")
	command.Flags().BoolVarP(&verbose, "verbose", "v", false, "Include each plugin's full status output")
	return command
}

// Use fresh commands and one daemon snapshot, preserving each plugin's command
// lifecycle without sharing flags or invoking runtime Setup.
func renderMITMReports(cmd *cobra.Command, definitions map[string]plugin.Definition, services plugin.CommandServices, statuses []plugin.InstanceStatus) error {
	byType := make(map[string][]plugin.InstanceStatus)
	for _, status := range statuses {
		byType[status.Type] = append(byType[status.Type], status)
	}
	names := make([]string, 0, len(byType))
	for name := range byType {
		names = append(names, name)
	}
	slices.Sort(names)
	var failures error
	for _, name := range names {
		if err := cmd.Context().Err(); err != nil {
			return errors.Join(failures, err)
		}
		instances := byType[name]
		local := services
		local.Status = func(ctx context.Context) ([]plugin.InstanceStatus, error) {
			return instances, ctx.Err()
		}
		group, custom := newMITMPluginCommand(name, definitions[name], local)
		var output bytes.Buffer
		var err error
		if custom {
			group.SilenceErrors, group.SilenceUsage = true, true
			group.SetIn(cmd.InOrStdin())
			group.SetOut(&output)
			group.SetErr(&output)
			args := []string{"status"}
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
			encoder := json.NewEncoder(&output)
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

// Keep the overview compact; --verbose and --json include full plugin reports.
func mitmReportSummary(raw json.RawMessage) string {
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		return ""
	}
	parts := make([]string, 0, len(fields))
	for name, value := range fields {
		switch value.(type) {
		case bool, float64, string:
			parts = append(parts, fmt.Sprintf("%s=%v", name, value))
		}
	}
	slices.Sort(parts)
	return strings.Join(parts, " ")
}

func logStartupMITMStatus(instances []plugin.InstanceStatus) {
	for _, instance := range instances {
		log.WithFields(log.Fields{"mitm_instance": instance.ID, "type": instance.Type,
			"state": instance.State, "scopes": instance.Scopes, "destination_rules": instance.DestinationRules,
		}).Debug("MITM plugin prepared")
	}
}
