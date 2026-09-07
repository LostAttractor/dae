// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/jedib0t/go-pretty/v6/table"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func fetchMITMStatus(ctx context.Context) ([]plugin.InstanceStatus, error) {
	internal.AutoSu()
	snapshot, err := fetchStatusContext(ctx)
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
	aggregate := newMITMStatusCommand(selectMITMStatus(services.Status, "", &instance))
	aggregate.Flags().StringVar(&instance, "instance", "", "Show only this instance")
	command.AddCommand(aggregate)
	names := make([]string, 0, len(definitions))
	for name := range definitions {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		group := &cobra.Command{Use: name, Short: "Manage " + name + " MITM plugins."}
		var id string
		group.PersistentFlags().StringVar(&id, "instance", "", "Query only this plugin instance")
		local := services
		local.Status = selectMITMStatus(services.Status, name, &id)
		if factory := definitions[name].Commands; factory != nil {
			group.AddCommand(factory(local)...)
		}
		hasStatus := false
		for _, child := range group.Commands() {
			if child.Name() == "status" {
				hasStatus = true
			}
		}
		if !hasStatus {
			group.AddCommand(newMITMStatusCommand(local.Status))
		}
		command.AddCommand(group)
	}
}

func newMITMStatusCommand(fetch func(context.Context) ([]plugin.InstanceStatus, error)) *cobra.Command {
	var asJSON bool
	command := &cobra.Command{
		Use: "status", Short: "Show MITM instances and their plugin reports.", Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			statuses, err := fetch(cmd.Context())
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
			rows := make([]table.Row, 0, len(statuses))
			for _, status := range statuses {
				rows = append(rows, table.Row{status.ID, status.Type, status.State, status.Scopes, status.DestinationRules})
			}
			fmt.Fprintln(cmd.OutOrStdout(), renderLogTable(table.Row{"INSTANCE", "TYPE", "STATE", "SCOPES", "DNAT"}, rows))
			for _, status := range statuses {
				if len(status.Details) != 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "\n%s: %s\n", status.ID, mitmReportSummary(status.Details))
				}
			}
			return nil
		},
	}
	command.Flags().BoolVar(&asJSON, "json", false, "Print full reports as JSON")
	return command
}

// Keep the overview compact; full nested reports are available with --json or
// the plugin's own status command.
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
		}).Info("MITM plugin prepared")
	}
}
