// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"slices"

	"github.com/daeuniverse/dae/client/cli"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/spf13/cobra"
)

func newPluginsCommand(definitions map[string]plugin.Definition, services plugin.CommandServices) *cobra.Command {
	command := &cobra.Command{Use: "plugins", Short: "Manage plugins and inspect their reports."}
	addMITMCommands(command, definitions, services)
	return command
}

func addMITMCommands(command *cobra.Command, definitions map[string]plugin.Definition, services plugin.CommandServices) {
	var instance string
	aggregate := cli.NewMITMStatusCommand(cli.SelectMITM(services.Status, "", &instance), func(name string, fetch cli.MITMSource) (*cobra.Command, bool) {
		local := services
		local.Status = fetch
		return newMITMPluginCommand(name, definitions[name], local)
	})
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
	return cli.NewMITMPluginCommand(name, services.Status, func(fetch cli.MITMSource) []*cobra.Command {
		if definition.Commands == nil {
			return nil
		}
		services.Status = fetch
		return definition.Commands(services)
	})
}
