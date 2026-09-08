// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"slices"

	"github.com/daeuniverse/dae/client/cli"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

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
	group := &cobra.Command{Use: name, Short: "Manage " + name + " MITM plugins."}
	var id string
	group.PersistentFlags().StringVar(&id, "instance", "", "Query only this plugin instance")
	services.Status = cli.SelectMITM(services.Status, name, &id)
	if definition.Commands != nil {
		group.AddCommand(definition.Commands(services)...)
	}
	for _, child := range group.Commands() {
		if child.Name() == "status" {
			return group, child.Runnable()
		}
	}
	group.AddCommand(cli.NewMITMStatusCommand(services.Status, nil))
	return group, false
}

func logStartupMITMStatus(instances []plugin.InstanceStatus) {
	for _, instance := range instances {
		log.WithFields(log.Fields{"mitm_instance": instance.ID, "type": instance.Type,
			"state": instance.State, "scopes": instance.Scopes, "destination_rules": instance.DestinationRules,
		}).Debug("MITM plugin prepared")
	}
}
