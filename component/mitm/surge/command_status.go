// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/daeuniverse/dae/pkg/clitable"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func newSurgeStatusCommand(services plugin.CommandServices) *cobra.Command {
	return &cobra.Command{
		Use: "status", Short: "Show loaded Surge modules in the running daemon.",
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			instances, err := services.Status(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to get Surge status: %w", err)
			}
			status, err := surgeStatus(instances)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), renderSurgeStatus(status, true))
			return err
		},
	}
}

func renderSurgeStatus(status Status, showWarnings bool) string {
	if !status.Enabled {
		return "Surge modules: disabled"
	}
	if len(status.Modules) == 0 {
		return "Surge modules: no modules configured"
	}
	rows := make([]table.Row, 0, len(status.Modules))
	var errors, warnings []string
	for _, module := range status.Modules {
		rows = append(rows, table.Row{
			module.Instance, module.Name, module.State, module.Scripts, module.Hostnames, module.HostMappings,
			module.URLRewrites, module.HeaderRewrites, module.BodyRewrites,
			module.MapLocals, module.Rules, len(module.Warnings),
		})
		identity := module.Name
		if module.Instance != "" {
			identity = module.Instance + "/" + identity
		}
		if module.Error != "" {
			errors = append(errors, identity+": "+module.Error)
		}
		if showWarnings {
			for _, warning := range module.Warnings {
				warnings = append(warnings, identity+": "+warning)
			}
		}
	}
	writer := clitable.New()
	writer.AppendHeader(table.Row{
		"INSTANCE", "MODULE", "STATE", "SCRIPTS", "HOSTS", "IP MAPS", "URL", "HEADER", "BODY", "LOCAL", "RULES", "WARNINGS",
	})
	writer.AppendRows(rows)
	sections := []string{"Surge modules:\n" + text.StripEscape(writer.Render())}
	if len(errors) > 0 {
		sections = append(sections, "Errors:\n"+strings.Join(errors, "\n"))
	}
	if len(warnings) > 0 {
		sections = append(sections, "Warnings:\n"+strings.Join(warnings, "\n"))
	}
	return strings.Join(sections, "\n\n")
}

func logModuleStatus(status Status, logger *log.Entry, instanceID string) {
	if !logger.Logger.IsLevelEnabled(log.InfoLevel) {
		return
	}
	for i := range status.Modules {
		status.Modules[i].Instance = instanceID
	}
	// Module warnings were already emitted while loading.
	for _, line := range strings.Split(renderSurgeStatus(status, false), "\n") {
		logger.Info(line)
	}
}

func surgeStatus(instances []plugin.InstanceStatus) (Status, error) {
	var status Status
	for _, instance := range instances {
		if instance.Type != "surge" {
			continue
		}
		var detail Status
		if len(instance.Details) == 0 || string(instance.Details) == "null" {
			return status, fmt.Errorf("mitm.%s: missing Surge status", instance.ID)
		}
		if err := json.Unmarshal(instance.Details, &detail); err != nil {
			return status, fmt.Errorf("mitm.%s: invalid Surge status: %w", instance.ID, err)
		}
		status.Enabled = status.Enabled || detail.Enabled
		for _, module := range detail.Modules {
			module.Instance = instance.ID
			status.Modules = append(status.Modules, module)
		}
	}
	return status, nil
}
