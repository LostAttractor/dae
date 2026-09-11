// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"encoding/json/v2"
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/api"
	"github.com/jedib0t/go-pretty/v6/table"
)

func RenderSurge(status api.SurgeStatus, showWarnings bool) string {
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
	sections := []string{"Surge modules:\n" + renderLogTable(table.Row{
		"INSTANCE", "MODULE", "STATE", "SCRIPTS", "HOSTS", "IP MAPS", "URL", "HEADER", "BODY", "LOCAL", "RULES", "WARNINGS",
	}, rows)}
	if len(errors) > 0 {
		sections = append(sections, "Errors:\n"+strings.Join(errors, "\n"))
	}
	if len(warnings) > 0 {
		sections = append(sections, "Warnings:\n"+strings.Join(warnings, "\n"))
	}
	return strings.Join(sections, "\n\n")
}

// Surge combines the plugin reports carried by a status snapshot.
func Surge(instances []api.PluginInstanceStatus) (api.SurgeStatus, error) {
	var status api.SurgeStatus
	for _, instance := range instances {
		if instance.Type != "surge" {
			continue
		}
		var detail *api.SurgeStatus
		if err := json.Unmarshal(instance.Details, &detail); err != nil {
			return status, fmt.Errorf("plugins.%s: invalid Surge status: %w", instance.ID, err)
		}
		if detail == nil {
			return status, fmt.Errorf("plugins.%s: missing Surge status", instance.ID)
		}
		status.Enabled = status.Enabled || detail.Enabled
		for _, module := range detail.Modules {
			module.Instance = instance.ID
			status.Modules = append(status.Modules, module)
		}
	}
	return status, nil
}
