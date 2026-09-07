// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"encoding/json"
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
	var details strings.Builder
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
			fmt.Fprintf(&details, "\n%s: %s", identity, module.Error)
		}
		if showWarnings {
			for _, warning := range module.Warnings {
				fmt.Fprintf(&details, "\n%s: warning: %s", identity, warning)
			}
		}
	}
	return "Surge modules:\n" + renderLogTable(table.Row{
		"INSTANCE", "MODULE", "STATE", "SCRIPTS", "HOSTS", "IP MAPS", "URL", "HEADER", "BODY", "LOCAL", "RULES", "WARNINGS",
	}, rows) + details.String()
}

// Surge combines the plugin reports carried by a schema-7 status snapshot.
func Surge(instances []api.MITMInstanceStatus) (api.SurgeStatus, error) {
	var status api.SurgeStatus
	for _, instance := range instances {
		if instance.Type != "surge" {
			continue
		}
		var detail *api.SurgeStatus
		if err := json.Unmarshal(instance.Details, &detail); err != nil {
			return status, fmt.Errorf("mitm.%s: invalid Surge status: %w", instance.ID, err)
		}
		if detail == nil {
			return status, fmt.Errorf("mitm.%s: missing Surge status", instance.ID)
		}
		status.Enabled = status.Enabled || detail.Enabled
		for _, module := range detail.Modules {
			module.Instance = instance.ID
			status.Modules = append(status.Modules, module)
		}
	}
	return status, nil
}
