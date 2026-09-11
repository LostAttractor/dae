// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"encoding/json/v2"
	"fmt"
	"slices"
	"strings"

	"github.com/daeuniverse/dae/api"
	"github.com/jedib0t/go-pretty/v6/table"
)

func RenderMITM(instances []api.PluginInstanceStatus, withSummary bool) string {
	if len(instances) == 0 {
		return "MITM: no active plugin instances"
	}
	var memorySummary string
	if memory := instances[0].BufferMemory; memory != nil {
		memorySummary = fmt.Sprintf("Body buffers (process): %.2f / %.2f MiB; peak=%.2f MiB; denied=%d\n\n",
			float64(memory.Used)/(1<<20), float64(memory.Limit)/(1<<20), float64(memory.Peak)/(1<<20), memory.Denied)
	}
	rows := make([]table.Row, 0, len(instances))
	var details strings.Builder
	for _, instance := range instances {
		rows = append(rows, table.Row{instance.ID, instance.Type, instance.State, instance.Scopes, instance.DestinationRules})
		if withSummary {
			if summary := mitmReportSummary(instance.Details); summary != "" {
				fmt.Fprintf(&details, "\n\n%s: %s", instance.ID, summary)
			}
		}
	}
	return memorySummary + renderLogTable(table.Row{"INSTANCE", "TYPE", "STATE", "SCOPES", "DNAT"}, rows) + details.String()
}

// Nested reports stay available through --verbose, --json or the plugin's status command.
func mitmReportSummary(raw []byte) string {
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
