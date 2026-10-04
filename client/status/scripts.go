// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"github.com/daeuniverse/dae/api"
	"github.com/jedib0t/go-pretty/v6/table"
)

// SurgeScriptTask associates one daemon task with its unambiguous CLI selectors.
// The embedded name is the script argument accepted by run.
type SurgeScriptTask struct {
	Instance string `json:"instance"`
	Module   string `json:"module"`
	api.ScriptTaskStatus
}

func RenderSurgeScriptTasks(tasks []SurgeScriptTask) string {
	if len(tasks) == 0 {
		return "No configured Surge script tasks match this selection."
	}
	rows := make([]table.Row, 0, len(tasks))
	for _, task := range tasks {
		rows = append(rows, table.Row{task.Instance, task.Module, task.Name, task.Type, task.State, task.CronExp})
	}
	return "Surge scripts supporting manual execution:\n" + renderLogTable(
		table.Row{"INSTANCE", "MODULE", "SCRIPT", "TYPE", "STATE", "EXPRESSION"}, rows)
}
