// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"encoding/json/v2"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/daeuniverse/dae/api"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

func RenderSurge(status api.SurgeStatus, verbose bool) string {
	if !status.Enabled {
		return "Surge modules: disabled"
	}
	if len(status.Modules) == 0 && len(status.Notifications) == 0 {
		return strings.TrimSpace("Surge modules: no modules configured\n\n" + renderSurgeRuntimes(status.Runtimes))
	}
	rows := make([]table.Row, 0, len(status.Modules))
	var taskRows, runRows []table.Row
	var errors, warnings []string
	for _, module := range status.Modules {
		rows = append(rows, table.Row{
			module.Instance, module.Name, module.State, module.Scripts, len(module.Tasks), module.Hostnames, module.HostMappings,
			module.URLRewrites, module.HeaderRewrites, module.BodyRewrites,
			module.MapLocals, module.Rules, len(module.Warnings),
		})
		for _, job := range module.Tasks {
			taskRows = append(taskRows, table.Row{module.Instance, module.Name, job.Name, job.Type, job.CronExp,
				job.Timezone, fmt.Sprintf("%gs", job.TimeoutSeconds), job.State, surgeTimestamp(job.NextRun)})
			result := job.LastResult
			if result == "" {
				result = "-"
			}
			if job.LastError != "" {
				result += "/" + job.LastError
			}
			runRows = append(runRows, table.Row{module.Instance, module.Name, job.Name, job.Type,
				surgeTimestamp(job.LastStartedAt), surgeTimestamp(job.LastFinishedAt),
				fmt.Sprintf("%dms", job.LastDurationMS), job.LastTrigger, result, job.Runs, job.Failures, job.Skipped})
		}
		identity := module.Name
		if module.Instance != "" {
			identity = module.Instance + "/" + identity
		}
		if module.Error != "" {
			errors = append(errors, identity+": "+module.Error)
		}
		for _, warning := range module.Warnings {
			warnings = append(warnings, identity+": "+warning)
		}
	}
	sections := []string{"Surge modules:\n" + renderLogTable(table.Row{
		"INSTANCE", "MODULE", "STATE", "SCRIPTS", "TASKS", "HOSTS", "IP MAPS", "URL", "HEADER", "BODY", "LOCAL", "RULES", "WARNINGS",
	}, rows)}
	if len(taskRows) > 0 {
		sections = append(sections, "Surge script tasks:\n"+renderLogTable(table.Row{
			"INSTANCE", "MODULE", "SCRIPT", "TYPE", "EXPRESSION", "TIMEZONE", "TIMEOUT", "STATE", "NEXT RUN",
		}, taskRows), "Last script runs:\n"+renderLogTable(table.Row{
			"INSTANCE", "MODULE", "SCRIPT", "TYPE", "STARTED", "FINISHED", "DURATION", "TRIGGER", "RESULT", "RUNS", "FAILED", "SKIPPED",
		}, runRows))
	}
	if len(errors) > 0 {
		sections = append(sections, "Errors:\n"+strings.Join(errors, "\n"))
	}
	if len(warnings) > 0 {
		sections = append(sections, "Warnings:\n"+strings.Join(warnings, "\n"))
	}
	if len(status.Notifications) > 0 {
		sections = append(sections, renderSurgeNotifications(status.Notifications, verbose))
	}
	if runtime := renderSurgeRuntimes(status.Runtimes); runtime != "" {
		sections = append(sections, runtime)
	}
	return strings.Join(sections, "\n\n")
}

func surgeTimestamp(timestamp time.Time) string {
	if timestamp.IsZero() {
		return "-"
	}
	return timestamp.Format(time.RFC3339)
}

const displayedNotificationsPerScript = 3

func renderSurgeNotifications(notifications []api.SurgeNotification, verbose bool) string {
	var output strings.Builder
	output.WriteString("Recent Surge notifications:")
	counts := make(map[[4]string]int)
	hidden := 0
	for _, notification := range notifications {
		if !verbose {
			key := [4]string{notification.Instance, notification.Module, notification.Script, notification.ScriptType}
			if counts[key] >= displayedNotificationsPerScript {
				hidden++
				continue
			}
			counts[key]++
		}
		identity := notification.Script
		if notification.Module != "" {
			identity = notification.Module + "/" + identity
		}
		if notification.Instance != "" {
			identity = notification.Instance + "/" + identity
		}
		fmt.Fprintf(&output, "\n%s  %s (#%d, %s)", surgeTimestamp(notification.CreatedAt),
			strings.ReplaceAll(notificationDisplayText(identity), "\n", " "), notification.ID,
			strings.ReplaceAll(notificationDisplayText(notification.ScriptType), "\n", " "))
		if notification.Truncated {
			output.WriteString(" [truncated]")
		}
		for _, field := range []struct{ label, value string }{
			{"Title", notification.Title}, {"Subtitle", notification.Subtitle}, {"Body", notification.Body},
		} {
			if field.value != "" {
				fmt.Fprintf(&output, "\n  %s: %s", field.label, strings.ReplaceAll(notificationDisplayText(field.value), "\n", "\n    "))
			}
		}
	}
	if hidden > 0 {
		fmt.Fprintf(&output, "\nShowing the latest %d per script; %d older notifications hidden. Use --verbose to show all retained notifications.", displayedNotificationsPerScript, hidden)
	}
	return output.String()
}

// Keep notification line breaks while preventing script text from controlling
// the terminal. JSON reports retain the original text.
func notificationDisplayText(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' {
			return -1
		}
		return r
	}, text.StripEscape(value))
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
		for _, runtime := range detail.Runtimes {
			runtime.Instance = instance.ID
			status.Runtimes = append(status.Runtimes, runtime)
		}
		for _, module := range detail.Modules {
			module.Instance = instance.ID
			status.Modules = append(status.Modules, module)
		}
		for _, notification := range detail.Notifications {
			notification.Instance = instance.ID
			status.Notifications = append(status.Notifications, notification)
		}
	}
	slices.SortStableFunc(status.Notifications, func(a, b api.SurgeNotification) int {
		return b.CreatedAt.Compare(a.CreatedAt)
	})
	return status, nil
}
