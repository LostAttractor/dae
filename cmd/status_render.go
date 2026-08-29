/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/daeuniverse/dae/control"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

// newStatusTable uses one ANSI- and CJK-aware layout for all status output.
func newStatusTable() table.Writer {
	writer := table.NewWriter()
	style := table.StyleDefault
	style.Options.DrawBorder = false
	style.Options.SeparateHeader = false
	style.Options.SeparateColumns = false
	style.Box.PaddingLeft = ""
	style.Box.PaddingRight = "  "
	style.Format.Header = text.FormatDefault
	writer.SetStyle(style)
	return writer
}

func printRenderedTable(rendered string) {
	for _, line := range strings.Split(rendered, "\n") {
		fmt.Println(strings.TrimRight(line, " "))
	}
}

func printTable(header table.Row, rows []table.Row) {
	writer := newStatusTable()
	writer.AppendHeader(header)
	writer.AppendRows(rows)
	printRenderedTable(writer.Render())
}

func tableUsageRow(usage control.TableUsage) table.Row {
	ratio := 0.0
	if usage.Limit > 0 {
		ratio = float64(usage.Used) / float64(usage.Limit)
	}
	used := fmt.Sprintf("%d", usage.Used)
	breakdown := "-"
	limitGC := "-"
	if usage.Breakdown != nil {
		used += " (LAZY)"
		breakdown = fmt.Sprintf("%d/%d", usage.Breakdown.Live, usage.Breakdown.Retained)
		limitGC = fmt.Sprintf("%d", usage.Breakdown.LimitGC)
	}
	return table.Row{
		usage.Name,
		used,
		usage.Limit,
		colorUsage(ratio, formatRatio(ratio)),
		breakdown,
		limitGC,
	}
}

func nodeLabel(status control.NodeStatus, index int) string {
	if status.Name != "" {
		return status.Name
	}
	if status.Address != "" {
		return status.Address
	}
	return fmt.Sprintf("#%d", index)
}

func annotatedNodeLabel(status control.NodeStatus, index int) string {
	label := nodeLabel(status, index)
	if status.Annotation == nil && !status.CheckAsync {
		return label
	}
	parts := make([]string, 0, 3)
	if status.Annotation != nil {
		if status.Annotation.Priority != nil {
			priority := fmt.Sprintf("p=%d", *status.Annotation.Priority)
			if status.Annotation.PriorityConditional {
				priority += "*"
			}
			parts = append(parts, priority)
		}
		if status.Annotation.AddLatency != "" {
			latency := status.Annotation.AddLatency
			if !strings.HasPrefix(latency, "-") {
				latency = "+" + latency
			}
			parts = append(parts, latency)
		}
	}
	if status.CheckAsync {
		parts = append(parts, "async")
	}
	if len(parts) == 0 {
		return label
	}
	return label + " [" + strings.Join(parts, ",") + "]"
}

func networkStatusRow(status control.NetworkStatus, nodes []control.NodeStatus) table.Row {
	selected := "-"
	if status.Selected != nil {
		selected = nodeLabel(nodes[status.Selected.Index], status.Selected.Index)
	}
	return table.Row{
		status.Network,
		colorNetworkSupport(status.SupportState),
		colorSelected(selected, status.Selected != nil),
		formatConnCounts(status.ActiveConns, status.TotalConns),
	}
}

type verboseNodeHealthCells struct {
	state        string
	latency      string
	upRatio      string
	upRatio24h   string
	healthySince string
	failure      string
	lastCheck    string
}

func verboseNodeHealth(status control.NodeStatus) verboseNodeHealthCells {
	cells := verboseNodeHealthCells{
		state:        "-",
		latency:      nodeLatency(status),
		upRatio:      "-",
		upRatio24h:   "-",
		healthySince: "-",
		failure:      "-",
		lastCheck:    "-",
	}
	if status.Health != nil {
		cells.state = colorNodeHealth(status.Health.State)
		cells.upRatio = colorRatio(status.Health.UpRatio, formatAvailability(status.Health.UpRatio, status.Health.ChecksFailed, status.Health.ChecksTotal))
		cells.upRatio24h = colorRatio(status.Health.UpRatio24h, formatAvailability(status.Health.UpRatio24h, status.Health.ChecksFailed24h, status.Health.ChecksTotal24h))
		cells.healthySince = formatAgoWithChecks(status.Health.HealthySince, status.Health.ChecksSinceHealthy)
		cells.failure = formatFailure(status.Health.Failure)
		cells.lastCheck = formatAgo(status.Health.LastCheckAt)
	}
	return cells
}

func nodeStatusRow(status control.NodeStatus, index int, groupNetworks []control.NetworkStatus) table.Row {
	selectedNetworks, selected := selectedNetworks(index, groupNetworks)
	session := "-"
	if status.Session != nil {
		session = string(status.Session.State)
	}
	health := verboseNodeHealth(status)
	return table.Row{
		colorSelected(annotatedNodeLabel(status, index), selected),
		emptyDash(status.Subtag),
		emptyDash(status.Protocol),
		session,
		health.state,
		networkSupport(status.Networks),
		colorSelected(selectedNetworks, selected),
		health.latency,
		health.upRatio,
		health.upRatio24h,
		health.healthySince,
		health.failure,
		health.lastCheck,
		formatAgo(status.LastConnectionFailureAt),
		formatConnCounts(status.ActiveConns, status.TotalConns),
		formatTrafficRateCell(status.Traffic),
		formatTrafficTotalCell(status.Traffic),
	}
}

func nodeLatency(status control.NodeStatus) string {
	if status.Health == nil || status.Health.Latency == nil || status.Health.State != control.NodeHealthHealthy {
		return "-"
	}
	latency := status.Health.Latency
	formatted := fmt.Sprintf("%.0f/%.0f/%.0f", latency.LastMs, latency.Average10Ms, latency.MovingAverageMs)
	if latency.Average10Failed {
		return colorize(formatted, text.FgHiRed, text.Bold)
	}
	return colorLatency(latency.MovingAverageMs, formatted)
}

func compactNodeState(status control.NodeStatus) string {
	if status.Session != nil && status.Session.State != control.SessionConnected {
		if status.Health != nil && status.Health.State == control.NodeHealthUnhealthy {
			return colorize(string(status.Session.State), text.FgRed)
		}
		switch status.Session.State {
		case control.SessionConnecting:
			return colorize(string(status.Session.State), text.FgYellow)
		default:
			return colorize(string(status.Session.State), text.FgRed)
		}
	}
	if status.Health != nil {
		return colorNodeHealth(status.Health.State)
	}
	if status.Session != nil {
		return colorize(string(status.Session.State), text.FgGreen)
	}
	return "-"
}

func compactUpRatios(status control.NodeStatus) string {
	if status.Health == nil || status.Health.State == control.NodeHealthUnknown {
		return "-"
	}
	formatted := fmt.Sprintf("%.1f/%.1f%%", status.Health.UpRatio*100, status.Health.UpRatio24h*100)
	return colorRatio(min(status.Health.UpRatio, status.Health.UpRatio24h), formatted)
}

func recentFailureEpisode(health *control.NodeHealthStatus, now time.Time) bool {
	if health == nil || health.Failure == nil || health.Failure.StartedAt.After(now) {
		return false
	}
	if health.UpRatio24h < 1 {
		return true
	}
	cutoff := now.Add(-24 * time.Hour)
	duration := time.Duration(max(health.Failure.DurationMs, 0)) * time.Millisecond
	if duration == 0 {
		return !health.Failure.StartedAt.Before(cutoff)
	}
	return health.Failure.StartedAt.Add(duration).After(cutoff)
}

func recentNodeFailure(health *control.NodeHealthStatus, now time.Time) bool {
	return health != nil && (health.ChecksFailed24h > 0 || recentFailureEpisode(health, now))
}

func compactFailure(health *control.NodeHealthStatus, now time.Time) string {
	if !recentNodeFailure(health, now) {
		return "-"
	}
	if !recentFailureEpisode(health, now) {
		return colorize(fmt.Sprintf("%dchk", health.ChecksFailed24h), text.FgYellow)
	}
	age := now.Sub(health.Failure.StartedAt)
	duration := time.Duration(max(health.Failure.DurationMs, 0)) * time.Millisecond
	formatDuration := func(d time.Duration) string {
		if d <= 0 {
			return "0s"
		}
		return formatUptime(d)
	}
	formatted := formatDuration(age) + "/" + formatDuration(duration)
	if health.State == control.NodeHealthUnhealthy {
		return colorize(formatted, text.FgRed)
	}
	return colorize(formatted, text.FgYellow)
}

func hasRecentNodeFailure(nodes []control.NodeStatus, now time.Time) bool {
	for _, node := range nodes {
		if recentNodeFailure(node.Health, now) {
			return true
		}
	}
	return false
}

func compactNodeStatusRow(status control.NodeStatus, index int, groupNetworks []control.NetworkStatus) table.Row {
	selectedNetworks, selected := selectedNetworks(index, groupNetworks)
	return table.Row{
		colorSelected(annotatedNodeLabel(status, index), selected),
		emptyDash(status.Protocol),
		compactNodeState(status),
		networkSupport(status.Networks),
		colorSelected(selectedNetworks, selected),
		nodeLatency(status),
		compactUpRatios(status),
		formatConnCounts(status.ActiveConns, status.TotalConns),
		formatTrafficRateCell(status.Traffic),
		formatTrafficTotalCell(status.Traffic),
	}
}

func groupDisplayMetadata(group control.GroupStatus) (targetKind, policy string) {
	policy = group.Policy
	if policy == "" {
		policy = "single path"
	}
	targetKind = group.TargetKind
	if targetKind == "" {
		targetKind = "group"
	}
	return targetKind, policy
}

func uncheckedNetworkRows(networks []control.NetworkStatus) []table.Row {
	rows := make([]table.Row, 0, len(networks))
	for _, status := range networks {
		rows = append(rows, table.Row{
			status.Network,
			formatConnCounts(status.ActiveConns, status.TotalConns),
		})
	}
	return rows
}

func checkedNetworkRows(group control.GroupStatus) []table.Row {
	rows := make([]table.Row, 0, len(group.Networks))
	for _, status := range group.Networks {
		rows = append(rows, networkStatusRow(status, group.Nodes))
	}
	return rows
}

func nodeTable(group control.GroupStatus, verbose bool, now time.Time) (table.Row, []table.Row) {
	rows := make([]table.Row, 0, len(group.Nodes))
	if verbose {
		for index, status := range group.Nodes {
			rows = append(rows, nodeStatusRow(status, index, group.Networks))
		}
		return table.Row{
			"PATH", "SUB", "PROTO", "SESSION", "HEALTH", "SUPPORT", "SELECTED",
			"LATENCY last/avg10/mov(ms)", "UP% (FAIL/CHK)", "24H UP% (FAIL/CHK)", "HEALTHY-SINCE",
			"FAILURE (START/DURATION)", "LAST-CHECK", "LAST-CONN-FAIL", "CONNS(A/T)", "RATE U/D", "TOTAL U/D",
		}, rows
	}

	showFailure := hasRecentNodeFailure(group.Nodes, now)
	for index, status := range group.Nodes {
		row := compactNodeStatusRow(status, index, group.Networks)
		if showFailure {
			row = append(row, compactFailure(status.Health, now))
		}
		rows = append(rows, row)
	}
	header := table.Row{
		"PATH", "PROTO", "STATE", "NETS", "SELECT", "LAT L/A/M(ms)", "UP/24H", "CONNS", "RATE U/D", "TOTAL U/D",
	}
	if showFailure {
		header = append(header, "FAIL A/D")
	}
	return header, rows
}

func printGroupStatus(group control.GroupStatus) {
	targetKind, policy := groupDisplayMetadata(group)
	if group.Connectivity == nil {
		fmt.Printf(
			"\nGroup '%s' [kind: %s, policy: %s%s] (no connectivity checks)\n",
			group.Name, targetKind, policy, formatTrafficSummarySuffix(group.Traffic),
		)
		printTable(table.Row{"NETWORK", "CONNS(A/T)"}, uncheckedNetworkRows(group.Networks))
		return
	}
	upRatio := "-"
	if group.Connectivity.UpRatio != nil {
		ratio := *group.Connectivity.UpRatio
		upRatio = colorRatio(ratio, formatRatio(ratio))
	}

	fmt.Printf(
		"\nGroup '%s' [kind: %s, policy: %s, state: %s, up: %s, up since: %s, failure: %s%s]\n",
		group.Name,
		targetKind,
		policy,
		formatGroupConnectivityState(group.Connectivity),
		upRatio,
		formatAgo(group.Connectivity.UpSince),
		formatFailure(group.Connectivity.LastFailure),
		formatTrafficSummarySuffix(group.Traffic),
	)
	printTable(table.Row{
		"NETWORK", "SUPPORT", "SELECTED", "CONNS(A/T)",
	}, checkedNetworkRows(group))

	fmt.Printf("\nPaths of target '%s':\n", group.Name)
	header, rows := nodeTable(group, statusVerbose, time.Now())
	printTable(header, rows)
}

func statusSummary(s *control.StatusSnapshot) string {
	var degradedGroups, warningGroups []string
	for _, group := range s.Groups {
		switch group.Health {
		case control.HealthDegraded:
			degradedGroups = append(degradedGroups, group.Name)
		case control.HealthWarning:
			warningGroups = append(warningGroups, group.Name)
		}
	}

	var details []string
	if len(degradedGroups) > 0 {
		details = append(details, "degraded groups: "+strings.Join(degradedGroups, ", "))
	}
	if len(warningGroups) > 0 {
		details = append(details, "warning groups: "+strings.Join(warningGroups, ", "))
	}

	summary := colorHealth(s.Health)
	if len(details) > 0 {
		summary += " (" + strings.Join(details, "; ") + ")"
	}
	return summary
}

func printStatus(s *control.StatusSnapshot) {
	fmt.Printf(
		"Daemon:      %s up %s (since %s)",
		s.Version,
		formatUptime(time.Since(s.StartedAt)),
		s.StartedAt.Local().Format("2006-01-02 15:04:05"),
	)
	if s.LastReloadAt != nil {
		fmt.Printf(", last reload %s", formatAgo(s.LastReloadAt))
	}
	fmt.Println()
	fmt.Printf("Status:      %s\n", statusSummary(s))
	perNet := make([]string, len(s.Networks))
	for i, network := range s.Networks {
		perNet[i] = fmt.Sprintf("%s %d", network.Network, network.ActiveConns)
	}
	fmt.Printf("Connections: %d active (%s), %d total", s.ActiveConns, strings.Join(perNet, ", "), s.TotalConns)
	if traffic := formatTrafficSummary(s.Traffic); traffic != "" {
		fmt.Printf("; %s", traffic)
	}
	fmt.Println()

	if len(s.Tables) > 0 {
		fmt.Println("\nTables:")
		rows := make([]table.Row, 0, len(s.Tables))
		for _, usage := range s.Tables {
			rows = append(rows, tableUsageRow(usage))
		}
		printTable(table.Row{"TABLE", "USED", "LIMIT", "USAGE", "LIVE/RETAINED", "LIMIT-GC"}, rows)
	}

	for _, group := range s.Groups {
		printGroupStatus(group)
	}
}
