/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/control"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

func truncateStatusCell(value string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}
	return text.Snip(value, maxWidth, "…")
}

func renderStatusTable(header table.Row, rows []table.Row, configs []table.ColumnConfig) string {
	writer := table.NewWriter()
	style := table.StyleDefault
	style.Options.DrawBorder = false
	style.Options.SeparateHeader = false
	style.Options.SeparateColumns = false
	style.Box.PaddingLeft = ""
	style.Box.PaddingRight = "  "
	style.Format.Header = text.FormatDefault
	writer.SetStyle(style)
	writer.SuppressTrailingSpaces()
	if terminalWidth := getStatusTerminalWidth(); terminalWidth > 0 {
		writer.Style().Size.WidthMax = terminalWidth
		writer.Style().Box.UnfinishedRow = ""
	}
	writer.SetColumnConfigs(configs)
	if len(header) > 0 {
		writer.AppendHeader(header)
	}
	writer.AppendRows(rows)
	return writer.Render()
}

func printTable(header table.Row, rows []table.Row) {
	fmt.Println(renderStatusTable(header, rows, nil))
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
	return table.Row{usage.Name, used, usage.Limit, colorUsage(ratio, formatRatio(ratio)), breakdown, limitGC}
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

func groupNetworkSupport(nodes []control.NodeStatus, network common.NetworkIndex) dialer.NetworkSupportState {
	support := dialer.NetworkSupportUnsupported
	for _, node := range nodes {
		switch node.Support[network] {
		case dialer.NetworkSupportConfirmed:
			return dialer.NetworkSupportConfirmed
		case dialer.NetworkSupportUnknown:
			support = dialer.NetworkSupportUnknown
		}
	}
	return support
}

func groupNetworkRoutable(group control.GroupStatus, network common.NetworkIndex) bool {
	if group.SelectedNodeIDs[network] != "" {
		return true
	}
	dynamicPolicy := group.Policy != "" && group.Policy != string(consts.DialerSelectionPolicy_Fixed)
	if !dynamicPolicy {
		return false
	}
	for _, node := range group.Nodes {
		if node.Healthy && node.Support[network] == dialer.NetworkSupportConfirmed {
			return true
		}
	}
	return false
}

func networkStatusRow(group control.GroupStatus, network common.NetworkIndex) table.Row {
	support := groupNetworkSupport(group.Nodes, network)
	route := colorNetworkSupport(support)
	selectedID := group.SelectedNodeIDs[network]
	for index, node := range group.Nodes {
		if selectedID != "" && node.ID == selectedID {
			route = colorSelected(nodeLabel(node, index), true)
			break
		}
	}
	if selectedID == "" && support == dialer.NetworkSupportConfirmed {
		if groupNetworkRoutable(group, network) {
			route = colorize("available", text.FgGreen)
		} else {
			route = colorize("down", text.FgRed)
		}
	}
	return table.Row{
		network.String(),
		route,
		formatConnCounts(group.Networks[network]),
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
	if status.ChecksConnectivity {
		availability := status.Availability
		cells.state = colorNodeHealth(nodeHealth(status))
		cells.upRatio = colorRatio(availability.UpRatio, formatAvailability(availability.UpRatio, availability.ChecksFailed, availability.ChecksTotal))
		cells.upRatio24h = colorRatio(availability.Recent24h.UpRatio, formatAvailability(availability.Recent24h.UpRatio, availability.Recent24h.ChecksFailed, availability.Recent24h.ChecksTotal))
		cells.healthySince = formatAgoWithChecks(availability.AliveSince, availability.ChecksSinceAlive)
		cells.failure = formatFailure(availability.LastFailureStartedAt, availability.LastFailureDuration)
		cells.lastCheck = formatAgo(availability.LastCheckAt)
	}
	return cells
}

func nodeStatusRow(status control.NodeStatus, index int, selected control.NetworkValues[string]) table.Row {
	networks, isSelected := nodeNetworks(status, selected)
	health := verboseNodeHealth(status)
	return table.Row{
		colorSelected(annotatedNodeLabel(status, index), isSelected),
		emptyDash(status.Subtag),
		emptyDash(status.Protocol),
		emptyDash(status.Session),
		health.state,
		networks,
		health.latency,
		health.upRatio,
		health.upRatio24h,
		health.failure,
		health.healthySince,
		health.lastCheck,
		formatAgo(status.Availability.LastConnFailAt),
		formatConnCounts(status.Stats),
		formatTrafficCell(status.Stats),
		formatTrafficTotalCell(status.Stats),
	}
}

func nodeLatency(status control.NodeStatus) string {
	if status.Latency == nil || nodeHealth(status) != nodeHealthHealthy {
		return "-"
	}
	latency := status.Latency
	last := latency.Last.Seconds() * 1000
	average := latency.Avg10.Seconds() * 1000
	moving := latency.MovingAvg.Seconds() * 1000
	formatted := fmt.Sprintf("%.0f/%.0f/%.0f", last, average, moving)
	if latency.Avg10HasFailure {
		return colorize(formatted, text.FgHiRed, text.Bold)
	}
	return colorLatency(moving, formatted)
}

func compactNodeState(status control.NodeStatus) string {
	health := nodeHealth(status)
	if status.Session != "" && status.Session != "connected" {
		if health == nodeHealthUnhealthy {
			return colorize(status.Session, text.FgRed)
		}
		if status.Session == "connecting" {
			return colorize(status.Session, text.FgYellow)
		}
		return colorize(status.Session, text.FgRed)
	}
	if status.ChecksConnectivity {
		return colorNodeHealth(health)
	}
	if status.Session != "" {
		return colorize(status.Session, text.FgGreen)
	}
	return "-"
}

func compactUpRatios(status control.NodeStatus) string {
	if nodeHealth(status) == nodeHealthUnknown {
		return "-"
	}
	availability := status.Availability
	formatted := fmt.Sprintf("%.1f/%.1f%%", availability.UpRatio*100, availability.Recent24h.UpRatio*100)
	return colorRatio(min(availability.UpRatio, availability.Recent24h.UpRatio), formatted)
}

func recentFailureEpisode(status control.NodeStatus, now time.Time) bool {
	availability := status.Availability
	startedAt := availability.LastFailureStartedAt
	if !status.ChecksConnectivity || startedAt.IsZero() || startedAt.After(now) {
		return false
	}
	if availability.Recent24h.UpRatio < 1 {
		return true
	}
	cutoff := now.Add(-24 * time.Hour)
	duration := max(availability.LastFailureDuration, 0)
	if duration == 0 {
		return !startedAt.Before(cutoff)
	}
	return startedAt.Add(duration).After(cutoff)
}

func recentNodeFailure(status control.NodeStatus, now time.Time) bool {
	return status.ChecksConnectivity && (status.Availability.Recent24h.ChecksFailed > 0 || recentFailureEpisode(status, now))
}

func compactFailure(status control.NodeStatus, now time.Time) string {
	if !recentNodeFailure(status, now) {
		return "-"
	}
	availability := status.Availability
	if !recentFailureEpisode(status, now) {
		return colorize(fmt.Sprintf("%dchk", availability.Recent24h.ChecksFailed), text.FgYellow)
	}
	formatDuration := func(duration time.Duration) string {
		if duration <= 0 {
			return "0s"
		}
		return formatUptime(duration)
	}
	formatted := formatDuration(now.Sub(availability.LastFailureStartedAt)) + "/" + formatDuration(availability.LastFailureDuration)
	if nodeHealth(status) == nodeHealthUnhealthy {
		return colorize(formatted, text.FgRed)
	}
	return colorize(formatted, text.FgYellow)
}

func hasRecentNodeFailure(nodes []control.NodeStatus, now time.Time) bool {
	for _, node := range nodes {
		if recentNodeFailure(node, now) {
			return true
		}
	}
	return false
}

func compactNodeStatusRow(status control.NodeStatus, index int, selected control.NetworkValues[string], showFailure bool, now time.Time) table.Row {
	networks, isSelected := nodeNetworks(status, selected)
	row := table.Row{
		colorSelected(annotatedNodeLabel(status, index), isSelected),
		emptyDash(status.Protocol),
		compactNodeState(status),
		networks,
		nodeLatency(status),
		compactUpRatios(status),
	}
	if showFailure {
		row = append(row, compactFailure(status, now))
	}
	return append(row,
		formatConnCounts(status.Stats),
		formatTrafficCell(status.Stats),
		formatTrafficTotalCell(status.Stats),
	)
}

func uncheckedNetworkRows(group control.GroupStatus) []table.Row {
	rows := make([]table.Row, common.NetworkTypeCount)
	for index := common.NetworkIndex(0); index < common.NetworkTypeCount; index++ {
		rows[index] = table.Row{index.String(), formatConnCounts(group.Networks[index])}
	}
	return rows
}

func checkedNetworkRows(group control.GroupStatus, verbose bool) []table.Row {
	rows := make([]table.Row, 0, common.NetworkTypeCount)
	for index := common.NetworkIndex(0); index < common.NetworkTypeCount; index++ {
		support := groupNetworkSupport(group.Nodes, index)
		if !verbose && support != dialer.NetworkSupportConfirmed {
			continue
		}
		rows = append(rows, networkStatusRow(group, index))
	}
	return rows
}

func nodeTable(group control.GroupStatus, verbose bool, now time.Time) (table.Row, []table.Row) {
	rows := make([]table.Row, 0, len(group.Nodes))
	if verbose {
		for index, status := range group.Nodes {
			rows = append(rows, nodeStatusRow(status, index, group.SelectedNodeIDs))
		}
		return table.Row{
			"PATH", "SUB", "PROTO", "SESSION", "HEALTH", "NETWORKS",
			"LATENCY last/avg10/mov(ms)", "UP% (FAIL/CHK)", "24H UP% (FAIL/CHK)", "FAILURE (START/DURATION)",
			"HEALTHY-SINCE", "LAST-CHECK", "LAST-CONN-FAIL", "CONNS(A/T)", "TRAFFIC 1M ↑/↓ AVG/MAX", "TOTAL ↑/↓",
		}, rows
	}

	showFailure := hasRecentNodeFailure(group.Nodes, now)
	for index, status := range group.Nodes {
		rows = append(rows, compactNodeStatusRow(status, index, group.SelectedNodeIDs, showFailure, now))
	}
	header := table.Row{"PATH", "PROTO", "STATE", "NETWORKS", "LAT L/A/M(ms)", "UP/24H"}
	if showFailure {
		header = append(header, "FAIL A/D")
	}
	header = append(header, "CONNS", "TRAFFIC 1M ↑/↓ AVG/MAX", "TOTAL ↑/↓")
	return header, rows
}

func printGroupStatus(group control.GroupStatus, verbose bool) {
	policy := group.Policy
	if policy == "" {
		policy = "single path"
	}
	fmt.Printf("\nGroup '%s' [kind: %s, policy: %s]\n", group.Name, group.TargetKind, policy)
	status := "no connectivity checks"
	if group.ChecksConnectivity {
		upRatio := "-"
		if group.Availability.Seen {
			upRatio = colorRatio(group.Availability.UpRatio, formatRatio(group.Availability.UpRatio))
		}
		status = fmt.Sprintf(
			"%s · up %s · since %s · failure %s",
			formatGroupConnectivityState(group),
			upRatio,
			formatAgo(group.Availability.AliveSince),
			formatFailure(group.Availability.LastFailureStartedAt, group.Availability.LastFailureDuration),
		)
	}
	if group.Stats.FallbackConnections > 0 {
		status += fmt.Sprintf(" · %d fallback total", group.Stats.FallbackConnections)
	}
	fmt.Printf("Status: %s\n", status)
	if traffic := formatTrafficSummary(group.Stats); traffic != "" {
		fmt.Printf("Traffic: %s\n", traffic)
	}
	if !group.ChecksConnectivity {
		printTable(table.Row{"NETWORK", "CONNS(A/T)"}, uncheckedNetworkRows(group))
		return
	}
	if rows := checkedNetworkRows(group, verbose); len(rows) > 0 {
		printTable(table.Row{"NETWORK", "ROUTE", "CONNS(A/T)"}, rows)
	}

	fmt.Printf("\nPaths of target '%s':\n", group.Name)
	header, rows := nodeTable(group, verbose, time.Now())
	printTable(header, rows)
}

func statusSummary(snapshot *control.StatusSnapshot) string {
	var degradedGroups, warningGroups []string
	for _, group := range snapshot.Groups {
		switch groupHealth(group) {
		case healthDegraded:
			degradedGroups = append(degradedGroups, group.Name)
		case healthWarning:
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

	summary := colorHealth(statusHealth(snapshot.Groups))
	if len(details) > 0 {
		summary += " (" + strings.Join(details, "; ") + ")"
	}
	return summary
}

func printStatus(snapshot *control.StatusSnapshot, verbose bool) {
	fmt.Printf(
		"Daemon:      %s up %s (since %s)",
		snapshot.Version,
		formatUptime(time.Since(snapshot.StartedAt)),
		snapshot.StartedAt.Local().Format("2006-01-02 15:04:05"),
	)
	if !snapshot.LastReloadAt.IsZero() {
		fmt.Printf(", last reload %s", formatAgo(snapshot.LastReloadAt))
	}
	fmt.Println()
	fmt.Printf("Status:      %s\n", statusSummary(snapshot))
	perNet := make([]string, common.NetworkTypeCount)
	for index := common.NetworkIndex(0); index < common.NetworkTypeCount; index++ {
		perNet[index] = fmt.Sprintf("%s %d", index.String(), snapshot.Networks[index].ActiveConnections)
	}
	fmt.Printf(
		"Connections: %d active (%s), %d total",
		snapshot.Stats.ActiveConnections,
		strings.Join(perNet, ", "),
		snapshot.Stats.TotalConnections,
	)
	if snapshot.Stats.FallbackConnections > 0 {
		fmt.Printf(", %d fallback total", snapshot.Stats.FallbackConnections)
	}
	fmt.Println()
	if traffic := formatTrafficSummary(snapshot.Stats); traffic != "" {
		fmt.Printf("Traffic:     %s\n", traffic)
	}

	if len(snapshot.Tables) > 0 {
		fmt.Println("\nTables:")
		rows := make([]table.Row, 0, len(snapshot.Tables))
		for _, usage := range snapshot.Tables {
			rows = append(rows, tableUsageRow(usage))
		}
		printTable(table.Row{"TABLE", "USED", "LIMIT", "USAGE", "LIVE/RETAINED", "LIMIT-GC"}, rows)
	}

	for _, group := range snapshot.Groups {
		printGroupStatus(group, verbose)
	}
}
