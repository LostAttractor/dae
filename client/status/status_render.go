/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package status

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/daeuniverse/dae/api"

	"github.com/daeuniverse/dae/pkg/clitable"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

func truncateStatusCell(value string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}
	return text.Snip(value, maxWidth, "…")
}

func renderStatusTable(header table.Row, rows []table.Row, configs []table.ColumnConfig, maxWidth int) string {
	writer := clitable.New()
	if maxWidth > 0 {
		writer.Style().Size.WidthMax = maxWidth
		writer.Style().Box.UnfinishedRow = ""
	}
	writer.SetColumnConfigs(configs)
	aligned := clitable.AlignRows(append([]table.Row{header}, rows...))
	if len(header) > 0 {
		writer.AppendHeader(aligned[0])
	}
	writer.AppendRows(aligned[1:])
	return writer.Render()
}

func printTable(out io.Writer, header table.Row, rows []table.Row) {
	fmt.Fprintln(out, renderStatusTable(header, rows, nil, getStatusTerminalWidth()))
}

// Journal output keeps the full table even when dae runs in a narrow terminal.
func renderLogTable(header table.Row, rows []table.Row) string {
	return text.StripEscape(renderStatusTable(header, rows, nil, 0))
}

func tableUsageRow(usage api.TableUsage) table.Row {
	limit, ratio := "unlimited", "-"
	if usage.Limit > 0 {
		limit = fmt.Sprint(usage.Limit)
		fraction := float64(usage.Used) / float64(usage.Limit)
		ratio = colorUsage(fraction, formatRatio(fraction))
	}
	return table.Row{fmt.Sprint(usage.Used), limit, ratio,
		fmt.Sprint(usage.Candidates), fmt.Sprint(max(0, usage.Candidates-usage.Used))}
}

func nodeLabel(status api.NodeStatus, index int) string {
	if status.Name != "" {
		return status.Name
	}
	if status.Address != "" {
		return status.Address
	}
	return fmt.Sprintf("#%d", index)
}

func annotatedNodeLabel(status api.NodeStatus, index int) string {
	label := nodeLabel(status, index)
	if status.Annotation == nil {
		return label
	}
	parts := make([]string, 0, 2)
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
	if len(parts) == 0 {
		return label
	}
	return label + " [" + strings.Join(parts, ",") + "]"
}

func groupNetworkSupport(nodes []api.NodeStatus, network api.NetworkIndex) api.NetworkSupportState {
	support := api.NetworkSupportUnsupported
	for _, node := range nodes {
		switch node.Support[network] {
		case api.NetworkSupportConfirmed:
			return api.NetworkSupportConfirmed
		case api.NetworkSupportUnknown:
			support = api.NetworkSupportUnknown
		}
	}
	return support
}

func groupNetworkRoutable(group api.GroupStatus, network api.NetworkIndex) bool {
	if group.SelectedNodeIDs[network] != "" {
		return true
	}
	dynamicPolicy := group.Policy != "" && group.Policy != "fixed"
	if !dynamicPolicy {
		return false
	}
	for _, node := range group.Nodes {
		if node.Healthy && node.Support[network] == api.NetworkSupportConfirmed {
			return true
		}
	}
	return false
}

func networkStatusRow(group api.GroupStatus, network api.NetworkIndex) table.Row {
	support := groupNetworkSupport(group.Nodes, network)
	route := colorNetworkSupport(support)
	selectedID := group.SelectedNodeIDs[network]
	for index, node := range group.Nodes {
		if selectedID != "" && node.ID == selectedID {
			route = colorSelected(nodeLabel(node, index), true)
			break
		}
	}
	if selectedID == "" && support == api.NetworkSupportConfirmed {
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
	latency      any
	upRatio      any
	upRatio24h   any
	healthySince string
	failure      any
	lastCheck    string
}

func verboseNodeHealth(status api.NodeStatus) verboseNodeHealthCells {
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
		cells.state = colorNodeState(nodeHealth(status), "")
		cells.upRatio = availabilityCell(availability.UpRatio, availability.ChecksFailed, availability.ChecksTotal).Decorate(func(value string) string { return colorRatio(availability.UpRatio, value) })
		cells.upRatio24h = availabilityCell(availability.Recent24h.UpRatio, availability.Recent24h.ChecksFailed, availability.Recent24h.ChecksTotal).Decorate(func(value string) string { return colorRatio(availability.Recent24h.UpRatio, value) })
		cells.healthySince = formatAgoWithChecks(availability.AliveSince, availability.ChecksSinceAlive)
		cells.failure = failureCell(availability.LastFailureStartedAt, availability.LastFailureDuration)
		cells.lastCheck = formatAgo(availability.LastCheckAt)
	}
	return cells
}

func nodeStatusRow(status api.NodeStatus, index int, selected api.NetworkValues[string], now time.Time) table.Row {
	networks, isSelected := nodeNetworks(status, selected)
	health := verboseNodeHealth(status)
	return table.Row{
		colorSelected(annotatedNodeLabel(status, index), isSelected),
		emptyDash(status.Subtag),
		emptyDash(status.Protocol),
		emptyDash(nodeSessionState(status)),
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
		formatRecovery(status.Recovery, now),
		formatRecoveryFailure(status.Failure),
	}
}

func nodeLatency(status api.NodeStatus) any {
	if status.Latency == nil || nodeHealth(status) != nodeHealthHealthy {
		return "-"
	}
	latency := status.Latency
	last := latency.Last.Seconds() * 1000
	average := latency.Avg10.Seconds() * 1000
	moving := latency.MovingAvg.Seconds() * 1000
	formatted := clitable.Parts(fmt.Sprintf("%.0f", last), "/", fmt.Sprintf("%.0f", average), "/", fmt.Sprintf("%.0f", moving))
	if latency.Avg10HasFailure {
		return formatted.Decorate(func(value string) string { return colorize(value, text.FgHiRed, text.Bold) })
	}
	return formatted.Decorate(func(value string) string { return colorLatency(moving, value) })
}

func compactNodeState(status api.NodeStatus, now time.Time) string {
	state := nodeHealth(status)
	if !status.ChecksConnectivity {
		state = nodeSessionState(status)
	}
	var detail string
	recovery := status.Recovery
	if recovery.Phase != "" && recovery.Phase != api.RecoveryReady &&
		(!status.Healthy || recovery.Phase == api.RecoveryBlocked || recovery.Action == "replenish") {
		detail = formatRecovery(recovery, now)
	}
	return colorNodeState(state, detail)
}

func compactUpRatios(status api.NodeStatus) any {
	if nodeHealth(status) == nodeHealthUnknown {
		return "-"
	}
	availability := status.Availability
	formatted := clitable.Parts(fmt.Sprintf("%.1f", availability.UpRatio*100), "/", fmt.Sprintf("%.1f%%", availability.Recent24h.UpRatio*100))
	return formatted.Decorate(func(value string) string {
		return colorRatio(min(availability.UpRatio, availability.Recent24h.UpRatio), value)
	})
}

func recentFailureEpisode(status api.NodeStatus, now time.Time) bool {
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

func recentNodeFailure(status api.NodeStatus, now time.Time) bool {
	return status.ChecksConnectivity && (status.Availability.Recent24h.ChecksFailed > 0 || recentFailureEpisode(status, now))
}

func compactFailure(status api.NodeStatus, now time.Time) any {
	if !recentNodeFailure(status, now) {
		return "-"
	}
	availability := status.Availability
	if !recentFailureEpisode(status, now) {
		return colorize(fmt.Sprintf("%dchk", availability.Recent24h.ChecksFailed), text.FgYellow)
	}
	formatted := clitable.Parts(failureDuration(now.Sub(availability.LastFailureStartedAt)), "/", failureDuration(availability.LastFailureDuration))
	if nodeHealth(status) == nodeHealthUnhealthy {
		return formatted.Decorate(func(value string) string { return colorize(value, text.FgRed) })
	}
	return formatted.Decorate(func(value string) string { return colorize(value, text.FgYellow) })
}

func hasRecentNodeFailure(nodes []api.NodeStatus, now time.Time) bool {
	for _, node := range nodes {
		if recentNodeFailure(node, now) {
			return true
		}
	}
	return false
}

func compactNodeStatusRow(status api.NodeStatus, index int, selected api.NetworkValues[string], showFailure bool, now time.Time) table.Row {
	networks, isSelected := nodeNetworks(status, selected)
	row := table.Row{
		colorSelected(annotatedNodeLabel(status, index), isSelected),
		emptyDash(status.Protocol),
		compactNodeState(status, now),
		networks,
		nodeLatency(status),
		compactUpRatios(status),
	}
	if showFailure {
		row = append(row, compactFailure(status, now))
	}
	return append(row, formatConnCounts(status.Stats))
}

func uncheckedNetworkRows(group api.GroupStatus) []table.Row {
	rows := make([]table.Row, api.NetworkTypeCount)
	for index := range api.NetworkIndex(api.NetworkTypeCount) {
		rows[index] = table.Row{index.String(), formatConnCounts(group.Networks[index])}
	}
	return rows
}

func checkedNetworkRows(group api.GroupStatus, verbose bool) []table.Row {
	rows := make([]table.Row, 0, api.NetworkTypeCount)
	for index := range api.NetworkIndex(api.NetworkTypeCount) {
		support := groupNetworkSupport(group.Nodes, index)
		if !verbose && support != api.NetworkSupportConfirmed {
			continue
		}
		rows = append(rows, networkStatusRow(group, index))
	}
	return rows
}

func nodeTable(group api.GroupStatus, verbose bool, now time.Time) (table.Row, []table.Row) {
	rows := make([]table.Row, 0, len(group.Nodes))
	if verbose {
		for index, status := range group.Nodes {
			rows = append(rows, nodeStatusRow(status, index, group.SelectedNodeIDs, now))
		}
		return table.Row{
			"PATH", "SUB", "PROTO", "SESSION", "HEALTH", "NETWORKS",
			"LATENCY last/avg10/mov(ms)", "UP% (FAIL/CHK)", "24H UP% (FAIL/CHK)", "FAILURE (START/DURATION)",
			"HEALTHY-SINCE", "LAST-CHECK", "LAST-CONN-FAIL", "CONNS(A/T)",
			"RECOVERY", "CAUSE",
		}, rows
	}

	showFailure := hasRecentNodeFailure(group.Nodes, now)
	for index, status := range group.Nodes {
		rows = append(rows, compactNodeStatusRow(status, index, group.SelectedNodeIDs, showFailure, now))
	}
	header := table.Row{"PATH", "PROTO", "STATE", "NETWORKS", "LAT L/A/M(ms)", clitable.Parts("UP", "/", "24H")}
	if showFailure {
		header = append(header, "FAIL A/D")
	}
	header = append(header, "CONNS")
	return header, rows
}

func groupStatusMetadata(group api.GroupStatus) string {
	policy := group.Policy
	if policy == "" {
		policy = "single path"
	}
	metadata := fmt.Sprintf("kind: %s, policy: %s", group.TargetKind, policy)
	if group.CheckAsync {
		metadata += ", check: async"
	}
	return metadata
}

// RenderStartupNodes retains the daemon's untruncated startup table format.
func RenderStartupNodes(groups []api.GroupStatus) string {
	now := time.Now()
	var out strings.Builder
	for _, group := range groups {
		var rows []table.Row
		for index, node := range group.Nodes {
			if !node.ChecksConnectivity || !node.InitialCheckDone || !node.Availability.Seen {
				continue
			}
			networks, _ := nodeNetworks(node, group.SelectedNodeIDs)
			rows = append(rows, table.Row{
				annotatedNodeLabel(node, index), emptyDash(node.Protocol),
				compactNodeState(node, now), networks, nodeLatency(node),
			})
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(&out, "Paths of target %q [%s]\n", group.Name, groupStatusMetadata(group))
		header := table.Row{"PATH", "PROTO", "STATE", "NETWORKS", "LAT L/A/M(ms)"}
		fmt.Fprintln(&out, renderLogTable(header, rows))
	}
	return strings.TrimSuffix(out.String(), "\n")
}

func printGroupStatus(out io.Writer, group api.GroupStatus, verbose bool) {
	fmt.Fprintf(out, "\nGroup '%s' [%s]\n", group.Name, groupStatusMetadata(group))
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
	fmt.Fprintf(out, "Status: %s\n", status)
	if !group.ChecksConnectivity {
		printTable(out, table.Row{"NETWORK", "CONNS(A/T)"}, uncheckedNetworkRows(group))
		return
	}
	if rows := checkedNetworkRows(group, verbose); len(rows) > 0 {
		printTable(out, table.Row{"NETWORK", "ROUTE", "CONNS(A/T)"}, rows)
	}

	fmt.Fprintf(out, "\nPaths of target '%s':\n", group.Name)
	header, rows := nodeTable(group, verbose, time.Now())
	printTable(out, header, rows)
}

func statusSummary(snapshot *api.StatusSnapshot) string {
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

func Print(out io.Writer, snapshot *api.StatusSnapshot, verbose bool) {
	fmt.Fprintf(out,
		"Daemon:      %s up %s (since %s)",
		snapshot.Version,
		formatUptime(time.Since(snapshot.StartedAt)),
		snapshot.StartedAt.Local().Format("2006-01-02 15:04:05"),
	)
	if !snapshot.LastReloadAt.IsZero() {
		fmt.Fprintf(out, ", last reload %s", formatAgo(snapshot.LastReloadAt))
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Status:      %s\n", statusSummary(snapshot))
	perNet := make([]string, api.NetworkTypeCount)
	for index := range api.NetworkIndex(api.NetworkTypeCount) {
		perNet[index] = fmt.Sprintf("%s %d", index.String(), snapshot.Networks[index].ActiveConnections)
	}
	fmt.Fprintf(out,
		"Connections: %d active (%s), %d total",
		snapshot.Stats.ActiveConnections,
		strings.Join(perNet, ", "),
		snapshot.Stats.TotalConnections,
	)
	if snapshot.Stats.FallbackConnections > 0 {
		fmt.Fprintf(out, ", %d fallback total", snapshot.Stats.FallbackConnections)
	}
	fmt.Fprintln(out)

	// Present retained evidence before its kernel projection.
	for _, usage := range snapshot.Tables {
		if detail := usage.Breakdown; detail != nil {
			limit := "unlimited"
			if usage.Limit > 0 {
				limit = fmt.Sprintf("limit: %d pairs", usage.Limit)
			}
			fmt.Fprintf(out, "\n%s (%s):\n", usage.Name, limit)
			printTable(out, table.Row{"PAIRS", "DOMAINS", "IPs", "IPv4", "IPv6", "GC (PAIRS)"}, []table.Row{
				{usage.Used, detail.Domains, detail.IPs, detail.IPv4, detail.IPv6, detail.GC},
			})
		}
	}
	for _, usage := range snapshot.Tables {
		if usage.Breakdown == nil {
			fmt.Fprintf(out, "\n%s:\n", usage.Name)
			printTable(out, table.Row{"USED (IPs)", "LIMIT", "USAGE", "CANDIDATES", "OMITTED"}, []table.Row{tableUsageRow(usage)})
		}
	}

	for _, group := range snapshot.Groups {
		printGroupStatus(out, group, verbose)
	}
	mode := trafficOrdinary
	if verbose {
		mode = trafficVerbose
	}
	printTraffic(out, snapshot, mode)
}

func nodeSessionState(status api.NodeStatus) string {
	if status.SessionDetail == nil {
		return ""
	}
	return status.SessionDetail.State
}
