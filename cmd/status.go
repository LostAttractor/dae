/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/control"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var statusVerbose bool

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the status of the running dae daemon.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		internal.AutoSu()
		snapshot, err := fetchStatus()
		if err != nil {
			return fmt.Errorf("failed to get status: %w", err)
		}
		printStatus(snapshot)
		return nil
	},
}

func fetchStatus() (*control.StatusSnapshot, error) {
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", StatusSocketPath)
			},
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get("http://unix/status")
	if err != nil {
		if os.IsNotExist(err) || strings.Contains(err.Error(), "no such file") {
			return nil, fmt.Errorf("is dae running? (%v)", err)
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("daemon returned %v (daemon may be reloading)", resp.Status)
	}
	return decodeStatus(resp.Body)
}

func decodeStatus(r io.Reader) (*control.StatusSnapshot, error) {
	var snapshot control.StatusSnapshot
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("status response contains multiple JSON values")
		}
		return nil, err
	}
	switch snapshot.Health {
	case control.HealthHealthy, control.HealthWarning, control.HealthDegraded:
	default:
		return nil, fmt.Errorf("status response has invalid health %q", snapshot.Health)
	}
	for i, group := range snapshot.Groups {
		for j, network := range group.Networks {
			if network.Selected != nil && (network.Selected.Index < 0 || network.Selected.Index >= len(group.Nodes)) {
				return nil, fmt.Errorf("groups[%d].networks[%d] selects node index %d outside nodes", i, j, network.Selected.Index)
			}
		}
	}
	return &snapshot, nil
}

func formatUptime(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	d = d.Truncate(time.Second)
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	hours := int(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	minutes := int(d / time.Minute)
	d -= time.Duration(minutes) * time.Minute
	seconds := int(d / time.Second)
	switch {
	case days > 0:
		return fmt.Sprintf("%dd%dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh%dm", hours, minutes)
	case minutes > 0:
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}

func formatAgo(t *time.Time) string {
	if t == nil {
		return "-"
	}
	d := time.Since(*t)
	if d < time.Second {
		return "just now"
	}
	return formatUptime(d) + " ago"
}

func formatRatio(ratio float64) string {
	return fmt.Sprintf("%.1f%%", ratio*100)
}

func formatAvailability(ratio float64, failed, total int64) string {
	if total == 0 {
		return formatRatio(ratio)
	}
	return fmt.Sprintf("%s (%d/%d)", formatRatio(ratio), failed, total)
}

func shouldEnableColors() bool {
	forceColor := os.Getenv("FORCE_COLOR")
	if forceColor != "" && forceColor != "0" && forceColor != "false" {
		return true
	}
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return false
	}
	if noColor := os.Getenv("NO_COLOR"); noColor != "" && noColor != "0" {
		return false
	}
	return os.Getenv("TERM") != "dumb"
}

var colorsEnabled = shouldEnableColors()

const (
	healthyUpRatio  = 0.99
	degradedUpRatio = 0.9
	fastLatencyMs   = 200
	slowLatencyMs   = 500
	ampleUsageRatio = 0.7
	tightUsageRatio = 0.9
)

func colorize(s string, colors ...text.Color) string {
	if !colorsEnabled {
		return s
	}
	return text.Escape(s, text.Colors(colors).EscapeSeq())
}

func colorAlive(alive bool) string {
	if alive {
		return colorize("yes", text.FgGreen)
	}
	return colorize("no", text.FgRed)
}

func colorHealth(health control.HealthStatus) string {
	switch health {
	case control.HealthHealthy:
		return colorize(string(health), text.FgGreen)
	case control.HealthWarning:
		return colorize(string(health), text.FgYellow)
	case control.HealthDegraded:
		return colorize(string(health), text.FgRed)
	default:
		panic(fmt.Sprintf("invalid health status %q", health))
	}
}

func colorNodeHealth(health control.NodeHealthState) string {
	switch health {
	case "":
		return "-"
	case control.NodeHealthHealthy:
		return colorize(string(health), text.FgGreen)
	case control.NodeHealthUnknown:
		return colorize(string(health), text.FgYellow)
	case control.NodeHealthUnhealthy:
		return colorize(string(health), text.FgRed)
	default:
		panic(fmt.Sprintf("invalid node health status %q", health))
	}
}

func colorSelected(s string, selected bool) string {
	if !selected {
		return s
	}
	return colorize(s, text.FgCyan)
}

func colorRatio(ratio float64, s string) string {
	switch {
	case ratio >= healthyUpRatio:
		return colorize(s, text.FgGreen)
	case ratio >= degradedUpRatio:
		return colorize(s, text.FgYellow)
	default:
		return colorize(s, text.FgRed)
	}
}

func colorLatency(latencyMs float64, s string) string {
	switch {
	case latencyMs < fastLatencyMs:
		return colorize(s, text.FgGreen)
	case latencyMs < slowLatencyMs:
		return colorize(s, text.FgYellow)
	default:
		return colorize(s, text.FgRed)
	}
}

func colorUsage(ratio float64, s string) string {
	switch {
	case ratio < ampleUsageRatio:
		return colorize(s, text.FgGreen)
	case ratio < tightUsageRatio:
		return colorize(s, text.FgYellow)
	default:
		return colorize(s, text.FgRed)
	}
}

func networkSupport(networks []control.NodeNetworkStatus) string {
	var parts []string
	for _, network := range networks {
		if network.SupportState == control.NetworkSupportConfirmed {
			parts = append(parts, network.Network)
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return compactNetworks(parts)
}

func compactNetworks(networks []string) string {
	set := make(map[string]bool, len(networks))
	for _, network := range networks {
		set[network] = true
	}
	if len(set) == 0 {
		return "-"
	}
	if len(set) == 4 && set["tcp4"] && set["tcp6"] && set["udp4"] && set["udp6"] {
		return "all"
	}
	parts := make([]string, 0, len(set))
	consume := func(label, first, second string) {
		if set[first] && set[second] {
			parts = append(parts, label)
			delete(set, first)
			delete(set, second)
		}
	}
	consume("all tcp", "tcp4", "tcp6")
	consume("all udp", "udp4", "udp6")
	consume("all ipv4", "tcp4", "udp4")
	consume("all ipv6", "tcp6", "udp6")
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		if set[network] {
			parts = append(parts, network)
			delete(set, network)
		}
	}
	for _, network := range networks {
		if set[network] {
			parts = append(parts, network)
			delete(set, network)
		}
	}
	return strings.Join(parts, ",")
}

func selectedNetworks(nodeIndex int, networks []control.NetworkStatus) (string, bool) {
	var parts []string
	for _, network := range networks {
		if network.Selected != nil && network.Selected.Index == nodeIndex {
			parts = append(parts, network.Network)
		}
	}
	if len(parts) == 0 {
		return "-", false
	}
	return compactNetworks(parts), true
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func formatAgoWithChecks(t *time.Time, checks int64) string {
	s := formatAgo(t)
	if t == nil || checks <= 0 {
		return s
	}
	return fmt.Sprintf("%s (+%d chk)", s, checks)
}

func formatFailure(failure *control.FailureStatus) string {
	if failure == nil {
		return "-"
	}
	duration := time.Duration(failure.DurationMs) * time.Millisecond
	durationText := "0s"
	if duration > 0 {
		durationText = formatUptime(duration)
	}
	return fmt.Sprintf("%s / %s", formatAgo(&failure.StartedAt), durationText)
}

func formatConnCounts(active, total int64) string {
	return fmt.Sprintf("%d/%d", active, total)
}

// printTable renders a borderless, left-aligned table with two-space column
// gutters. go-pretty measures cell widths ANSI- and CJK-aware, so colored
// cells and East Asian wide runes stay aligned.
func printTable(header table.Row, rows []table.Row) {
	t := table.NewWriter()
	style := table.StyleDefault
	style.Options.DrawBorder = false
	style.Options.SeparateHeader = false
	style.Options.SeparateColumns = false
	style.Box.PaddingLeft = ""
	style.Box.PaddingRight = "  "
	style.Format.Header = text.FormatDefault
	t.SetStyle(style)
	t.AppendHeader(header)
	t.AppendRows(rows)
	for _, line := range strings.Split(t.Render(), "\n") {
		fmt.Println(strings.TrimRight(line, " "))
	}
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
		string(status.SupportState),
		colorSelected(selected, status.Selected != nil),
		formatConnCounts(status.ActiveConns, status.TotalConns),
	}
}

func nodeStatusRow(status control.NodeStatus, index int, groupNetworks []control.NetworkStatus) table.Row {
	selectedNetworks, selected := selectedNetworks(index, groupNetworks)
	session := "-"
	if status.Session != nil {
		session = string(status.Session.State)
	}

	healthState := "-"
	latency := nodeLatency(status)
	upRatio := "-"
	upRatio24h := "-"
	healthySince := "-"
	failure := "-"
	lastCheck := "-"
	if status.Health != nil {
		healthState = colorNodeHealth(status.Health.State)
		upRatio = colorRatio(status.Health.UpRatio, formatAvailability(status.Health.UpRatio, status.Health.ChecksFailed, status.Health.ChecksTotal))
		upRatio24h = colorRatio(status.Health.UpRatio24h, formatAvailability(status.Health.UpRatio24h, status.Health.ChecksFailed24h, status.Health.ChecksTotal24h))
		healthySince = formatAgoWithChecks(status.Health.HealthySince, status.Health.ChecksSinceHealthy)
		failure = formatFailure(status.Health.Failure)
		lastCheck = formatAgo(status.Health.LastCheckAt)
	}
	return table.Row{
		colorSelected(annotatedNodeLabel(status, index), selected),
		emptyDash(status.Subtag),
		emptyDash(status.Protocol),
		session,
		healthState,
		networkSupport(status.Networks),
		colorSelected(selectedNetworks, selected),
		latency,
		upRatio,
		upRatio24h,
		healthySince,
		failure,
		lastCheck,
		formatAgo(status.LastConnectionFailureAt),
		formatConnCounts(status.ActiveConns, status.TotalConns),
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
	}
}

func printGroupStatus(group control.GroupStatus) {
	policy := group.Policy
	if policy == "" {
		policy = "single path"
	}
	targetKind := group.TargetKind
	if targetKind == "" {
		targetKind = "group"
	}
	if group.Connectivity == nil {
		fmt.Printf("\nGroup '%s' [kind: %s, policy: %s] (no connectivity checks)\n", group.Name, targetKind, policy)
		rows := make([]table.Row, 0, len(group.Networks))
		for _, status := range group.Networks {
			rows = append(rows, table.Row{
				status.Network,
				formatConnCounts(status.ActiveConns, status.TotalConns),
			})
		}
		printTable(table.Row{"NETWORK", "CONNS(A/T)"}, rows)
		return
	}

	fmt.Printf(
		"\nGroup '%s' [kind: %s, policy: %s, available: %s, up: %s, available since: %s, failure: %s]\n",
		group.Name,
		targetKind,
		policy,
		colorAlive(group.Connectivity.Available),
		colorRatio(group.Connectivity.UpRatio, formatRatio(group.Connectivity.UpRatio)),
		formatAgo(group.Connectivity.AvailableSince),
		formatFailure(group.Connectivity.Failure),
	)
	rows := make([]table.Row, 0, len(group.Networks))
	for _, status := range group.Networks {
		rows = append(rows, networkStatusRow(status, group.Nodes))
	}
	printTable(table.Row{
		"NETWORK", "SUPPORT", "SELECTED", "CONNS(A/T)",
	}, rows)

	fmt.Printf("\nPaths of target '%s':\n", group.Name)
	now := time.Now()
	showFailure := !statusVerbose && hasRecentNodeFailure(group.Nodes, now)
	rows = make([]table.Row, 0, len(group.Nodes))
	for i, status := range group.Nodes {
		if statusVerbose {
			rows = append(rows, nodeStatusRow(status, i, group.Networks))
		} else {
			row := compactNodeStatusRow(status, i, group.Networks)
			if showFailure {
				row = append(row, compactFailure(status.Health, now))
			}
			rows = append(rows, row)
		}
	}
	if !statusVerbose {
		header := table.Row{
			"PATH", "PROTO", "STATE", "NETS", "SELECT", "LAT L/A/M(ms)", "UP/24H", "CONNS",
		}
		if showFailure {
			header = append(header, "FAIL A/D")
		}
		printTable(header, rows)
		return
	}
	printTable(table.Row{
		"PATH", "SUB", "PROTO", "SESSION", "HEALTH", "SUPPORT", "SELECTED",
		"LATENCY last/avg10/mov(ms)", "UP% (FAIL/CHK)", "24H UP% (FAIL/CHK)", "HEALTHY-SINCE",
		"FAILURE (START/DURATION)", "LAST-CHECK", "LAST-CONN-FAIL", "CONNS(A/T)",
	}, rows)
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
	fmt.Printf("Connections: %d active (%s), %d total\n", s.ActiveConns, strings.Join(perNet, ", "), s.TotalConns)

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

func init() {
	statusCmd.Flags().BoolVar(&statusVerbose, "verbose", false, "show detailed path health history")
	rootCmd.AddCommand(statusCmd)
}
