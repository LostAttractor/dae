/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
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
	var snapshot control.StatusSnapshot
	if err = json.NewDecoder(resp.Body).Decode(&snapshot); err != nil {
		return nil, err
	}
	normalizeStatus(&snapshot)
	return &snapshot, nil
}

func normalizeStatus(snapshot *control.StatusSnapshot) {
	legacy := snapshot.Health == ""
	for i := range snapshot.Groups {
		group := &snapshot.Groups[i]
		if group.NoCheck {
			group.Available = true
		}
		for j := range group.Networks {
			network := &group.Networks[j]
			if legacy && !group.NoCheck {
				network.Supported = true
			}
			if network.SupportState == "" {
				network.SupportState = "unsupported"
				if network.Supported {
					network.SupportState = "confirmed"
				}
			}
			group.Available = group.Available || network.Alive
			if network.UpRatio > group.UpRatio {
				group.UpRatio = network.UpRatio
			}
			if group.AliveSince == nil && network.AliveSince != nil {
				group.AliveSince = network.AliveSince
			}
			if group.LastFailureStartedAt == nil && network.LastFailureStartedAt != nil {
				group.LastFailureStartedAt = network.LastFailureStartedAt
				group.LastFailureDuration = network.LastFailureDuration
			}
		}
		for j := range group.Nodes {
			node := &group.Nodes[j]
			if node.DialerKind == "" {
				node.DialerKind = "stateless"
			}
			if node.SessionState == "" {
				node.SessionState = "n/a"
			}
			if node.HealthState == "" {
				node.HealthState = "unhealthy"
				if node.Alive {
					node.HealthState = "healthy"
				}
			}
			for k := range node.SupportState {
				if node.SupportState[k] == "" {
					node.SupportState[k] = "unsupported"
					if node.Supported[k] {
						node.SupportState[k] = "confirmed"
					}
				}
			}
		}
	}
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
		if health == "" {
			return "unknown"
		}
		return string(health)
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

var networkNames = [4]string{"tcp4", "tcp6", "udp4", "udp6"}

func networkFlags(flags [4]bool) string {
	var parts []string
	for i, flag := range flags {
		if flag {
			parts = append(parts, networkNames[i])
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ",")
}

func networkSupport(states [4]string) string {
	var parts []string
	for i, state := range states {
		if state == "confirmed" {
			parts = append(parts, networkNames[i])
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ",")
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

func formatFailure(startedAt *time.Time, duration time.Duration) string {
	if startedAt == nil {
		return "-"
	}
	durationText := "0s"
	if duration > 0 {
		durationText = formatUptime(duration)
	}
	return fmt.Sprintf("%s / %s", formatAgo(startedAt), durationText)
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

func networkStatusRow(status control.NetworkStatus) table.Row {
	return table.Row{
		status.Network,
		status.SupportState,
		colorSelected(emptyDash(status.Selected), status.Selected != ""),
		formatConnCounts(status.ActiveConns, status.TotalConns),
	}
}

func nodeStatusRow(status control.NodeStatus) table.Row {
	selected := status.Selected != [4]bool{}
	selectedNetworks := networkFlags(status.Selected)

	latency := "-"
	if status.HasLatency && status.HealthState == "healthy" {
		latency = fmt.Sprintf("%.0f/%.0f/%.0f", status.LastLatencyMs, status.Avg10LatencyMs, status.MovingAvgLatencyMs)
		if status.Avg10HasFailure {
			latency = colorize(latency, text.FgHiRed, text.Bold)
		} else {
			latency = colorLatency(status.MovingAvgLatencyMs, latency)
		}
	}

	upRatio := formatAvailability(status.UpRatio, status.ChecksFailed, status.ChecksTotal)
	upRatio24h := formatAvailability(status.UpRatio24h, status.ChecksFailed24h, status.ChecksTotal24h)

	return table.Row{
		colorSelected(status.Name, selected),
		emptyDash(status.Subtag),
		emptyDash(status.Protocol),
		emptyDash(status.DialerKind),
		emptyDash(status.SessionState),
		emptyDash(status.HealthState),
		networkSupport(status.SupportState),
		colorSelected(selectedNetworks, selected),
		latency,
		colorRatio(status.UpRatio, upRatio),
		colorRatio(status.UpRatio24h, upRatio24h),
		formatAgoWithChecks(status.AliveSince, status.ChecksSinceAlive),
		formatFailure(status.LastFailureStartedAt, status.LastFailureDuration),
		formatAgo(status.LastCheckAt),
		formatAgo(status.LastConnFailAt),
		formatConnCounts(status.ActiveConns, status.TotalConns),
	}
}

func printGroupStatus(group control.GroupStatus) {
	if group.NoCheck {
		fmt.Printf("\nGroup '%s' [policy: %s] (no connectivity checks)\n", group.Name, group.Policy)
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
		"\nGroup '%s' [policy: %s, available: %s, up: %s, alive since: %s, failure: %s]\n",
		group.Name,
		group.Policy,
		colorAlive(group.Available),
		colorRatio(group.UpRatio, formatRatio(group.UpRatio)),
		formatAgo(group.AliveSince),
		formatFailure(group.LastFailureStartedAt, group.LastFailureDuration),
	)
	rows := make([]table.Row, 0, len(group.Networks))
	for _, status := range group.Networks {
		rows = append(rows, networkStatusRow(status))
	}
	printTable(table.Row{
		"NETWORK", "SUPPORT", "SELECTED", "CONNS(A/T)",
	}, rows)

	fmt.Printf("\nNodes of group '%s':\n", group.Name)
	rows = make([]table.Row, 0, len(group.Nodes))
	for _, status := range group.Nodes {
		rows = append(rows, nodeStatusRow(status))
	}
	printTable(table.Row{
		"NODE", "SUB", "PROTO", "KIND", "SESSION", "HEALTH", "SUPPORT", "SELECTED",
		"LATENCY last/avg10/mov(ms)", "UP% (FAIL/CHK)", "24H UP% (FAIL/CHK)", "ALIVE-SINCE",
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
	perNet := make([]string, len(s.ActiveByNet))
	for i, n := range s.ActiveByNet {
		perNet[i] = fmt.Sprintf("%s %d", networkNames[i], n)
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
	rootCmd.AddCommand(statusCmd)
}
