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
	"github.com/spf13/cobra"
	"golang.org/x/text/width"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the status of the running dae daemon.",
	Run: func(cmd *cobra.Command, args []string) {
		internal.AutoSu()
		snapshot, err := fetchStatus()
		if err != nil {
			fmt.Println("Failed to get status:", err)
			os.Exit(1)
		}
		printStatus(snapshot)
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

func boolYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
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

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// withChecks appends a check counter to a relative timestamp, telling how
// many checks (i.e. latency samples) have run since that moment.
func withChecks(s string, t *time.Time, checks int64) string {
	if t == nil || checks <= 0 {
		return s
	}
	return fmt.Sprintf("%v (+%v chk)", s, checks)
}

// displayWidth returns the number of terminal cells occupied by s, treating
// East Asian wide/fullwidth runes as two cells.
func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		switch width.LookupRune(r).Kind() {
		case width.EastAsianFullwidth, width.EastAsianWide:
			w += 2
		default:
			w++
		}
	}
	return w
}

func printTable(out io.Writer, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	cols := 0
	for _, row := range rows {
		if len(row) > cols {
			cols = len(row)
		}
	}
	widths := make([]int, cols)
	for _, row := range rows {
		for i, cell := range row {
			if w := displayWidth(cell); w > widths[i] {
				widths[i] = w
			}
		}
	}
	for _, row := range rows {
		for i, cell := range row {
			if i > 0 {
				fmt.Fprint(out, "  ")
			}
			fmt.Fprint(out, cell)
			if i < len(row)-1 {
				fmt.Fprint(out, strings.Repeat(" ", widths[i]-displayWidth(cell)))
			}
		}
		fmt.Fprintln(out)
	}
}

func printStatus(s *control.StatusSnapshot) {
	fmt.Printf("Daemon:      %v up %v (since %v)", s.Version, formatUptime(time.Since(s.StartedAt)), s.StartedAt.Local().Format("2006-01-02 15:04:05"))
	if s.LastReloadAt != nil {
		fmt.Printf(", last reload %v", formatAgo(s.LastReloadAt))
	}
	fmt.Println()
	var perNet []string
	for i, n := range s.ActiveByNet {
		perNet = append(perNet, fmt.Sprintf("%v %v", networkNames[i], n))
	}
	fmt.Printf("Connections: %v active (%v), %v total\n", s.ActiveConns, strings.Join(perNet, ", "), s.TotalConns)

	for _, g := range s.Groups {
		if g.NoCheck {
			fmt.Printf("\nGroup '%v' [policy: %v] (no connectivity checks)\n", g.Name, g.Policy)
			rows := [][]string{
				{"NETWORK", "CONNS(A/T)"},
			}
			for _, ns := range g.Networks {
				rows = append(rows, []string{
					ns.Network,
					fmt.Sprintf("%v/%v", ns.ActiveConns, ns.TotalConns),
				})
			}
			printTable(os.Stdout, rows)
			continue
		}
		fmt.Printf("\nGroup '%v' [policy: %v]\n", g.Name, g.Policy)
		rows := [][]string{
			{"NETWORK", "ALIVE", "SELECTED", "UP%", "ALIVE-SINCE", "LAST-FAIL", "CONNS(A/T)"},
		}
		for _, ns := range g.Networks {
			rows = append(rows, []string{
				ns.Network,
				boolYesNo(ns.Alive),
				emptyDash(ns.Selected),
				formatRatio(ns.UpRatio),
				formatAgo(ns.AliveSince),
				formatAgo(ns.LastFailAt),
				fmt.Sprintf("%v/%v", ns.ActiveConns, ns.TotalConns),
			})
		}
		printTable(os.Stdout, rows)

		fmt.Printf("\nNodes of group '%v':\n", g.Name)
		rows = [][]string{
			{"NODE", "SUB", "PROTO", "ALIVE", "SUPPORT", "SELECTED", "LATENCY last/avg10/mov(ms)", "UP% (FAIL/CHK)", "ALIVE-SINCE", "LAST-FAIL", "LAST-CHECK", "LAST-CONN-FAIL", "CONNS(A/T)"},
		}
		for _, n := range g.Nodes {
			latency := "-"
			if n.HasLatency && n.Alive {
				latency = fmt.Sprintf("%.0f/%.0f/%.0f", n.LastLatencyMs, n.Avg10LatencyMs, n.MovingAvgLatencyMs)
			}
			up := formatRatio(n.UpRatio)
			if n.ChecksTotal > 0 {
				up = fmt.Sprintf("%v (%v/%v)", up, n.ChecksFailed, n.ChecksTotal)
			}
			rows = append(rows, []string{
				n.Name,
				emptyDash(n.Subtag),
				emptyDash(n.Protocol),
				boolYesNo(n.Alive),
				networkFlags(n.Supported),
				networkFlags(n.Selected),
				latency,
				up,
				withChecks(formatAgo(n.AliveSince), n.AliveSince, n.ChecksSinceAlive),
				withChecks(formatAgo(n.LastFailAt), n.LastFailAt, n.ChecksSinceFail),
				formatAgo(n.LastCheckAt),
				formatAgo(n.LastConnFailAt),
				fmt.Sprintf("%v/%v", n.ActiveConns, n.TotalConns),
			})
		}
		printTable(os.Stdout, rows)
	}
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
