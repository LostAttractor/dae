/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
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

const (
	recentWindowSeconds = int64(time.Hour / time.Second)
	recentBucketCount   = 10
)

func colorRecentHealth(health control.HealthStatus) string {
	label := strings.ToUpper(string(health))
	switch health {
	case control.HealthHealthy:
		return colorize(label, text.FgGreen)
	case control.HealthWarning:
		return colorize(label, text.FgYellow)
	case control.HealthDegraded:
		return colorize(label, text.FgRed)
	default:
		return label
	}
}

func recentCurrentState(connectivity *control.GroupConnectivityStatus) string {
	if connectivity == nil {
		return colorize("N/A", text.FgHiBlack)
	}
	switch connectivity.State {
	case control.GroupConnectivityAvailable:
		return colorize("UP", text.FgGreen)
	case control.GroupConnectivityUnavailable:
		return colorize("DOWN", text.FgRed)
	case control.GroupConnectivityUnknown, control.GroupConnectivityChecking:
		return colorize("CHECKING", text.FgYellow)
	default:
		return string(connectivity.State)
	}
}

func recentStatePoint(state control.GroupConnectivityState) string {
	if !colorsEnabled {
		switch state {
		case control.GroupConnectivityAvailable:
			return "+"
		case control.GroupConnectivityChecking:
			return "?"
		case control.GroupConnectivityUnavailable:
			return "x"
		default:
			return "."
		}
	}
	switch state {
	case control.GroupConnectivityAvailable:
		return colorize("●", text.FgGreen)
	case control.GroupConnectivityChecking:
		return colorize("●", text.FgYellow)
	case control.GroupConnectivityUnavailable:
		return colorize("●", text.FgRed)
	default:
		return colorize("○", text.FgHiBlack)
	}
}

func recentWindowLabel(seconds int64) string {
	if seconds <= 0 {
		seconds = recentWindowSeconds
	}
	duration := time.Duration(seconds) * time.Second
	switch {
	case duration%time.Hour == 0:
		return fmt.Sprintf("%dH", duration/time.Hour)
	case duration%time.Minute == 0:
		return fmt.Sprintf("%dM", duration/time.Minute)
	default:
		return fmt.Sprintf("%dS", seconds)
	}
}

func recentTimeline(connectivity *control.GroupConnectivityStatus) string {
	states := make([]control.GroupConnectivityState, recentBucketCount)
	windowSeconds := recentWindowSeconds
	if connectivity != nil {
		copy(states, connectivity.Recent.Buckets)
		windowSeconds = connectivity.Recent.WindowSeconds
	}
	var timeline strings.Builder
	timeline.WriteByte('[')
	for _, state := range states {
		timeline.WriteString(recentStatePoint(state))
	}
	timeline.WriteString("] / ")
	timeline.WriteString(recentWindowLabel(windowSeconds))
	return timeline.String()
}

func recentUpRatio(connectivity *control.GroupConnectivityStatus) string {
	if connectivity == nil || connectivity.UpRatio24h == nil {
		return "- / 24H"
	}
	ratio := *connectivity.UpRatio24h
	formatted := fmt.Sprintf("%.2f%% / 24H", ratio*100)
	return colorRatio(ratio, formatted)
}

func recentGroupRow(group control.GroupStatus) table.Row {
	return table.Row{
		group.Name,
		recentCurrentState(group.Connectivity),
		recentTimeline(group.Connectivity),
		recentUpRatio(group.Connectivity),
		fmt.Sprintf("%d active", group.ActiveConns),
	}
}

func truncateRecentGroupName(value string, maxWidth int) string {
	if text.StringWidth(value) <= maxWidth {
		return value
	}
	return text.Trim(value, maxWidth-1) + "…"
}

func printRecentStatus(snapshot *control.StatusSnapshot) {
	fmt.Printf(
		"dae %s · %s · up %s · %d active\n\n",
		snapshot.Version,
		colorRecentHealth(snapshot.Health),
		formatUptime(time.Since(snapshot.StartedAt)),
		snapshot.ActiveConns,
	)

	writer := table.NewWriter()
	style := table.StyleDefault
	style.Options.DrawBorder = false
	style.Options.SeparateColumns = false
	style.Box.PaddingLeft = ""
	style.Box.PaddingRight = "  "
	writer.SetStyle(style)
	writer.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, WidthMax: 18, WidthMaxEnforcer: truncateRecentGroupName},
		{Number: 4, Align: text.AlignRight},
		{Number: 5, Align: text.AlignRight},
	})
	rows := make([]table.Row, 0, len(snapshot.Groups))
	for _, group := range snapshot.Groups {
		rows = append(rows, recentGroupRow(group))
	}
	writer.AppendRows(rows)
	for _, line := range strings.Split(writer.Render(), "\n") {
		fmt.Println(strings.TrimRight(line, " "))
	}
}
