/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/control"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

func colorRecentHealth(health healthStatus) string {
	label := strings.ToUpper(string(health))
	switch health {
	case healthHealthy:
		return colorize(label, text.FgGreen)
	case healthWarning:
		return colorize(label, text.FgYellow)
	case healthDegraded:
		return colorize(label, text.FgRed)
	default:
		return label
	}
}

func recentStatePoint(state stats.GroupHistoryState) string {
	if !colorsEnabled {
		switch state {
		case stats.GroupHistoryAvailable:
			return "+"
		case stats.GroupHistoryUnavailable:
			return "x"
		default:
			return "."
		}
	}
	switch state {
	case stats.GroupHistoryAvailable:
		return colorize("●", text.FgGreen)
	case stats.GroupHistoryUnavailable:
		return colorize("●", text.FgRed)
	default:
		return colorize("○", text.FgHiBlack)
	}
}

func recentWindowLabel(duration time.Duration) string {
	switch {
	case duration%time.Hour == 0:
		return fmt.Sprintf("%dH", duration/time.Hour)
	case duration%time.Minute == 0:
		return fmt.Sprintf("%dM", duration/time.Minute)
	default:
		return fmt.Sprintf("%dS", duration/time.Second)
	}
}

func recentTimeline(group control.GroupStatus) string {
	states := make([]stats.GroupHistoryState, stats.GroupStateBucketCount)
	copy(states, group.Availability.Recent.States)
	var timeline strings.Builder
	timeline.WriteByte('[')
	for _, state := range states {
		timeline.WriteString(recentStatePoint(state))
	}
	timeline.WriteString("] / ")
	timeline.WriteString(recentWindowLabel(stats.GroupStateWindowDuration))
	return timeline.String()
}

func recentUpRatio(group control.GroupStatus) string {
	if !group.Availability.Seen {
		return "- / 24H"
	}
	ratio := group.Availability.Recent24h.UpRatio
	formatted := fmt.Sprintf("%.2f%% / 24H", ratio*100)
	return colorRatio(ratio, formatted)
}

func recentActiveWidth(groups []control.GroupStatus) int {
	width := 1
	for _, group := range groups {
		if digits := len(strconv.FormatInt(group.Stats.ActiveConnections, 10)); digits > width {
			width = digits
		}
	}
	return width
}

func recentGroupRow(group control.GroupStatus, activeWidth int) table.Row {
	activity := fmt.Sprintf("%*d active", activeWidth, group.Stats.ActiveConnections)
	rate := formatTrafficRateCell(group.Stats)
	total := formatTrafficTotalCell(group.Stats)
	if !group.ChecksConnectivity {
		return table.Row{group.Name, "", "", "", activity, rate, "U/D rate", total, "U/D total"}
	}
	return table.Row{
		group.Name,
		formatGroupConnectivityState(group),
		recentTimeline(group),
		recentUpRatio(group),
		activity,
		rate,
		"U/D rate",
		total,
		"U/D total",
	}
}

func truncateRecentGroupName(value string, maxWidth int) string {
	if text.StringWidth(value) <= maxWidth {
		return value
	}
	return text.Trim(value, maxWidth-1) + "…"
}

func renderRecentGroups(groups []control.GroupStatus) string {
	writer := newStatusTable()
	writer.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, WidthMax: 18, WidthMaxEnforcer: truncateRecentGroupName},
		{Number: 4, Align: text.AlignRight},
	})
	activeWidth := recentActiveWidth(groups)
	for _, group := range groups {
		writer.AppendRow(recentGroupRow(group, activeWidth))
	}
	return writer.Render()
}

func printRecentStatus(snapshot *control.StatusSnapshot) {
	traffic := formatTrafficSummary(snapshot.Stats)
	if traffic != "" {
		traffic = " · " + traffic
	}
	fmt.Printf(
		"dae %s · %s · up %s · %d active%s\n\n",
		snapshot.Version,
		colorRecentHealth(statusHealth(snapshot.Groups)),
		formatUptime(time.Since(snapshot.StartedAt)),
		snapshot.Stats.ActiveConnections,
		traffic,
	)

	printRenderedTable(renderRecentGroups(snapshot.Groups))
}
