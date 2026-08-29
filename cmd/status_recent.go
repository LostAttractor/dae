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

	"github.com/daeuniverse/dae/control"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

const (
	recentWindowSeconds = int64(time.Hour / time.Second)
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

func recentStatePoint(state control.GroupBucketState) string {
	if !colorsEnabled {
		switch state {
		case control.GroupBucketAvailable:
			return "+"
		case control.GroupBucketUnavailable:
			return "x"
		default:
			return "."
		}
	}
	switch state {
	case control.GroupBucketAvailable:
		return colorize("●", text.FgGreen)
	case control.GroupBucketUnavailable:
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
	states := make([]control.GroupBucketState, control.GroupRecentBucketCount)
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

func recentActiveWidth(groups []control.GroupStatus) int {
	width := 1
	for _, group := range groups {
		if digits := len(strconv.FormatInt(group.ActiveConns, 10)); digits > width {
			width = digits
		}
	}
	return width
}

func recentGroupRow(group control.GroupStatus, activeWidth int) table.Row {
	activity := fmt.Sprintf("%*d active", activeWidth, group.ActiveConns)
	rate := formatTrafficRateCell(group.Traffic)
	total := formatTrafficTotalCell(group.Traffic)
	if group.Connectivity == nil {
		return table.Row{group.Name, "", "", "", activity, rate, "U/D rate", total, "U/D total"}
	}
	return table.Row{
		group.Name,
		formatGroupConnectivityState(group.Connectivity),
		recentTimeline(group.Connectivity),
		recentUpRatio(group.Connectivity),
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
	traffic := formatTrafficSummary(snapshot.Traffic)
	if traffic != "" {
		traffic = " · " + traffic
	}
	fmt.Printf(
		"dae %s · %s · up %s · %d active%s\n\n",
		snapshot.Version,
		colorRecentHealth(snapshot.Health),
		formatUptime(time.Since(snapshot.StartedAt)),
		snapshot.ActiveConns,
		traffic,
	)

	printRenderedTable(renderRecentGroups(snapshot.Groups))
}
