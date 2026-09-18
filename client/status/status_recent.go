/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package status

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

func recentTimeline(group api.GroupStatus) string {
	var timeline strings.Builder
	timeline.WriteByte('[')
	for _, state := range group.Availability.Recent.States {
		plain, glyph, color := ".", "○", text.FgHiBlack
		switch state {
		case api.GroupHistoryAvailable:
			plain, glyph, color = "+", "●", text.FgGreen
		case api.GroupHistoryUnavailable:
			plain, glyph, color = "x", "●", text.FgRed
		}
		if colorsEnabled {
			timeline.WriteString(colorize(glyph, color))
		} else {
			timeline.WriteString(plain)
		}
	}
	timeline.WriteByte(']')
	return timeline.String()
}

// Group by identity rather than display name, preserving the wire network order.
// Only confirmed capabilities and live selections need entries in this compact
// view. Unknown/unsupported networks without a selection are omitted.
func recentSelections(group api.GroupStatus) []string {
	if group.Policy == "random" {
		return []string{"random"}
	}
	var visible uint8
	for network, id := range group.SelectedNodeIDs {
		if id != "" || groupNetworkSupport(group.Nodes, api.NetworkIndex(network)) == api.NetworkSupportConfirmed {
			visible |= 1 << network
		}
	}
	var selections []string
	remaining := visible
	for network, id := range group.SelectedNodeIDs {
		if remaining&(1<<network) == 0 {
			continue
		}
		var mask uint8
		for i, selected := range group.SelectedNodeIDs {
			if selected == id {
				mask |= 1 << i
			}
		}
		mask &= visible
		remaining &^= mask
		label := emptyDash(id)
		if index := slices.IndexFunc(group.Nodes, func(node api.NodeStatus) bool { return id != "" && node.ID == id }); index >= 0 {
			label = nodeLabel(group.Nodes[index], index)
		}
		label = colorSelected(label, id != "")
		if mask != visible {
			label = strings.TrimPrefix(compactNetworks(mask), "all ") + ": " + label
		}
		selections = append(selections, label)
	}
	if len(selections) == 0 {
		return []string{"-"}
	}
	return selections
}

func renderRecentGroups(groups []api.GroupStatus) string {
	header := table.Row{"GROUP", "STATE", "24H", "1H", "SELECTED", "ACTIVE"}
	rows := make([]table.Row, 0, len(groups))
	for _, group := range groups {
		if group.TargetKind == "builtin" {
			continue
		}
		ratio, history := "-", "-"
		if group.ChecksConnectivity {
			history = recentTimeline(group)
			if group.Availability.Seen {
				up := group.Availability.Recent24h.UpRatio
				ratio = colorRatio(up, fmt.Sprintf("%.2f%%", up*100))
			}
		}
		selections := recentSelections(group)
		for i, selection := range selections {
			selections[i] = truncateStatusCell(selection, 32)
		}
		row := table.Row{group.Name, formatGroupConnectivityState(group), ratio, history, strings.Join(selections, "; "),
			fmt.Sprint(group.Stats.ActiveConnections)}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return ""
	}
	return renderStatusTable(header, rows, []table.ColumnConfig{
		{Number: 1, WidthMax: 18, WidthMaxEnforcer: truncateStatusCell},
	}, getStatusTerminalWidth())
}

func PrintRecent(out io.Writer, snapshot *api.StatusSnapshot) {
	width := getStatusTerminalWidth()
	health, color := statusHealth(snapshot.Groups), text.FgGreen
	switch health {
	case healthWarning:
		color = text.FgYellow
	case healthDegraded:
		color = text.FgRed
	}
	summary := []string{
		"dae " + snapshot.Version,
		colorize(strings.ToUpper(string(health)), color),
		"up " + formatUptime(time.Since(snapshot.StartedAt)),
		fmt.Sprintf("%d active", snapshot.Stats.ActiveConnections),
	}
	writeStatusLine(out, strings.Join(summary, "  "), width)
	fmt.Fprintln(out)

	printBuiltinStatus(out, snapshot, false)
	if groups := renderRecentGroups(snapshot.Groups); groups != "" {
		fmt.Fprintln(out, groups)
	}
	printTraffic(out, snapshot, trafficRecent)
}
