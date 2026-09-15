// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/pkg/clitable"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

type trafficMode uint8

const (
	trafficOrdinary trafficMode = iota
	trafficRecent
	trafficVerbose
)

func trafficRateCell(average, maximum uint64) clitable.Cell {
	averageValue, averageUnit := formatBitRateParts(average)
	maximumValue, maximumUnit := formatBitRateParts(maximum)
	if averageUnit == maximumUnit {
		averageUnit = ""
	}
	return clitable.Parts(averageValue+averageUnit, "/", maximumValue+maximumUnit)
}

func hasTraffic(value api.PathStats) bool {
	return value.ActiveConnections > 0 || value.UploadBytes > 0 || value.DownloadBytes > 0
}

func hasRecentTraffic(value api.PathStats) bool {
	return trafficMaximum(value.History.UploadBytesPerSecond) > 0 || trafficMaximum(value.History.DownloadBytesPerSecond) > 0
}

func trafficRow(label string, value api.PathStats) table.Row {
	row := table.Row{label,
		"-", "-", "-", "-", formatBytes(value.UploadBytes), formatBytes(value.DownloadBytes)}
	upload, download := value.History.UploadBytesPerSecond, value.History.DownloadBytesPerSecond
	if len(upload) > 0 {
		upMax, downMax := trafficMaximum(upload), trafficMaximum(download)
		scale := max(upMax, downMax)
		row[1], row[2] = trafficSparkline(upload, scale), trafficSparkline(download, scale)
		row[3], row[4] = trafficRateCell(trafficAverage(upload), upMax), trafficRateCell(trafficAverage(download), downMax)
	}
	return row
}

func trafficNodeLabel(group api.GroupStatus, index int) string {
	node := group.Nodes[index]
	label := strings.Join(strings.Fields(nodeLabel(node, index)), " ")
	return colorSelected(label, slices.Contains(group.SelectedNodeIDs[:], node.ID))
}

func renderTraffic(snapshot *api.StatusSnapshot, mode trafficMode) string {
	header := table.Row{"GROUP / DIALER", "UPLOAD 1M", "DOWNLOAD 1M",
		clitable.Parts("AVG", "/", "MAX ↑"), clitable.Parts("AVG", "/", "MAX ↓"), "TOTAL ↑", "TOTAL ↓"}
	include := hasTraffic
	if mode == trafficRecent {
		include = hasRecentTraffic
	}
	rows := []table.Row{trafficRow(colorize("ALL", text.Bold), snapshot.Stats)}
	for _, group := range snapshot.Groups {
		if mode != trafficVerbose && !include(group.Stats) {
			continue
		}
		var nodes []int
		for i, node := range group.Nodes {
			if mode == trafficVerbose || include(node.Stats) || mode == trafficOrdinary && slices.Contains(group.SelectedNodeIDs[:], node.ID) {
				nodes = append(nodes, i)
			}
		}
		label := colorize(strings.Join(strings.Fields(group.Name), " "), text.Bold)
		if mode != trafficVerbose && len(nodes) == 1 {
			index := nodes[0]
			rows = append(rows, trafficRow(label+"("+trafficNodeLabel(group, index)+")", group.Stats))
			continue
		}
		rows = append(rows, trafficRow(label+" (total)", group.Stats))
		for _, index := range nodes {
			rows = append(rows, trafficRow("  "+trafficNodeLabel(group, index), group.Nodes[index].Stats))
		}
	}
	configs := []table.ColumnConfig{
		{Number: 1, WidthMax: 52, WidthMaxEnforcer: truncateStatusCell},
	}
	width := getStatusTerminalWidth()
	if mode == trafficVerbose {
		return renderStatusTable(header, rows, configs, width)
	}
	rendered := renderStatusTable(header, rows, configs, 0)
	if width == 0 || text.LongestLineLen(rendered) <= width {
		return rendered
	}
	// Keep both trends and lifetime totals when the rate columns do not fit.
	for i := range rows {
		rows[i] = slices.Delete(rows[i], 3, 5)
	}
	return renderStatusTable(slices.Delete(header, 3, 5), rows, configs, width)
}

func printTraffic(out io.Writer, snapshot *api.StatusSnapshot, mode trafficMode) {
	fmt.Fprintf(out, "\nTraffic:\n%s\n", renderTraffic(snapshot, mode))
}
