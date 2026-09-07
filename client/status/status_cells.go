// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"fmt"
	"github.com/daeuniverse/dae/api"
	"time"

	"github.com/daeuniverse/dae/pkg/clitable"
)

func formatConnCounts(value api.PathStats) clitable.Cell {
	fallback := ""
	if value.FallbackConnections > 0 {
		fallback = fmt.Sprintf(" (fb %d)", value.FallbackConnections)
	}
	return clitable.Parts(fmt.Sprint(value.ActiveConnections), "/", fmt.Sprint(value.TotalConnections),
		fallback)
}

func availabilityCell(ratio float64, failed, total int64) clitable.Cell {
	if total == 0 {
		return clitable.Parts(formatRatio(ratio))
	}
	return clitable.Parts(formatRatio(ratio), " (", fmt.Sprint(failed), "/", fmt.Sprintf("%d)", total))
}

func failureCell(startedAt time.Time, duration time.Duration) clitable.Cell {
	if startedAt.IsZero() {
		return clitable.Parts("-")
	}
	return clitable.Parts(formatAgo(startedAt), " / ", failureDuration(duration))
}

func failureDuration(duration time.Duration) string {
	if duration <= 0 {
		return "0s"
	}
	return formatUptime(duration)
}

func bitRatePairParts(average, maximum uint64) (string, string) {
	averageValue, averageUnit := formatBitRateParts(average)
	maximumValue, maximumUnit := formatBitRateParts(maximum)
	if averageUnit == maximumUnit {
		averageUnit = ""
	}
	return averageValue + averageUnit, maximumValue + maximumUnit
}

func trafficCell(value api.PathStats) clitable.Cell {
	if !hasTrafficHistory(value) {
		return clitable.Parts("-")
	}
	upload, download := value.History.UploadBytesPerSecond, value.History.DownloadBytesPerSecond
	uploadMax, downloadMax := trafficMaximum(upload), trafficMaximum(download)
	scale := max(uploadMax, downloadMax)
	upAverage, upMaximum := bitRatePairParts(trafficAverage(upload), uploadMax)
	downAverage, downMaximum := bitRatePairParts(trafficAverage(download), downloadMax)
	return clitable.Parts("↑"+trafficSparkline(upload, scale)+" ", upAverage, "/", upMaximum,
		" ↓"+trafficSparkline(download, scale)+" ", downAverage, "/", downMaximum)
}

func trafficTotalCell(value api.PathStats) clitable.Cell {
	if value.UploadBytes == 0 && value.DownloadBytes == 0 {
		return clitable.Parts("-")
	}
	return clitable.Parts("↑", formatBytes(value.UploadBytes), " ↓", formatBytes(value.DownloadBytes))
}
