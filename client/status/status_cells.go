// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"fmt"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/pkg/clitable"
)

func formatConnCounts(value api.PathStats) clitable.Cell {
	return clitable.Parts(fmt.Sprint(value.ActiveConnections), "/", fmt.Sprint(value.TotalConnections))
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
