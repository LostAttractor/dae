// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/daeuniverse/dae/api"
)

func renderSurgeRuntimes(runtimes []api.SurgeRuntimeStatus) string {
	var lines []string
	for _, runtime := range runtimes {
		lines = append(lines, fmt.Sprintf("Surge runtime %s: %s", runtime.Instance, runtime.Backend))
		n := runtime.NodeJS
		if n == nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("  Workers: active=%d idle=%d limit=%d; idle timeout=%gs", n.Active, n.Idle, n.Limit, n.IdleTimeoutSeconds))
		memory := fmt.Sprintf("RSS=%.1f MiB PSS=%.1f MiB", float64(n.RSSBytes)/(1<<20), float64(n.PSSBytes)/(1<<20))
		if n.MemorySampledWorkers == 0 && n.Active+n.Idle > 0 {
			memory = "RSS/PSS unavailable"
		}
		lines = append(lines, "  Memory: "+memory)
		sampleAge := "-"
		if !n.MemorySampledAt.IsZero() {
			sampleAge = max(0, time.Since(n.MemorySampledAt)).Round(time.Second).String() + " ago"
		}
		lines = append(lines, fmt.Sprintf("  Sample: %d/%d workers; oldest=%s", n.MemorySampledWorkers, n.Active+n.Idle, sampleAge),
			fmt.Sprintf("  Pool: started=%d reused=%d start errors=%d", n.Started, n.Reused, n.StartFailures),
			fmt.Sprintf("  Retired: idle=%d failed/canceled=%d", n.IdleReaped, n.Discarded))
	}
	return strings.Join(lines, "\n")
}

func printSurgeRuntimes(out io.Writer, instances []api.PluginInstanceStatus) {
	report, err := Surge(instances)
	if err != nil {
		writeStatusLine(out, "Surge runtime: "+err.Error(), getStatusTerminalWidth())
		return
	}
	if len(report.Runtimes) == 0 {
		return
	}
	fmt.Fprintln(out)
	for line := range strings.SplitSeq(renderSurgeRuntimes(report.Runtimes), "\n") {
		writeStatusLine(out, line, getStatusTerminalWidth())
	}
}
