// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"slices"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
)

// SelectionMetrics uses the same runtime measurements and candidate scoring as
// status and routing. Rank sorting belongs to scrapes, not each probe update.
func (g *DialerGroup) SelectionMetrics() []stats.SelectionMetrics {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed.Load() || !g.ChecksConnectivity() {
		return nil
	}
	automatic := g.selectionPolicy.Automatic()
	metrics := make([]stats.SelectionMetrics, 0, len(g.Dialers)*common.NetworkTypeCount)
	type rankedCandidate struct {
		candidate selectorCandidate
		metric    int
	}
	var candidates [common.NetworkTypeCount][]rankedCandidate
	for _, d := range g.Dialers {
		runtime := d.RuntimeStatus()
		var candidate selectorCandidate
		if automatic {
			candidate = g.scoreCandidate(d, runtime.Latency, runtime.Degraded)
		}
		for network, support := range runtime.SupportState {
			if support != api.NetworkSupportConfirmed {
				continue
			}
			if automatic && runtime.Healthy {
				candidates[network] = append(candidates[network], rankedCandidate{candidate, len(metrics)})
			}
			metrics = append(metrics, stats.SelectionMetrics{
				Path:    d.StatsPath(g.Name, common.NetworkIndex(network).NetworkType()),
				Latency: runtime.Latency, HasLatency: runtime.HasLatency,
				Score: candidate.sortingLatency, HasScore: automatic && runtime.HasLatency,
			})
		}
	}
	for _, network := range candidates {
		slices.SortStableFunc(network, func(a, b rankedCandidate) int { return compareCandidates(a.candidate, b.candidate) })
		for rank, candidate := range network {
			metrics[candidate.metric].Rank, metrics[candidate.metric].Ranked = rank, true
		}
	}
	return metrics
}
