// SPDX-License-Identifier: AGPL-3.0-only

package stats

import (
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/prometheus/client_golang/prometheus"
)

// SelectionMetrics is a read-only projection of current runtime measurements
// and policy scores. Unmeasured paths and ineligible ranks remain absent.
type SelectionMetrics struct {
	Path       Path
	Latency    api.LatencyStats
	HasLatency bool
	Score      time.Duration
	HasScore   bool
	Rank       int
	Ranked     bool
}

type SelectionMetricsSource interface {
	SelectionMetrics() []SelectionMetrics
}

var (
	checkLatencyLabels = []string{"id", "outbound", "subtag", "dialer", "network", "sample"}

	checkLatencyDesc = prometheus.NewDesc("dae_check_latency_seconds",
		"Connectivity-check latency in seconds by sample type.", checkLatencyLabels, nil)
	selectionRankDesc = prometheus.NewDesc("dae_selection_rank",
		"Current selection rank of an outbound path.", pathLabels, nil)
	selectionScoreDesc = prometheus.NewDesc("dae_selection_score_seconds",
		"Policy latency plus configured offset; may be negative and is not measured latency.", pathLabels, nil)
)

func (s *availabilityStore) collectSelections(ch chan<- prometheus.Metric) {
	s.mu.Lock()
	sources := s.selections // Reconcile replaces this immutable slice.
	s.mu.Unlock()
	// Never call a runtime source with the store lock held: snapshots can also
	// read availability, and connectivity publication goes in the other direction.
	for _, source := range sources {
		for _, snapshot := range source.SelectionMetrics() {
			labels := pathLabelValues(snapshot.Path)
			if snapshot.HasLatency {
				ch <- prometheus.MustNewConstMetric(checkLatencyDesc, prometheus.GaugeValue, snapshot.Latency.Last.Seconds(), append(labels, "last")...)
				ch <- prometheus.MustNewConstMetric(checkLatencyDesc, prometheus.GaugeValue, snapshot.Latency.MovingAvg.Seconds(), append(labels, "moving")...)
			}
			if snapshot.HasScore {
				ch <- prometheus.MustNewConstMetric(selectionScoreDesc, prometheus.GaugeValue, snapshot.Score.Seconds(), labels...)
			}
			if snapshot.Ranked {
				ch <- prometheus.MustNewConstMetric(selectionRankDesc, prometheus.GaugeValue, float64(snapshot.Rank), labels...)
			}
		}
	}
}
