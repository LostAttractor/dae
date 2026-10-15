// SPDX-License-Identifier: AGPL-3.0-only

package surge

import "github.com/prometheus/client_golang/prometheus"

type runtimeMetrics struct {
	runtime                                                       *Runtime
	info, workers, limit, started, reused, startFailures, retired *prometheus.Desc
	rss, pss, sampledWorkers, sampledAt, idleTimeout              *prometheus.Desc
}

func newRuntimeMetrics(r *Runtime) *runtimeMetrics {
	desc := func(name, help string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc("surge_"+name, help, labels, nil)
	}
	return &runtimeMetrics{
		runtime:        r,
		info:           desc("runtime_info", "Compiled Surge JavaScript backend.", "backend"),
		workers:        desc("nodejs_workers", "Node.js workers by lease state; active includes startup and waiting for host I/O.", "state"),
		limit:          desc("nodejs_worker_limit", "Maximum Node.js workers in this instance."),
		started:        desc("nodejs_worker_starts_total", "Successfully spawned application workers, excluding startup probes."),
		reused:         desc("nodejs_worker_reuses_total", "Application leases acquired from idle workers."),
		startFailures:  desc("nodejs_worker_start_failures_total", "Application worker spawn failures."),
		retired:        desc("nodejs_worker_retirements_total", "Workers retired after idle timeout or failed/canceled execution; excludes probes and shutdown.", "reason"),
		rss:            desc("nodejs_rss_bytes", "Sum of cached worker RSS samples; shared pages may be counted more than once."),
		pss:            desc("nodejs_pss_bytes", "Sum of cached worker PSS samples, proportionally accounting for shared pages."),
		sampledWorkers: desc("nodejs_memory_sampled_workers", "Current workers included in cached RSS/PSS sums."),
		sampledAt:      desc("nodejs_memory_sample_timestamp_seconds", "Oldest memory sample included in the sums, or zero if none."),
		idleTimeout:    desc("nodejs_idle_timeout_seconds", "Idle timeout for excess workers; one idle worker is kept warm."),
	}
}

func (m *runtimeMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.info
	if compiledJSRuntime == "nodejs" {
		for _, desc := range []*prometheus.Desc{m.workers, m.limit, m.started, m.reused, m.startFailures, m.retired, m.rss, m.pss, m.sampledWorkers, m.sampledAt, m.idleTimeout} {
			ch <- desc
		}
	}
}

func (m *runtimeMetrics) Collect(ch chan<- prometheus.Metric) {
	s := m.runtime.backend.status()
	ch <- prometheus.MustNewConstMetric(m.info, prometheus.GaugeValue, 1, s.Backend)
	n := s.NodeJS
	if n == nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(m.workers, prometheus.GaugeValue, float64(n.Active), "active")
	ch <- prometheus.MustNewConstMetric(m.workers, prometheus.GaugeValue, float64(n.Idle), "idle")
	ch <- prometheus.MustNewConstMetric(m.limit, prometheus.GaugeValue, float64(n.Limit))
	ch <- prometheus.MustNewConstMetric(m.started, prometheus.CounterValue, float64(n.Started))
	ch <- prometheus.MustNewConstMetric(m.reused, prometheus.CounterValue, float64(n.Reused))
	ch <- prometheus.MustNewConstMetric(m.startFailures, prometheus.CounterValue, float64(n.StartFailures))
	ch <- prometheus.MustNewConstMetric(m.retired, prometheus.CounterValue, float64(n.IdleReaped), "idle")
	ch <- prometheus.MustNewConstMetric(m.retired, prometheus.CounterValue, float64(n.Discarded), "failed")
	ch <- prometheus.MustNewConstMetric(m.rss, prometheus.GaugeValue, float64(n.RSSBytes))
	ch <- prometheus.MustNewConstMetric(m.pss, prometheus.GaugeValue, float64(n.PSSBytes))
	ch <- prometheus.MustNewConstMetric(m.sampledWorkers, prometheus.GaugeValue, float64(n.MemorySampledWorkers))
	var sampledAt float64
	if !n.MemorySampledAt.IsZero() {
		sampledAt = float64(n.MemorySampledAt.UnixNano()) / 1e9
	}
	ch <- prometheus.MustNewConstMetric(m.sampledAt, prometheus.GaugeValue, sampledAt)
	ch <- prometheus.MustNewConstMetric(m.idleTimeout, prometheus.GaugeValue, n.IdleTimeoutSeconds)
}
