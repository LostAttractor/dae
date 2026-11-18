// SPDX-License-Identifier: AGPL-3.0-only
package daemon

import (
	"net/http"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/control"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	metricsRegistry = prometheus.NewRegistry()
	pluginMetrics   mitm.Metrics
)

func init() { metricsRegistry.MustRegister(stats.DefaultStore) }

type registryMetrics struct {
	usage func() (control.RegistryUsage, bool)
}

var (
	registryPairs      = prometheus.NewDesc("dae_domain_registry_pairs", "Current retained DNS domain-IP pairs.", nil, nil)
	registryMemory     = prometheus.NewDesc("dae_domain_registry_estimated_bytes", "Estimated bytes of retained DNS domain-IP history, not process memory usage.", nil, nil)
	registryLimit      = prometheus.NewDesc("dae_domain_registry_memory_limit_bytes", "Configured budget for estimated retained DNS domain-IP history bytes.", nil, nil)
	registryIncomplete = prometheus.NewDesc("dae_domain_registry_incomplete_buckets", "Current buckets with incomplete pair history.", nil, nil)
	registryOmissions  = prometheus.NewDesc("dae_domain_registry_pair_omissions_total", "DNS domain-IP pair omission events since startup.", nil, nil)
)

func (m registryMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- registryPairs
	ch <- registryMemory
	ch <- registryLimit
	ch <- registryIncomplete
	ch <- registryOmissions
}

func (m registryMetrics) Collect(ch chan<- prometheus.Metric) {
	usage, ok := m.usage()
	if !ok {
		return
	}
	ch <- prometheus.MustNewConstMetric(registryPairs, prometheus.GaugeValue, float64(usage.UserUsed))
	ch <- prometheus.MustNewConstMetric(registryMemory, prometheus.GaugeValue, float64(usage.MemoryUsed))
	ch <- prometheus.MustNewConstMetric(registryLimit, prometheus.GaugeValue, float64(usage.MemoryLimit))
	ch <- prometheus.MustNewConstMetric(registryIncomplete, prometheus.GaugeValue, float64(usage.IncompleteBuckets))
	ch <- prometheus.MustNewConstMetric(registryOmissions, prometheus.CounterValue, float64(usage.OmittedPairs))
}

func newRuntimeMetricsHandler(usage func() (control.RegistryUsage, bool)) http.Handler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(registryMetrics{usage: usage})
	return promhttp.HandlerFor(prometheus.Gatherers{metricsRegistry, &pluginMetrics, registry}, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError})
}
