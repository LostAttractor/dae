// SPDX-License-Identifier: AGPL-3.0-only
package daemon

import (
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	metricsRegistry = prometheus.NewRegistry()
	pluginMetrics   mitm.Metrics
	metricsHandler  = promhttp.HandlerFor(prometheus.Gatherers{metricsRegistry, &pluginMetrics}, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError})
)

func init() { metricsRegistry.MustRegister(stats.DefaultStore) }
