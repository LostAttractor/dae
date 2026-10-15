package direct

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	DirectDialLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dae_direct_dial_latency_seconds",
			Help:    "Direct Dialer Dial latency in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 17), // 1ms ~ ~64s
		},
	)
)

func init() {
	prometheus.MustRegister(DirectDialLatency)
}
