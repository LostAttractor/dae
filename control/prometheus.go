package control

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	ActiveConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dae_active_connections",
			Help: "Number of active connections",
		},
	)
	ActiveConnectionsTCP = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dae_active_connections_tcp",
			Help: "Number of active TCP connections",
		},
	)
	ActiveConnectionsUDP = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dae_active_connections_udp",
			Help: "Number of active UDP connections",
		},
	)
	TotalConnections = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dae_total_connections",
			Help: "Total number of connections handled",
		},
	)
	DialLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dae_dial_latency_seconds",
			Help:    "Dial latency in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15), // 1ms ~ ~16s
		},
	)
)

func init() {
	prometheus.MustRegister(ActiveConnections)
	prometheus.MustRegister(ActiveConnectionsTCP)
	prometheus.MustRegister(ActiveConnectionsUDP)
	prometheus.MustRegister(TotalConnections)
	prometheus.MustRegister(DialLatency)
}
