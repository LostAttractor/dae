package common

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	ActiveConnections *prometheus.GaugeVec
	// CoreIpDomainBitmap prometheus.Gauge
	// DeadlineTimers     prometheus.Gauge
	// DnsCacheSize       prometheus.Gauge
	// DnsCacheHit        *prometheus.CounterVec
	CheckLatency       *prometheus.GaugeVec
	CheckMovingLatency *prometheus.GaugeVec
	CheckSelectLatency *prometheus.GaugeVec
	DialerSelectIndex  *prometheus.GaugeVec
	DialLatency        *prometheus.HistogramVec
	ErrorCount         *prometheus.CounterVec
	// TrafficBytes       *prometheus.CounterVec
	// VmRssKb            prometheus.Gauge
)

func InitPrometheus(registry *prometheus.Registry) {
	labels := []string{"outbound", "subtag", "dialer", "network"}
	ActiveConnections = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_active_connections",
		},
		labels,
	)
	// CoreIpDomainBitmap = prometheus.NewGauge(
	// 	prometheus.GaugeOpts{
	// 		Name: "dae_ip_domain_bitmap",
	// 	},
	// )
	// DeadlineTimers = prometheus.NewGauge(
	// 	prometheus.GaugeOpts{
	// 		Name: "dae_deadline_timers",
	// 	},
	// )
	// DnsCacheSize = prometheus.NewGauge(
	// 	prometheus.GaugeOpts{
	// 		Name: "dae_dns_cache_size",
	// 	},
	// )
	// DnsCacheHit = prometheus.NewCounterVec(
	// 	prometheus.CounterOpts{
	// 		Name: "dae_dns_cache_hit",
	// 	},
	// 	[]string{"outbound", "qtype"},
	// )
	CheckLatency = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_check_latency",
		},
		labels,
	)
	CheckMovingLatency = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_check_moving_latency",
		},
		labels,
	)
	CheckSelectLatency = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_check_select_latency",
		},
		labels,
	)
	DialerSelectIndex = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_dialer_select_index",
		},
		labels,
	)
	DialLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "dae_dial_latency",
			Help:    "Dial latency in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15), // 1ms ~ ~16s
		},
		labels,
	)
	ErrorCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dae_error_count",
		},
		labels,
	)
	// TrafficBytes = prometheus.NewCounterVec(
	// 	prometheus.CounterOpts{
	// 		Name: "dae_traffic_bytes",
	// 	},
	// 	[]string{"outbound", "subtag", "network", "dst"}, //, "direction", "src"},
	// )
	// VmRssKb = prometheus.NewGauge(
	// 	prometheus.GaugeOpts{
	// 		Name: "dae_vm_rss_kb",
	// 	},
	// )
	registry.MustRegister(ActiveConnections)
	// registry.MustRegister(CoreIpDomainBitmap)
	// registry.MustRegister(DeadlineTimers)
	// registry.MustRegister(DnsCacheSize)
	// registry.MustRegister(DnsCacheHit)
	registry.MustRegister(CheckLatency)
	registry.MustRegister(CheckMovingLatency)
	registry.MustRegister(CheckSelectLatency)
	registry.MustRegister(DialerSelectIndex)
	registry.MustRegister(DialLatency)
	registry.MustRegister(ErrorCount)
	// registry.MustRegister(TrafficBytes)
	// registry.MustRegister(VmRssKb)
}
