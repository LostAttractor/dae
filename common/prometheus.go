package common

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// CoreIpDomainBitmap prometheus.Gauge
	// DeadlineTimers     *prometheus.GaugeVec
	// DnsCacheSize       prometheus.Gauge
	// DnsCacheHit        *prometheus.CounterVec

	// The metrics below are periodically overwritten by the health-check
	// loop, so they are reset on control-plane reload to drop series of
	// removed nodes/dialers.
	CheckLatency       *prometheus.GaugeVec
	CheckMovingLatency *prometheus.GaugeVec
	CheckSelectLatency *prometheus.GaugeVec
	DialerSelectIndex  *prometheus.GaugeVec

	// The metrics below keep process-lifetime values and are not reset on
	// control-plane reload, because what they measure also survives reloads
	// (e.g. connections outlive the control plane that accepted them).
	ActiveConnections *prometheus.GaugeVec
	DialLatency       *prometheus.HistogramVec
	ErrorCount        *prometheus.CounterVec
	// TrafficBytes       *prometheus.CounterVec
	// VmRssKb            prometheus.Gauge

	TotalConnections *prometheus.CounterVec

	// Node/group availability metrics are the single source of truth for
	// the single-value availability state (current aliveness and event
	// timestamps); common/stats stores this state only in these gauges.
	// Node-level series carry an "id" label (a hash of the node identity)
	// so that nodes sharing the same (subtag, dialer) display labels do
	// not alias each other's state.
	NodeAlive           *prometheus.GaugeVec
	NodeAliveSince      *prometheus.GaugeVec
	NodeLastFailure     *prometheus.GaugeVec
	NodeLastCheck       *prometheus.GaugeVec
	NodeLastConnFailure *prometheus.GaugeVec
	// Node check counters: one increment per connectivity check (each check
	// also appends one latency sample, so they double as sample counts).
	NodeChecksTotal        *prometheus.CounterVec
	NodeCheckFailures      *prometheus.CounterVec
	NodeChecksSinceAlive   *prometheus.GaugeVec
	NodeChecksSinceFailure *prometheus.GaugeVec
	GroupAlive             *prometheus.GaugeVec
	GroupAliveSince        *prometheus.GaugeVec
	GroupLastFailure       *prometheus.GaugeVec

	StartTime      prometheus.Gauge
	LastReloadTime prometheus.Gauge
)

// newMetrics constructs all metric collectors. It is called once at package
// init so that the collectors are never nil (e.g., in tests that do not build
// a control plane).
func newMetrics() {
	labels := []string{"id", "outbound", "subtag", "dialer", "network"}
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
	TotalConnections = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dae_total_connections",
		},
		labels,
	)
	nodeLabels := []string{"id", "subtag", "dialer"}
	NodeAlive = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_node_alive",
		},
		nodeLabels,
	)
	NodeAliveSince = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_node_alive_since_timestamp_seconds",
		},
		nodeLabels,
	)
	NodeLastFailure = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_node_last_failure_timestamp_seconds",
		},
		nodeLabels,
	)
	NodeLastCheck = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_node_last_check_timestamp_seconds",
		},
		nodeLabels,
	)
	NodeLastConnFailure = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_node_last_conn_failure_timestamp_seconds",
		},
		nodeLabels,
	)
	NodeChecksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dae_node_checks_total",
		},
		nodeLabels,
	)
	NodeCheckFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dae_node_check_failures_total",
		},
		nodeLabels,
	)
	NodeChecksSinceAlive = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_node_checks_since_alive",
		},
		nodeLabels,
	)
	NodeChecksSinceFailure = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_node_checks_since_failure",
		},
		nodeLabels,
	)
	groupLabels := []string{"outbound", "network"}
	GroupAlive = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_group_alive",
		},
		groupLabels,
	)
	GroupAliveSince = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_group_alive_since_timestamp_seconds",
		},
		groupLabels,
	)
	GroupLastFailure = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_group_last_failure_timestamp_seconds",
		},
		groupLabels,
	)
	StartTime = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dae_start_time_seconds",
		},
	)
	StartTime.SetToCurrentTime()
	LastReloadTime = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dae_last_reload_timestamp_seconds",
		},
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
}

func init() {
	newMetrics()
}

func InitPrometheus(registry *prometheus.Registry) {
	// Building a candidate control plane must not mutate process-global
	// metrics: the candidate may fail validation while the current plane is
	// still serving. Reload-scoped gauges are reset later, during Activate.
	for _, c := range []prometheus.Collector{
		// registry.MustRegister(CoreIpDomainBitmap)
		// registry.MustRegister(DeadlineTimers)
		// registry.MustRegister(DnsCacheSize)
		// registry.MustRegister(DnsCacheHit)
		ActiveConnections,
		CheckLatency,
		CheckMovingLatency,
		CheckSelectLatency,
		DialerSelectIndex,
		DialLatency,
		ErrorCount,
		TotalConnections,
		NodeAlive,
		NodeAliveSince,
		NodeLastFailure,
		NodeLastCheck,
		NodeLastConnFailure,
		NodeChecksTotal,
		NodeCheckFailures,
		NodeChecksSinceAlive,
		NodeChecksSinceFailure,
		GroupAlive,
		GroupAliveSince,
		GroupLastFailure,
		StartTime,
		LastReloadTime,
		// registry.MustRegister(TrafficBytes)
		// registry.MustRegister(VmRssKb)
	} {
		registry.MustRegister(c)
	}
}

// ResetReloadMetrics drops gauges that the newly activated health-check
// loops will repopulate. Connection gauges, counters and histograms retain
// process-lifetime values because active connections can outlive a reload.
func ResetReloadMetrics() {
	for _, vec := range []*prometheus.GaugeVec{
		CheckLatency,
		CheckMovingLatency,
		CheckSelectLatency,
		DialerSelectIndex,
	} {
		vec.Reset()
	}
}
