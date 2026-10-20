/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/prometheus/client_golang/prometheus"
)

type storeMetrics struct {
	dialDuration *prometheus.HistogramVec
	errors       *prometheus.CounterVec
}

func newStoreMetrics() storeMetrics {
	return storeMetrics{
		dialDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "dae_dial_duration_seconds",
			Help:    "Duration of outbound dial attempts in seconds.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		}, pathLabels),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dae_path_errors_total",
			Help: "Cumulative errors encountered on an outbound path.",
		}, pathLabels),
	}
}

func (m *storeMetrics) describe(ch chan<- *prometheus.Desc) {
	for _, collector := range []prometheus.Collector{
		m.dialDuration,
		m.errors,
	} {
		collector.Describe(ch)
	}
}

func (m *storeMetrics) collect(ch chan<- prometheus.Metric) {
	m.dialDuration.Collect(ch)
	m.errors.Collect(ch)
}

var (
	processConnectionsDesc = prometheus.NewDesc("dae_process_connections_total", "Process-lifetime established connections, including retired paths.", []string{"network"}, nil)
	processTrafficDesc     = prometheus.NewDesc("dae_process_traffic_bytes_total", "Process-lifetime payload bytes, including retired paths.", []string{"network", "direction"}, nil)
	pathLabels             = []string{"id", "outbound", "subtag", "dialer", "network"}
	trafficLabels          = []string{"id", "outbound", "subtag", "dialer", "network", "direction"}

	activeConnectionsDesc = prometheus.NewDesc(
		"dae_active_connections",
		"Current number of established traffic connections.",
		pathLabels,
		nil,
	)
	totalConnectionsDesc = prometheus.NewDesc(
		"dae_connections_total",
		"Cumulative number of established traffic connections.",
		pathLabels,
		nil,
	)
	fallbackConnectionsDesc = prometheus.NewDesc(
		"dae_fallback_connections_total",
		"Cumulative number of established connections falling back to direct when no proxy node is available.",
		nil,
		nil,
	)
	trafficBytesDesc = prometheus.NewDesc(
		"dae_traffic_bytes_total",
		"Payload bytes transferred by established traffic connections.",
		trafficLabels,
		nil,
	)
	externalCounterErrorsDesc = prometheus.NewDesc(
		"dae_external_counter_read_errors_total",
		"Cumulative failures reading externally maintained traffic counters.",
		nil,
		nil,
	)
	processTimestampDesc = prometheus.NewDesc(
		"dae_process_timestamp_seconds",
		"Unix timestamp of a process lifecycle event.",
		[]string{"event"},
		nil,
	)
)

func (s *Store) Describe(ch chan<- *prometheus.Desc) {
	for _, descriptor := range []*prometheus.Desc{
		activeConnectionsDesc,
		processConnectionsDesc, processTrafficDesc,
		totalConnectionsDesc,
		fallbackConnectionsDesc,
		trafficBytesDesc,
		externalCounterErrorsDesc,
		processTimestampDesc,
	} {
		ch <- descriptor
	}
	s.availabilityStore.describe(ch)
	s.metrics.describe(ch)
}

func pathLabelValues(path Path) []string {
	return []string{path.NodeID, path.Outbound, path.Subtag, path.Dialer, path.Network.String()}
}

func (s *Store) RecordDial(path Path, elapsed time.Duration) {
	s.pathsMu.Lock()
	defer s.pathsMu.Unlock()
	counters := s.pathCountersLocked(path)
	s.track(counters)
	s.metrics.dialDuration.WithLabelValues(pathLabelValues(path)...).Observe(elapsed.Seconds())
}

func (s *Store) RecordError(path Path) {
	s.pathsMu.Lock()
	defer s.pathsMu.Unlock()
	counters := s.pathCountersLocked(path)
	s.track(counters)
	s.metrics.errors.WithLabelValues(pathLabelValues(path)...).Inc()
}

func boolValue(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func unixSeconds(value time.Time) float64 {
	if value.IsZero() {
		return 0
	}
	return float64(value.UnixNano()) / float64(time.Second)
}

func (s *Store) collectConnections(ch chan<- prometheus.Metric) {
	fallback := s.DirectFallbackConnections()
	snapshot := s.snapshot(false)
	ch <- prometheus.MustNewConstMetric(fallbackConnectionsDesc, prometheus.CounterValue, float64(fallback))
	for network, values := range snapshot.Networks {
		name := common.NetworkIndex(network).String()
		ch <- prometheus.MustNewConstMetric(processConnectionsDesc, prometheus.CounterValue, float64(values.TotalConnections), name)
		ch <- prometheus.MustNewConstMetric(processTrafficDesc, prometheus.CounterValue, float64(values.UploadBytes), name, trafficDirectionUpload)
		ch <- prometheus.MustNewConstMetric(processTrafficDesc, prometheus.CounterValue, float64(values.DownloadBytes), name, trafficDirectionDownload)
	}
	for path, stats := range snapshot.Paths {
		labels := pathLabelValues(path)
		ch <- prometheus.MustNewConstMetric(activeConnectionsDesc, prometheus.GaugeValue, float64(stats.ActiveConnections), labels...)
		ch <- prometheus.MustNewConstMetric(totalConnectionsDesc, prometheus.CounterValue, float64(stats.TotalConnections), labels...)
		ch <- prometheus.MustNewConstMetric(trafficBytesDesc, prometheus.CounterValue, float64(stats.UploadBytes),
			path.NodeID, path.Outbound, path.Subtag, path.Dialer, path.Network.String(), trafficDirectionUpload)
		ch <- prometheus.MustNewConstMetric(trafficBytesDesc, prometheus.CounterValue, float64(stats.DownloadBytes),
			path.NodeID, path.Outbound, path.Subtag, path.Dialer, path.Network.String(), trafficDirectionDownload)
	}
}

func (s *Store) collectProcess(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(processTimestampDesc, prometheus.GaugeValue, unixSeconds(s.startedAt), "start")
	lastReload := s.lastReload.Load()
	ch <- prometheus.MustNewConstMetric(processTimestampDesc, prometheus.GaugeValue, float64(lastReload), "reload")
	ch <- prometheus.MustNewConstMetric(externalCounterErrorsDesc, prometheus.CounterValue, float64(s.externalReadErrors.Load()))
}

func (s *Store) Collect(ch chan<- prometheus.Metric) {
	s.collectConnections(ch)
	s.availabilityStore.collect(ch)
	s.collectProcess(ch)
	s.metrics.collect(ch)
}
