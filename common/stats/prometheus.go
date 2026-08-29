/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type storeMetrics struct {
	checkLatency  *prometheus.GaugeVec
	selectionRank *prometheus.GaugeVec
	dialDuration  *prometheus.HistogramVec
	errors        *prometheus.CounterVec
}

func newStoreMetrics() storeMetrics {
	return storeMetrics{
		checkLatency: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "dae_check_latency_seconds",
			Help: "Connectivity-check latency in seconds by sample type.",
		}, checkLatencyLabels),
		selectionRank: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "dae_selection_rank",
			Help: "Current selection rank of an outbound path.",
		}, pathLabels),
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
		m.checkLatency,
		m.selectionRank,
		m.dialDuration,
		m.errors,
	} {
		collector.Describe(ch)
	}
}

func (m *storeMetrics) collect(ch chan<- prometheus.Metric) {
	m.checkLatency.Collect(ch)
	m.selectionRank.Collect(ch)
	m.dialDuration.Collect(ch)
	m.errors.Collect(ch)
}

func (m *storeMetrics) resetCurrent() {
	m.checkLatency.Reset()
	m.selectionRank.Reset()
}

var (
	pathLabels         = []string{"id", "outbound", "subtag", "dialer", "network"}
	checkLatencyLabels = []string{"id", "outbound", "subtag", "dialer", "network", "sample"}
	nodeLabels         = []string{"id", "subtag", "dialer"}
	nodeEventLabels    = []string{"id", "subtag", "dialer", "event"}
	nodeResultLabels   = []string{"id", "subtag", "dialer", "result"}
	trafficLabels      = []string{"id", "outbound", "subtag", "dialer", "network", "direction"}

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
	externalCounterCollectionErrorDesc = prometheus.NewDesc(
		"dae_external_counter_collection_error",
		"Error refreshing externally maintained traffic counters.",
		nil,
		nil,
	)
	nodeAliveDesc = prometheus.NewDesc(
		"dae_node_alive",
		"Whether the node is currently considered alive.",
		nodeLabels,
		nil,
	)
	nodeTimestampDesc = prometheus.NewDesc(
		"dae_node_timestamp_seconds",
		"Unix timestamp of a node availability event.",
		nodeEventLabels,
		nil,
	)
	nodeChecksDesc = prometheus.NewDesc(
		"dae_node_checks_total",
		"Cumulative node connectivity checks by result.",
		nodeResultLabels,
		nil,
	)
	nodeChecksSinceAliveDesc = prometheus.NewDesc(
		"dae_node_checks_since_alive",
		"Number of connectivity checks since the node most recently became alive.",
		nodeLabels,
		nil,
	)
	groupAvailableDesc = prometheus.NewDesc(
		"dae_group_available",
		"Whether the outbound group is currently available.",
		[]string{"outbound"},
		nil,
	)
	groupTimestampDesc = prometheus.NewDesc(
		"dae_group_timestamp_seconds",
		"Unix timestamp of an outbound group availability event.",
		[]string{"outbound", "event"},
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
		totalConnectionsDesc,
		trafficBytesDesc,
		externalCounterErrorsDesc,
		externalCounterCollectionErrorDesc,
		nodeAliveDesc,
		nodeTimestampDesc,
		nodeChecksDesc,
		nodeChecksSinceAliveDesc,
		groupAvailableDesc,
		groupTimestampDesc,
		processTimestampDesc,
	} {
		ch <- descriptor
	}
	s.metrics.describe(ch)
}

func pathLabelValues(path Path) []string {
	return []string{path.NodeID, path.Outbound, path.Subtag, path.Dialer, path.Network.String()}
}

func (s *Store) RecordCheckMetrics(path Path, check, moving, selection time.Duration) {
	labels := pathLabelValues(path)
	s.metrics.checkLatency.WithLabelValues(append(labels, "last")...).Set(check.Seconds())
	if moving > 0 {
		s.metrics.checkLatency.WithLabelValues(append(labels, "moving")...).Set(moving.Seconds())
	}
	if selection > 0 {
		s.metrics.checkLatency.WithLabelValues(append(labels, "selection")...).Set(selection.Seconds())
	}
}

func (s *Store) RecordSelectionIndex(path Path, index int) {
	s.metrics.selectionRank.WithLabelValues(pathLabelValues(path)...).Set(float64(index))
}

func (s *Store) RecordDial(path Path, elapsed time.Duration) {
	s.metrics.dialDuration.WithLabelValues(pathLabelValues(path)...).Observe(elapsed.Seconds())
}

func (s *Store) RecordError(path Path) {
	s.metrics.errors.WithLabelValues(pathLabelValues(path)...).Inc()
}

func (s *Store) resetCurrentMetrics() {
	s.metrics.resetCurrent()
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
	snapshot, err := s.Snapshot()
	if err != nil {
		ch <- prometheus.NewInvalidMetric(externalCounterCollectionErrorDesc, err)
		return
	}
	for path, stats := range snapshot {
		labels := pathLabelValues(path)
		ch <- prometheus.MustNewConstMetric(activeConnectionsDesc, prometheus.GaugeValue, float64(stats.ActiveConnections), labels...)
		ch <- prometheus.MustNewConstMetric(totalConnectionsDesc, prometheus.CounterValue, float64(stats.TotalConnections), labels...)
		ch <- prometheus.MustNewConstMetric(trafficBytesDesc, prometheus.CounterValue, float64(stats.UploadBytes),
			path.NodeID, path.Outbound, path.Subtag, path.Dialer, path.Network.String(), trafficDirectionUpload)
		ch <- prometheus.MustNewConstMetric(trafficBytesDesc, prometheus.CounterValue, float64(stats.DownloadBytes),
			path.NodeID, path.Outbound, path.Subtag, path.Dialer, path.Network.String(), trafficDirectionDownload)
	}
}

func (s *Store) collectAvailability(ch chan<- prometheus.Metric) {
	type nodeSnapshot struct {
		key string
		NodeIdentity
		Availability
	}
	type groupSnapshot struct {
		name string
		Availability
	}

	s.availabilityMu.Lock()
	now := time.Now()
	nodes := make([]nodeSnapshot, 0, len(s.nodes))
	for key, availability := range s.nodes {
		snapshot := availability.snapshot(now)
		if snapshot.Seen {
			nodes = append(nodes, nodeSnapshot{key, availability.NodeIdentity, snapshot})
		}
	}
	groups := make([]groupSnapshot, 0, len(s.groups))
	for name, group := range s.groups {
		snapshot := group.snapshot(now)
		if snapshot.Seen {
			groups = append(groups, groupSnapshot{name, snapshot})
		}
	}
	s.availabilityMu.Unlock()

	for _, snapshot := range nodes {
		labels := []string{NodeID(snapshot.key), snapshot.Subtag, snapshot.Name}
		ch <- prometheus.MustNewConstMetric(nodeAliveDesc, prometheus.GaugeValue, boolValue(snapshot.Alive), labels...)
		ch <- prometheus.MustNewConstMetric(nodeTimestampDesc, prometheus.GaugeValue, unixSeconds(snapshot.AliveSince), append(labels, "alive_since")...)
		ch <- prometheus.MustNewConstMetric(nodeTimestampDesc, prometheus.GaugeValue, unixSeconds(snapshot.LastFailureStartedAt), append(labels, "failure_started")...)
		ch <- prometheus.MustNewConstMetric(nodeTimestampDesc, prometheus.GaugeValue, unixSeconds(snapshot.LastCheckAt), append(labels, "last_check")...)
		ch <- prometheus.MustNewConstMetric(nodeTimestampDesc, prometheus.GaugeValue, unixSeconds(snapshot.LastConnFailAt), append(labels, "last_connection_failure")...)
		ch <- prometheus.MustNewConstMetric(nodeChecksDesc, prometheus.CounterValue, float64(snapshot.ChecksTotal-snapshot.ChecksFailed), append(labels, "success")...)
		ch <- prometheus.MustNewConstMetric(nodeChecksDesc, prometheus.CounterValue, float64(snapshot.ChecksFailed), append(labels, "failure")...)
		ch <- prometheus.MustNewConstMetric(nodeChecksSinceAliveDesc, prometheus.GaugeValue, float64(snapshot.ChecksSinceAlive), labels...)
	}

	for _, snapshot := range groups {
		ch <- prometheus.MustNewConstMetric(groupAvailableDesc, prometheus.GaugeValue, boolValue(snapshot.Alive), snapshot.name)
		ch <- prometheus.MustNewConstMetric(groupTimestampDesc, prometheus.GaugeValue, unixSeconds(snapshot.AliveSince), snapshot.name, "available_since")
		ch <- prometheus.MustNewConstMetric(groupTimestampDesc, prometheus.GaugeValue, unixSeconds(snapshot.LastFailureStartedAt), snapshot.name, "failure_started")
	}

	ch <- prometheus.MustNewConstMetric(processTimestampDesc, prometheus.GaugeValue, unixSeconds(s.startedAt), "start")
	lastReload := s.lastReload.Load()
	ch <- prometheus.MustNewConstMetric(processTimestampDesc, prometheus.GaugeValue, float64(lastReload), "reload")
	ch <- prometheus.MustNewConstMetric(externalCounterErrorsDesc, prometheus.CounterValue, float64(s.externalReadErrors.Load()))
}

func (s *Store) Collect(ch chan<- prometheus.Metric) {
	s.collectConnections(ch)
	s.collectAvailability(ch)
	s.metrics.collect(ch)
}
