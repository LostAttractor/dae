/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"slices"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/prometheus/client_golang/prometheus"
)

type availabilityMetrics struct {
	relayFailures    *prometheus.CounterVec
	resourceFailures *prometheus.CounterVec
	reconnects       *prometheus.CounterVec
	nodeUnavailable  *prometheus.CounterVec
}

func newAvailabilityMetrics() availabilityMetrics {
	return availabilityMetrics{
		relayFailures:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dae_relay_failures_total", Help: "Independent relay failure causes by bounded classification."}, []string{"id", "subtag", "dialer", "scope", "layer", "reason"}),
		resourceFailures: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dae_resource_failures_total", Help: "Authoritative shared resource failure episodes."}, nodeLabels),
		reconnects:       prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dae_reconnect_attempts_total", Help: "Background session connection requests by recovery executor."}, []string{"id", "subtag", "dialer", "executor"}),
		nodeUnavailable:  prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dae_node_unavailable_total", Help: "Transitions from available to unavailable."}, nodeLabels),
	}
}

func (s *availabilityStore) nodeMetricLabelsLocked(key string) []string {
	if node := s.nodes[key]; node != nil {
		return []string{NodeID(key), node.Subtag, node.Name}
	}
	return nil
}

func boundedFailureLabel(value string, allowed ...string) string {
	if slices.Contains(allowed, value) {
		return value
	}
	return "unknown"
}

func (s *availabilityStore) RecordRelayFailure(key, scope, layer, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	labels := s.nodeMetricLabelsLocked(key)
	if labels == nil {
		return
	}
	scope = boundedFailureLabel(scope, "operation", "stream", "shared_resource")
	layer = boundedFailureLabel(layer, "tcp", "udp", "tls", "quic", "h2", "h3", "grpc", "proxy", "smux", "anytls")
	reason = boundedFailureLabel(reason, "reset", "rejected", "capacity", "protocol", "deadline", "auth", "closed", "canceled")
	s.metrics.relayFailures.WithLabelValues(append(labels, scope, layer, reason)...).Inc()
}

func (s *availabilityStore) RecordResourceFailure(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if labels := s.nodeMetricLabelsLocked(key); labels != nil {
		s.metrics.resourceFailures.WithLabelValues(labels...).Inc()
	}
}

func (s *availabilityStore) RecordReconnectAttempt(key, executor string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if labels := s.nodeMetricLabelsLocked(key); labels != nil {
		executor = boundedFailureLabel(executor, "daemon", "library_managed")
		s.metrics.reconnects.WithLabelValues(append(labels, executor)...).Inc()
	}
}

var (
	nodeLabels       = []string{"id", "subtag", "dialer"}
	nodeEventLabels  = []string{"id", "subtag", "dialer", "event"}
	nodeResultLabels = []string{"id", "subtag", "dialer", "result"}

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
)

func (s *availabilityStore) describe(ch chan<- *prometheus.Desc) {
	for _, descriptor := range []*prometheus.Desc{
		checkLatencyDesc, selectionRankDesc, selectionScoreDesc,
		nodeAliveDesc, nodeTimestampDesc, nodeChecksDesc, nodeChecksSinceAliveDesc,
		groupAvailableDesc, groupTimestampDesc,
	} {
		ch <- descriptor
	}
	for _, collector := range []prometheus.Collector{
		s.metrics.relayFailures, s.metrics.resourceFailures, s.metrics.reconnects, s.metrics.nodeUnavailable,
	} {
		collector.Describe(ch)
	}
}

func (s *availabilityStore) collectAvailability(ch chan<- prometheus.Metric) {
	type nodeSnapshot struct {
		key string
		NodeIdentity
		api.Availability
	}
	type groupSnapshot struct {
		name string
		api.Availability
	}

	s.mu.Lock()
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
	s.mu.Unlock()

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
}

func (s *availabilityStore) collect(ch chan<- prometheus.Metric) {
	s.collectAvailability(ch)
	s.collectSelections(ch)
	s.metrics.relayFailures.Collect(ch)
	s.metrics.resourceFailures.Collect(ch)
	s.metrics.reconnects.Collect(ch)
	s.metrics.nodeUnavailable.Collect(ch)
}
