/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func gatheredMetricValue(t *testing.T, registry *prometheus.Registry, familyName, id string) (float64, bool) {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != familyName {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "id" && label.GetValue() == id {
					return metric.GetGauge().GetValue(), true
				}
			}
		}
	}
	return 0, false
}

func TestInitPrometheusDoesNotResetLiveReloadMetrics(t *testing.T) {
	labels := prometheus.Labels{
		"id":       t.Name(),
		"outbound": t.Name(),
		"subtag":   "sub",
		"dialer":   "node",
		"network":  "tcp4",
	}
	defer CheckLatency.Delete(labels)
	CheckLatency.With(labels).Set(42)

	registry := prometheus.NewRegistry()
	InitPrometheus(registry)
	if value, ok := gatheredMetricValue(t, registry, "dae_check_latency", t.Name()); !ok || value != 42 {
		t.Fatalf("candidate registry construction reset live metric: value=%v present=%v", value, ok)
	}

	ResetReloadMetrics()
	if value, ok := gatheredMetricValue(t, registry, "dae_check_latency", t.Name()); ok {
		t.Fatalf("committed reload reset left stale metric: %v", value)
	}
}

func TestInitPrometheusRegistersTrafficBytes(t *testing.T) {
	labels := prometheus.Labels{
		"id": t.Name(), "outbound": t.Name(), "subtag": "sub", "dialer": "node",
		"network": "tcp4", "direction": "upload",
	}
	defer TrafficBytes.Delete(labels)
	TrafficBytes.With(labels).Add(42)
	registry := prometheus.NewRegistry()
	InitPrometheus(registry)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "dae_traffic_bytes_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "id" && label.GetValue() == t.Name() {
					if got := metric.GetCounter().GetValue(); got != 42 {
						t.Fatalf("traffic bytes = %v, want 42", got)
					}
					return
				}
			}
		}
	}
	t.Fatal("dae_traffic_bytes_total metric was not gathered")
}
