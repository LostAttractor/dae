/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func gatheredPathMetric(t *testing.T, registry *prometheus.Registry, familyName string, path Path, extraLabels map[string]string) (*dto.Metric, bool) {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"id": path.NodeID, "outbound": path.Outbound, "subtag": path.Subtag,
		"dialer": path.Dialer, "network": path.Network.String(),
	}
	for name, value := range extraLabels {
		want[name] = value
	}
	for _, family := range families {
		if family.GetName() != familyName {
			continue
		}
		for _, metric := range family.GetMetric() {
			matched := 0
			for _, label := range metric.GetLabel() {
				if value, ok := want[label.GetName()]; ok && value == label.GetValue() {
					matched++
				}
			}
			if matched == len(want) {
				return metric, true
			}
		}
	}
	return nil, false
}

func TestStoreMetricsKeepLifetimeValuesAcrossCurrentReset(t *testing.T) {
	store := newStoreAt(time.Now())
	path := trafficTestPath(t.Name())
	store.RecordCheckMetrics(path, 42*time.Millisecond, 50*time.Millisecond, 60*time.Millisecond)
	store.RecordSelectionIndex(path, 2)
	store.RecordDial(path, 25*time.Millisecond)
	store.RecordError(path)
	registry := prometheus.NewRegistry()
	registry.MustRegister(store)

	for sample, want := range map[string]float64{
		"last":      0.042,
		"moving":    0.050,
		"selection": 0.060,
	} {
		metric, ok := gatheredPathMetric(t, registry, "dae_check_latency_seconds", path, map[string]string{"sample": sample})
		if !ok {
			t.Fatalf("check latency sample %s is absent", sample)
		}
		if value := metric.GetGauge().GetValue(); value != want {
			t.Fatalf("check latency sample %s = %v, want %v", sample, value, want)
		}
	}
	if metric, ok := gatheredPathMetric(t, registry, "dae_selection_rank", path, nil); !ok || metric.GetGauge().GetValue() != 2 {
		t.Fatalf("selection rank = %+v, present=%v", metric, ok)
	}
	if metric, ok := gatheredPathMetric(t, registry, "dae_path_errors_total", path, nil); !ok || metric.GetCounter().GetValue() != 1 {
		t.Fatalf("path error counter = %+v, present=%v", metric, ok)
	}
	if metric, ok := gatheredPathMetric(t, registry, "dae_dial_duration_seconds", path, nil); !ok || metric.GetHistogram().GetSampleCount() != 1 {
		t.Fatalf("dial histogram = %+v, present=%v", metric, ok)
	}

	store.Reconcile(nil, nil)
	if _, ok := gatheredPathMetric(t, registry, "dae_check_latency_seconds", path, map[string]string{"sample": "last"}); ok {
		t.Fatal("current check metric survived reset")
	}
	if _, ok := gatheredPathMetric(t, registry, "dae_selection_rank", path, nil); ok {
		t.Fatal("current selection rank survived reset")
	}
	if metric, ok := gatheredPathMetric(t, registry, "dae_path_errors_total", path, nil); !ok || metric.GetCounter().GetValue() != 1 {
		t.Fatalf("lifetime error counter after reset = %+v, present=%v", metric, ok)
	}
	if metric, ok := gatheredPathMetric(t, registry, "dae_dial_duration_seconds", path, nil); !ok || metric.GetHistogram().GetSampleCount() != 1 {
		t.Fatalf("lifetime dial histogram after reset = %+v, present=%v", metric, ok)
	}
}

func TestStoreCollectorSurvivesExternalReadFailure(t *testing.T) {
	store := newStoreAt(time.Now())
	connection := store.OpenConnection(trafficTestPath(t.Name()), false)
	if err := connection.AttachExternalCounters(func() (TrafficCounters, error) {
		return TrafficCounters{}, errors.New("counter source failed")
	}); err != nil {
		t.Fatal(err)
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(store)

	if _, err := registry.Gather(); err != nil {
		t.Fatalf("collector failed after an external counter error: %v", err)
	}
	if got := store.externalReadErrors.Load(); got == 0 {
		t.Fatal("external counter error was not recorded")
	}
	_ = connection.Close()
}
