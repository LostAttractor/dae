package stats

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestRecoveryMetricsKeepIndependentEventsAndBoundLabels(t *testing.T) {
	store := newStoreAt(time.Now())
	key := t.Name()
	store.Reconcile(map[string]NodeIdentity{key: {Name: "node"}}, nil)
	store.RecordNodeState(key, true, time.Time{})
	store.RecordRelayFailure(key, "stream", "h2", "reset")
	store.RecordRelayFailure(key, "shared_resource", "tcp", "reset")
	store.RecordRelayFailure(key, "arbitrary scope", "arbitrary layer", "sensitive diagnostic text")
	store.RecordRelayFailure(key, "shared_resource", "smux", "reset")
	store.RecordRelayFailure(key, "shared_resource", "anytls", "reset")
	store.RecordResourceFailure(key)
	store.RecordReconnectAttempt(key, "daemon")
	store.RecordNodeState(key, false, time.Time{})
	store.RecordNodeState(key, false, time.Time{})
	registry := prometheus.NewRegistry()
	registry.MustRegister(store)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]float64{}
	unknownSeen := false
	layers := map[string]bool{}
	for _, family := range families {
		for _, metric := range family.Metric {
			counts[family.GetName()] += metric.GetCounter().GetValue()
			unknown := 0
			for _, label := range metric.Label {
				if label.GetName() == "layer" {
					layers[label.GetValue()] = true
				}
				if label.GetValue() == "sensitive diagnostic text" {
					t.Fatal("unbounded diagnostic became metric label")
				}
				if label.GetValue() == "unknown" {
					unknown++
				}
			}
			unknownSeen = unknownSeen || unknown == 3
		}
	}
	for name, expected := range map[string]float64{
		"dae_relay_failures_total": 5, "dae_resource_failures_total": 1,
		"dae_reconnect_attempts_total": 1, "dae_node_unavailable_total": 1,
	} {
		if counts[name] != expected {
			t.Errorf("%s = %v, want %v", name, counts[name], expected)
		}
	}
	if !unknownSeen {
		t.Fatal("unbounded classifications were not normalized")
	}
	if !layers["smux"] || !layers["anytls"] {
		t.Fatalf("known protocol layer was discarded: %v", layers)
	}
}
