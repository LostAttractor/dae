// SPDX-License-Identifier: AGPL-3.0-only

package stats

import (
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestAvailabilityCountersRetireWithIdentity(t *testing.T) {
	store := newAvailabilityStore()
	registry := prometheus.NewRegistry()
	for _, vector := range []*prometheus.CounterVec{store.metrics.relayFailures, store.metrics.resourceFailures, store.metrics.reconnects, store.metrics.nodeUnavailable} {
		registry.MustRegister(vector)
	}
	active := map[string]NodeIdentity{"retained": {Name: "retained"}, "changed": {Name: "old"}, "removed": {Name: "removed"}}
	store.Reconcile(active, nil)
	record := func(key string) {
		store.recordNode(key, true, true, time.Time{})
		store.recordNode(key, false, true, time.Time{})
		store.RecordRelayFailure(key, "stream", "tcp", "reset")
		store.RecordResourceFailure(key)
		store.RecordReconnectAttempt(key, "daemon")
	}
	for key := range active {
		record(key)
	}
	delete(active, "removed")
	active["changed"] = NodeIdentity{Name: "new"}
	store.Reconcile(active, nil)
	record("changed")
	active["removed"] = NodeIdentity{Name: "removed"}
	store.Reconcile(active, nil)
	record("removed")
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if len(family.Metric) != 3 {
			t.Fatalf("%s retained %d series", family.GetName(), len(family.Metric))
		}
		for _, metric := range family.Metric {
			if metric.GetCounter().GetValue() != 1 {
				t.Fatalf("%s inherited retired counters: %v", family.GetName(), metric)
			}
			for _, label := range metric.Label {
				if label.GetName() == "dialer" && label.GetValue() == "old" {
					t.Fatal("renamed identity retained old labels")
				}
			}
		}
	}
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			for range 100 {
				record("removed")
			}
		})
	}
	store.Reconcile(nil, nil)
	workers.Wait()
	families, err = registry.Gather()
	if err != nil || len(families) != 0 {
		t.Fatalf("removed identities were recreated: %v, %v", families, err)
	}
}
