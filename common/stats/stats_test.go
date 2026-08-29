/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func collectedMetricValue(t *testing.T, store *Store, familyName string, labels map[string]string) (float64, bool) {
	t.Helper()
	registry := prometheus.NewRegistry()
	registry.MustRegister(store)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != familyName {
			continue
		}
		for _, metric := range family.GetMetric() {
			matched := true
			for name, want := range labels {
				found := false
				for _, label := range metric.GetLabel() {
					if label.GetName() == name && label.GetValue() == want {
						found = true
						break
					}
				}
				if !found {
					matched = false
					break
				}
			}
			if matched {
				if metric.GetGauge() != nil {
					return metric.GetGauge().GetValue(), true
				}
				return metric.GetCounter().GetValue(), true
			}
		}
	}
	return 0, false
}

func nodeMetricValue(t *testing.T, store *Store, familyName, key, subtag, name string, labels ...string) float64 {
	t.Helper()
	wantLabels := map[string]string{
		"id": NodeID(key), "subtag": subtag, "dialer": name,
	}
	for i := 0; i < len(labels); i += 2 {
		wantLabels[labels[i]] = labels[i+1]
	}
	value, ok := collectedMetricValue(t, store, familyName, wantLabels)
	if !ok {
		t.Fatalf("metric %s for node %s is absent", familyName, key)
	}
	return value
}

func registerNode(store *Store, key, subtag, name string) {
	store.Reconcile(map[string]NodeIdentity{
		key: {Subtag: subtag, Name: name},
	}, nil)
}

func TestRecordNode_Snapshot(t *testing.T) {
	store := newStoreAt(time.Now())
	key, subtag, name := t.Name()+"\x1fnode", "sub", "node-a"
	registerNode(store, key, subtag, name)
	if avail := store.GetNode(key); avail.Seen {
		t.Fatalf("unrecorded node should not be seen")
	}
	store.RecordNodeCheck(key, true, time.Time{})
	avail := store.GetNode(key)
	if !avail.Seen || !avail.Alive {
		t.Errorf("node should be seen and alive: %+v", avail)
	}
	if avail.AliveSince.IsZero() {
		t.Errorf("alive node should have AliveSince: %+v", avail)
	}
	if avail.LastCheckAt.IsZero() {
		t.Errorf("checked record should set LastCheckAt")
	}
	if !avail.LastFailureStartedAt.IsZero() || avail.LastFailureDuration != 0 {
		t.Errorf("never-failed node should have no failure episode: %+v", avail)
	}
	if avail.UpRatio <= 0 || avail.UpRatio > 1 {
		t.Errorf("UpRatio out of range: %v", avail.UpRatio)
	}

	store.RecordNodeCheck(key, false, time.Time{})
	avail = store.GetNode(key)
	if avail.Alive {
		t.Errorf("node should be down")
	}
	if avail.LastFailureStartedAt.IsZero() {
		t.Errorf("failed record should start a failure episode")
	}
	if !avail.AliveSince.IsZero() {
		t.Errorf("down node should not report AliveSince: %+v", avail)
	}
	if avail.UpRatio >= 1 {
		t.Errorf("UpRatio should drop below 1 after failure: %v", avail.UpRatio)
	}
}

func TestRecordNode_UncheckedRegistration(t *testing.T) {
	store := newStoreAt(time.Now())
	key, subtag, name := t.Name()+"\x1fnode", "sub", "node-b"
	registerNode(store, key, subtag, name)
	store.RecordNodeState(key, true, time.Time{})
	avail := store.GetNode(key)
	if !avail.Seen || !avail.Alive {
		t.Errorf("node should be seen and alive: %+v", avail)
	}
	if !avail.LastCheckAt.IsZero() {
		t.Errorf("unchecked record should not set LastCheckAt")
	}
}

func TestRecordNodeCollectorMatchesSnapshot(t *testing.T) {
	store := newStoreAt(time.Now())
	key, subtag, name := t.Name()+"\x1fnode", "sub", "node-c"
	registerNode(store, key, subtag, name)
	store.RecordNodeCheck(key, true, time.Time{})
	if v := nodeMetricValue(t, store, "dae_node_alive", key, subtag, name); v != 1 {
		t.Errorf("dae_node_alive should be 1, got %v", v)
	}
	if v := nodeMetricValue(t, store, "dae_node_timestamp_seconds", key, subtag, name, "event", "alive_since"); v == 0 {
		t.Errorf("node alive_since timestamp should be set")
	}
	if v := nodeMetricValue(t, store, "dae_node_timestamp_seconds", key, subtag, name, "event", "last_check"); v == 0 {
		t.Errorf("node last_check timestamp should be set")
	}
	store.RecordNodeCheck(key, false, time.Time{})
	if v := nodeMetricValue(t, store, "dae_node_alive", key, subtag, name); v != 0 {
		t.Errorf("dae_node_alive should be 0, got %v", v)
	}
	if v := nodeMetricValue(t, store, "dae_node_timestamp_seconds", key, subtag, name, "event", "alive_since"); v != 0 {
		t.Error("node alive_since timestamp should be zero while down")
	}
	if v := nodeMetricValue(t, store, "dae_node_timestamp_seconds", key, subtag, name, "event", "failure_started"); v == 0 {
		t.Errorf("node failure_started timestamp should be set")
	}
	avail := store.GetNode(key)
	if got := unixSeconds(avail.LastFailureStartedAt); got != nodeMetricValue(t, store, "dae_node_timestamp_seconds", key, subtag, name, "event", "failure_started") {
		t.Errorf("LastFailureStartedAt disagrees with gauge: %v", got)
	}
	if got := unixSeconds(avail.LastCheckAt); got != nodeMetricValue(t, store, "dae_node_timestamp_seconds", key, subtag, name, "event", "last_check") {
		t.Errorf("LastCheckAt disagrees with gauge: %v", got)
	}
}

// Nodes sharing the same (subtag, dialer) display labels must not alias
// each other's state, thanks to the "id" label.
func TestRecordNode_SameNameDistinctIdentity(t *testing.T) {
	store := newStoreAt(time.Now())
	key1 := t.Name() + "\x1fnode-1"
	key2 := t.Name() + "\x1fnode-2"
	store.Reconcile(map[string]NodeIdentity{
		key1: {Subtag: "sub", Name: "same-name"},
		key2: {Subtag: "sub", Name: "same-name"},
	}, nil)
	store.RecordNodeCheck(key1, true, time.Time{})
	store.RecordNodeCheck(key2, false, time.Time{})
	if avail := store.GetNode(key1); !avail.Alive {
		t.Errorf("node-1 should stay alive")
	}
	if avail := store.GetNode(key2); avail.Alive || avail.LastFailureStartedAt.IsZero() {
		t.Errorf("node-2 should have an active failure episode: %+v", avail)
	}
	if NodeID(key1) == NodeID(key2) {
		t.Fatalf("distinct keys must produce distinct ids")
	}
}

func TestRecordNodeConnFail(t *testing.T) {
	store := newStoreAt(time.Now())
	key, subtag, name := t.Name()+"\x1fnode", "sub", "node-d"
	store.RecordNodeConnFail(key) // no-op before the first RecordNode
	if avail := store.GetNode(key); avail.Seen {
		t.Fatalf("conn-fail alone should not create node state")
	}
	registerNode(store, key, subtag, name)
	store.RecordNodeCheck(key, true, time.Time{})
	store.RecordNodeConnFail(key)
	avail := store.GetNode(key)
	if avail.LastConnFailAt.IsZero() {
		t.Errorf("LastConnFailAt should be set")
	}
	if !avail.Alive || !avail.LastFailureStartedAt.IsZero() {
		t.Errorf("conn-fail should not affect aliveness or failure episodes: %+v", avail)
	}
	if v := nodeMetricValue(t, store, "dae_node_timestamp_seconds", key, subtag, name, "event", "last_connection_failure"); v == 0 {
		t.Errorf("node last_connection_failure timestamp should be set")
	}
}

func TestRecordGroup_Snapshot(t *testing.T) {
	store := newStoreAt(time.Now())
	name := t.Name()
	store.Reconcile(nil, map[string]struct{}{name: {}})
	if avail := store.GetGroup(name); avail.Seen {
		t.Fatalf("unrecorded group should not be seen")
	}
	store.RecordGroup(name, true)
	avail := store.GetGroup(name)
	if !avail.Seen || !avail.Alive {
		t.Errorf("group should be seen and available: %+v", avail)
	}
	if got := avail.Recent.States[len(avail.Recent.States)-1]; got != GroupHistoryAvailable {
		t.Errorf("latest group history = %q, want available", got)
	}
	if avail.AliveSince.IsZero() {
		t.Errorf("alive group should have AliveSince: %+v", avail)
	}
	if v, ok := collectedMetricValue(t, store, "dae_group_timestamp_seconds", map[string]string{"outbound": name, "event": "available_since"}); !ok || v == 0 {
		t.Error("group available_since timestamp should be set")
	}
	if !avail.LastCheckAt.IsZero() || !avail.LastConnFailAt.IsZero() {
		t.Errorf("groups never set check/conn-fail timestamps: %+v", avail)
	}
	store.RecordGroup(name, false)
	avail = store.GetGroup(name)
	if avail.Alive || avail.LastFailureStartedAt.IsZero() {
		t.Errorf("group should have an active failure episode: %+v", avail)
	}
	if got := avail.Recent.States[len(avail.Recent.States)-1]; got != GroupHistoryUnavailable {
		t.Errorf("latest group history = %q, want unavailable", got)
	}
	if v, ok := collectedMetricValue(t, store, "dae_group_available", map[string]string{"outbound": name}); !ok || v != 0 {
		t.Errorf("dae_group_available should be 0, got %v", v)
	}
	if v, ok := collectedMetricValue(t, store, "dae_group_timestamp_seconds", map[string]string{"outbound": name, "event": "failure_started"}); !ok || v == 0 {
		t.Error("group failure_started timestamp should be set")
	}
}

func TestRecordNode_FailureEpisodes(t *testing.T) {
	a := new(availability)
	startedAt := time.Now().Add(-time.Hour).Truncate(time.Second)

	a.record(false, true, startedAt, time.Time{})
	snap := a.snapshot(startedAt.Add(2 * time.Minute))
	if snap.Alive || !snap.LastFailureStartedAt.Equal(startedAt) || snap.LastFailureDuration != 2*time.Minute {
		t.Fatalf("first down observation should start a failure episode: %+v", snap)
	}

	a.record(false, true, startedAt.Add(3*time.Minute), time.Time{})
	snap = a.snapshot(startedAt.Add(5 * time.Minute))
	if !snap.LastFailureStartedAt.Equal(startedAt) || snap.LastFailureDuration != 5*time.Minute {
		t.Fatalf("repeated failures should preserve the episode start: %+v", snap)
	}
	if snap.ChecksFailed != 2 {
		t.Fatalf("failed samples should still be counted independently: %+v", snap)
	}

	recoveredAt := startedAt.Add(7 * time.Minute)
	a.record(true, true, recoveredAt, time.Time{})
	snap = a.snapshot(startedAt.Add(30 * time.Minute))
	if !snap.Alive || !snap.AliveSince.Equal(recoveredAt) || snap.LastFailureDuration != 7*time.Minute {
		t.Fatalf("recovery should freeze the completed failure duration: %+v", snap)
	}

	a.record(true, true, startedAt.Add(35*time.Minute), time.Time{})
	snap = a.snapshot(startedAt.Add(40 * time.Minute))
	if snap.LastFailureDuration != 7*time.Minute {
		t.Fatalf("successful checks should not extend a completed failure: %+v", snap)
	}

	secondStartedAt := startedAt.Add(45 * time.Minute)
	a.record(false, true, secondStartedAt, time.Time{})
	snap = a.snapshot(secondStartedAt.Add(4 * time.Minute))
	if !snap.LastFailureStartedAt.Equal(secondStartedAt) || snap.LastFailureDuration != 4*time.Minute {
		t.Fatalf("a new outage should replace the previous episode: %+v", snap)
	}
}

func TestRecordNode_SubsecondFailureDuration(t *testing.T) {
	a := new(availability)
	startedAt := time.Now()

	a.record(false, true, startedAt, time.Time{})
	a.record(true, true, startedAt.Add(150*time.Millisecond), time.Time{})
	snap := a.snapshot(startedAt.Add(time.Second))
	if snap.LastFailureDuration != 150*time.Millisecond {
		t.Fatalf("subsecond failure duration = %v, want 150ms", snap.LastFailureDuration)
	}
}

func TestRecordNodeClampsFailureTimestamp(t *testing.T) {
	a := new(availability)
	startedAt := time.Now().Truncate(time.Second)
	a.record(true, true, startedAt, time.Time{})

	failedAt := startedAt.Add(2 * time.Second)
	a.record(false, true, failedAt, startedAt.Add(-time.Second))
	snapshot := a.snapshot(failedAt)
	if !snapshot.LastFailureStartedAt.Equal(startedAt) {
		t.Fatalf("old failure timestamp was not clamped: %v", snapshot.LastFailureStartedAt)
	}
	if snapshot.UpRatio < 0 || snapshot.UpRatio > 1 {
		t.Fatalf("up ratio = %v, want [0, 1]", snapshot.UpRatio)
	}

	a.record(true, true, failedAt.Add(time.Second), time.Time{})
	futureReport := failedAt.Add(3 * time.Second)
	a.record(false, true, futureReport, futureReport.Add(time.Minute))
	if snapshot = a.snapshot(futureReport); !snapshot.LastFailureStartedAt.Equal(futureReport) {
		t.Fatalf("future failure timestamp was not clamped: %v", snapshot.LastFailureStartedAt)
	}
}

func TestRecordNode_CheckCounters(t *testing.T) {
	store := newStoreAt(time.Now())
	key, subtag, name := t.Name()+"\x1fnode", "sub", "node-e"
	registerNode(store, key, subtag, name)
	store.RecordNodeState(key, true, time.Time{}) // registration: not a check
	if avail := store.GetNode(key); avail.ChecksTotal != 0 {
		t.Fatalf("registration should not count as check: %+v", avail)
	}

	store.RecordNodeCheck(key, true, time.Time{})
	store.RecordNodeCheck(key, true, time.Time{})
	avail := store.GetNode(key)
	if avail.ChecksTotal != 2 || avail.ChecksFailed != 0 {
		t.Errorf("want 2/0 checks, got %v/%v", avail.ChecksTotal, avail.ChecksFailed)
	}
	if avail.ChecksSinceAlive != 2 {
		t.Errorf("want ChecksSinceAlive 2, got %v", avail.ChecksSinceAlive)
	}

	store.RecordNodeCheck(key, false, time.Time{})
	store.RecordNodeCheck(key, false, time.Time{})
	avail = store.GetNode(key)
	if avail.ChecksTotal != 4 || avail.ChecksFailed != 2 {
		t.Errorf("want 4/2 checks, got %v/%v", avail.ChecksTotal, avail.ChecksFailed)
	}
	if avail.Recent24h.ChecksTotal != 4 || avail.Recent24h.ChecksFailed != 2 {
		t.Errorf("want recent 4/2 checks, got %v/%v", avail.Recent24h.ChecksTotal, avail.Recent24h.ChecksFailed)
	}
	store.RecordNodeCheck(key, true, time.Time{})
	avail = store.GetNode(key)
	if avail.ChecksSinceAlive != 1 {
		t.Errorf("recovery check resets ChecksSinceAlive to 1, got %v", avail.ChecksSinceAlive)
	}
	store.RecordNodeCheck(key, true, time.Time{})
	if avail = store.GetNode(key); avail.ChecksSinceAlive != 2 {
		t.Errorf("want ChecksSinceAlive 2, got %v", avail.ChecksSinceAlive)
	}

	if v := int64(nodeMetricValue(t, store, "dae_node_checks_total", key, subtag, name, "result", "success")); v != avail.ChecksTotal-avail.ChecksFailed {
		t.Errorf("successful dae_node_checks_total disagrees: %v", v)
	}
	if v := int64(nodeMetricValue(t, store, "dae_node_checks_total", key, subtag, name, "result", "failure")); v != avail.ChecksFailed {
		t.Errorf("failed dae_node_checks_total disagrees: %v", v)
	}
	if v := int64(nodeMetricValue(t, store, "dae_node_checks_since_alive", key, subtag, name)); v != avail.ChecksSinceAlive {
		t.Errorf("dae_node_checks_since_alive disagrees: %v", v)
	}
}

func TestRecordReload(t *testing.T) {
	store := newStoreAt(time.Now())
	before := time.Now().Unix()
	store.RecordReload()
	last := store.LastReload()
	if last.IsZero() || last.Unix() < before {
		t.Errorf("LastReload should be >= %v, got %v", before, last)
	}
	if v, ok := collectedMetricValue(t, store, "dae_process_timestamp_seconds", map[string]string{"event": "start"}); !ok || v != unixSeconds(store.startedAt) {
		t.Errorf("process start timestamp disagrees with Store.startedAt: %v", v)
	}
	if v, ok := collectedMetricValue(t, store, "dae_process_timestamp_seconds", map[string]string{"event": "reload"}); !ok || v != float64(last.Unix()) {
		t.Errorf("process reload timestamp disagrees with LastReload: %v", v)
	}
}

func collectorHasLabelValue(t *testing.T, collector prometheus.Collector, labelName, labelValue string) bool {
	t.Helper()
	registry := prometheus.NewRegistry()
	registry.MustRegister(collector)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == labelName && label.GetValue() == labelValue {
					return true
				}
			}
		}
	}
	return false
}

func TestReconcilePreservesFailureEpisode(t *testing.T) {
	store := newStoreAt(time.Now())
	key, subtag, name := t.Name()+"\x1fnode", "sub", "node"
	identity := NodeIdentity{Subtag: subtag, Name: name}
	store.Reconcile(map[string]NodeIdentity{key: identity}, nil)
	a := store.nodes[key]
	startedAt := time.Now()
	a.record(false, true, startedAt, time.Time{})

	store.Reconcile(map[string]NodeIdentity{key: identity}, nil)
	v, ok := store.nodes[key]
	if !ok || v != a {
		t.Fatal("reconcile replaced the retained availability state")
	}
	if snap := a.snapshot(startedAt.Add(2 * time.Second)); snap.LastFailureDuration != 2*time.Second {
		t.Fatalf("active failure did not continue across reconcile: %+v", snap)
	}

	a.record(true, true, startedAt.Add(3*time.Second), time.Time{})
	if snap := a.snapshot(startedAt.Add(10 * time.Second)); snap.LastFailureDuration != 3*time.Second {
		t.Fatalf("post-reconcile recovery did not freeze the failure duration: %+v", snap)
	}
}

func TestReconcileRetiresRemovedIdentities(t *testing.T) {
	store := newStoreAt(time.Now())
	keepKey := t.Name() + "\x1fkeep"
	removeKey := t.Name() + "\x1fremove"
	keepGroup := t.Name() + "-keep-group"
	removeGroup := t.Name() + "-remove-group"

	store.Reconcile(map[string]NodeIdentity{
		keepKey:   {Subtag: "sub", Name: "keep"},
		removeKey: {Subtag: "sub", Name: "remove"},
	}, map[string]struct{}{keepGroup: {}, removeGroup: {}})
	store.RecordNodeCheck(keepKey, true, time.Time{})
	store.RecordNodeCheck(removeKey, true, time.Time{})
	store.RecordNodeCheck(removeKey, true, time.Time{})
	store.RecordGroup(keepGroup, true)
	store.RecordGroup(removeGroup, true)

	store.Reconcile(map[string]NodeIdentity{
		keepKey: {Subtag: "sub", Name: "keep"},
	}, map[string]struct{}{keepGroup: {}})

	if avail := store.GetNode(keepKey); !avail.Seen || avail.ChecksTotal != 1 {
		t.Fatalf("retained node lost its history: %+v", avail)
	}
	if avail := store.GetNode(removeKey); avail.Seen {
		t.Fatalf("removed node is still visible: %+v", avail)
	}
	if avail := store.GetGroup(keepGroup); !avail.Seen {
		t.Fatalf("retained group lost its history")
	}
	if avail := store.GetGroup(removeGroup); avail.Seen {
		t.Fatalf("removed group is still visible: %+v", avail)
	}
	if collectorHasLabelValue(t, store, "id", NodeID(removeKey)) {
		t.Fatalf("removed node prometheus series still exists")
	}
	if collectorHasLabelValue(t, store, "outbound", removeGroup) {
		t.Fatalf("removed group prometheus series still exists")
	}

	// Re-adding a retired identity starts fresh instead of treating the time
	// it was absent from the configuration as part of its history.
	store.Reconcile(map[string]NodeIdentity{
		keepKey:   {Subtag: "sub", Name: "keep"},
		removeKey: {Subtag: "sub", Name: "remove"},
	}, map[string]struct{}{keepGroup: {}})
	store.RecordNodeCheck(removeKey, true, time.Time{})
	if avail := store.GetNode(removeKey); avail.ChecksTotal != 1 {
		t.Fatalf("re-added node should have fresh counters: %+v", avail)
	}
}

func TestReconcileConcurrentWithNodeAccess(t *testing.T) {
	store := newStoreAt(time.Now())
	key := t.Name() + "\x1fnode"
	identity := NodeIdentity{Subtag: "sub", Name: "node"}
	store.Reconcile(map[string]NodeIdentity{key: identity}, nil)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			store.RecordNodeCheck(key, i%2 == 0, time.Time{})
			_ = store.GetNode(key)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if i%2 == 0 {
				store.Reconcile(map[string]NodeIdentity{key: identity}, nil)
			} else {
				store.Reconcile(nil, nil)
			}
		}
	}()
	wg.Wait()
}
