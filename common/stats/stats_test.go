/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/prometheus/client_golang/prometheus"
)

func nodeGaugeValue(t *testing.T, vec *prometheus.GaugeVec, key, subtag, name string) float64 {
	t.Helper()
	return gaugeValue(vec.With(prometheus.Labels{"id": nodeID(key), "subtag": subtag, "dialer": name}))
}

func TestRecordNode_Snapshot(t *testing.T) {
	key, subtag, name := t.Name()+"\x1fnode", "sub", "node-a"
	if avail := GetNode(key); avail.Seen {
		t.Fatalf("unrecorded node should not be seen")
	}
	RecordNode(key, subtag, name, true, true)
	avail := GetNode(key)
	if !avail.Seen || !avail.Alive {
		t.Errorf("node should be seen and alive: %+v", avail)
	}
	if avail.AliveSince.IsZero() || avail.UpDuration <= 0 {
		t.Errorf("alive node should have AliveSince/UpDuration: %+v", avail)
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

	RecordNode(key, subtag, name, false, true)
	avail = GetNode(key)
	if avail.Alive {
		t.Errorf("node should be down")
	}
	if avail.LastFailureStartedAt.IsZero() {
		t.Errorf("failed record should start a failure episode")
	}
	if !avail.AliveSince.IsZero() || avail.UpDuration != 0 {
		t.Errorf("down node should not report AliveSince/UpDuration: %+v", avail)
	}
	if avail.UpRatio >= 1 {
		t.Errorf("UpRatio should drop below 1 after failure: %v", avail.UpRatio)
	}
}

func TestRecordNode_UncheckedRegistration(t *testing.T) {
	key, subtag, name := t.Name()+"\x1fnode", "sub", "node-b"
	RecordNode(key, subtag, name, true, false)
	avail := GetNode(key)
	if !avail.Seen || !avail.Alive {
		t.Errorf("node should be seen and alive: %+v", avail)
	}
	if !avail.LastCheckAt.IsZero() {
		t.Errorf("unchecked record should not set LastCheckAt")
	}
}

// The gauges are the single source of truth: values read straight from the
// prometheus vectors must match what snapshots report.
func TestRecordNode_GaugesAreSourceOfTruth(t *testing.T) {
	key, subtag, name := t.Name()+"\x1fnode", "sub", "node-c"
	RecordNode(key, subtag, name, true, true)
	if v := nodeGaugeValue(t, common.NodeAlive, key, subtag, name); v != 1 {
		t.Errorf("dae_node_alive should be 1, got %v", v)
	}
	if v := nodeGaugeValue(t, common.NodeAliveSince, key, subtag, name); v == 0 {
		t.Errorf("dae_node_alive_since_timestamp_seconds should be set")
	}
	if v := nodeGaugeValue(t, common.NodeLastCheck, key, subtag, name); v == 0 {
		t.Errorf("dae_node_last_check_timestamp_seconds should be set")
	}
	RecordNode(key, subtag, name, false, true)
	if v := nodeGaugeValue(t, common.NodeAlive, key, subtag, name); v != 0 {
		t.Errorf("dae_node_alive should be 0, got %v", v)
	}
	if v := nodeGaugeValue(t, common.NodeLastFailureStart, key, subtag, name); v == 0 {
		t.Errorf("dae_node_last_failure_start_timestamp_seconds should be set")
	}
	avail := GetNode(key)
	if got := float64(avail.LastFailureStartedAt.Unix()); got != nodeGaugeValue(t, common.NodeLastFailureStart, key, subtag, name) {
		t.Errorf("LastFailureStartedAt disagrees with gauge: %v", got)
	}
	if got := float64(avail.LastCheckAt.Unix()); got != nodeGaugeValue(t, common.NodeLastCheck, key, subtag, name) {
		t.Errorf("LastCheckAt disagrees with gauge: %v", got)
	}
}

// Nodes sharing the same (subtag, dialer) display labels must not alias
// each other's state, thanks to the "id" label.
func TestRecordNode_SameNameDistinctIdentity(t *testing.T) {
	key1 := t.Name() + "\x1fnode-1"
	key2 := t.Name() + "\x1fnode-2"
	RecordNode(key1, "sub", "same-name", true, true)
	RecordNode(key2, "sub", "same-name", false, true)
	if avail := GetNode(key1); !avail.Alive {
		t.Errorf("node-1 should stay alive")
	}
	if avail := GetNode(key2); avail.Alive || avail.LastFailureStartedAt.IsZero() {
		t.Errorf("node-2 should have an active failure episode: %+v", avail)
	}
	if nodeID(key1) == nodeID(key2) {
		t.Fatalf("distinct keys must produce distinct ids")
	}
}

func TestRecordNodeConnFail(t *testing.T) {
	key, subtag, name := t.Name()+"\x1fnode", "sub", "node-d"
	RecordNodeConnFail(key) // no-op before the first RecordNode
	if avail := GetNode(key); avail.Seen {
		t.Fatalf("conn-fail alone should not create node state")
	}
	RecordNode(key, subtag, name, true, true)
	RecordNodeConnFail(key)
	avail := GetNode(key)
	if avail.LastConnFailAt.IsZero() {
		t.Errorf("LastConnFailAt should be set")
	}
	if !avail.Alive || !avail.LastFailureStartedAt.IsZero() {
		t.Errorf("conn-fail should not affect aliveness or failure episodes: %+v", avail)
	}
	if v := nodeGaugeValue(t, common.NodeLastConnFailure, key, subtag, name); v == 0 {
		t.Errorf("dae_node_last_conn_failure_timestamp_seconds should be set")
	}
}

func TestRecordGroup_Snapshot(t *testing.T) {
	name := t.Name()
	if avail := GetGroup(name, 0); avail.Seen {
		t.Fatalf("unrecorded group should not be seen")
	}
	RecordGroup(name, 0, true)
	RecordGroup(name, 2, false)
	avail := GetGroup(name, 0)
	if !avail.Seen || !avail.Alive {
		t.Errorf("group network 0 should be seen and alive: %+v", avail)
	}
	if avail.AliveSince.IsZero() || avail.UpDuration <= 0 {
		t.Errorf("alive group should have AliveSince/UpDuration: %+v", avail)
	}
	if !avail.LastCheckAt.IsZero() || !avail.LastConnFailAt.IsZero() {
		t.Errorf("groups never set check/conn-fail timestamps: %+v", avail)
	}
	avail = GetGroup(name, 2)
	if avail.Alive || avail.LastFailureStartedAt.IsZero() {
		t.Errorf("group network 2 should have an active failure episode: %+v", avail)
	}
	if avail := GetGroup(name, 1); avail.Seen {
		t.Errorf("unrecorded network index should not be seen")
	}
	labels := prometheus.Labels{"outbound": name, "network": common.IndexToNetworkType(2).String()}
	if v := gaugeValue(common.GroupAlive.With(labels)); v != 0 {
		t.Errorf("dae_group_alive should be 0, got %v", v)
	}
	if v := gaugeValue(common.GroupLastFailureStart.With(labels)); v == 0 {
		t.Errorf("dae_group_last_failure_start_timestamp_seconds should be set")
	}
}

func TestRecordNode_FailureEpisodes(t *testing.T) {
	key, subtag, name := t.Name()+"\x1fnode", "sub", "node-episode"
	a := nodeAvailability(key, subtag, name)
	startedAt := time.Now().Add(-time.Hour).Truncate(time.Second)

	a.record(false, true, startedAt)
	snap := a.snapshotAt(startedAt.Add(2 * time.Minute))
	if snap.Alive || !snap.LastFailureStartedAt.Equal(startedAt) || snap.LastFailureDuration != 2*time.Minute {
		t.Fatalf("first down observation should start a failure episode: %+v", snap)
	}

	a.record(false, true, startedAt.Add(3*time.Minute))
	snap = a.snapshotAt(startedAt.Add(5 * time.Minute))
	if !snap.LastFailureStartedAt.Equal(startedAt) || snap.LastFailureDuration != 5*time.Minute {
		t.Fatalf("repeated failures should preserve the episode start: %+v", snap)
	}
	if snap.ChecksFailed != 2 || snap.ChecksSinceFail != 1 {
		t.Fatalf("failed samples should still be counted independently: %+v", snap)
	}

	recoveredAt := startedAt.Add(7 * time.Minute)
	a.record(true, true, recoveredAt)
	snap = a.snapshotAt(startedAt.Add(30 * time.Minute))
	if !snap.Alive || !snap.AliveSince.Equal(recoveredAt) || snap.LastFailureDuration != 7*time.Minute {
		t.Fatalf("recovery should freeze the completed failure duration: %+v", snap)
	}

	a.record(true, true, startedAt.Add(35*time.Minute))
	snap = a.snapshotAt(startedAt.Add(40 * time.Minute))
	if snap.LastFailureDuration != 7*time.Minute {
		t.Fatalf("successful checks should not extend a completed failure: %+v", snap)
	}

	secondStartedAt := startedAt.Add(45 * time.Minute)
	a.record(false, true, secondStartedAt)
	snap = a.snapshotAt(secondStartedAt.Add(4 * time.Minute))
	if !snap.LastFailureStartedAt.Equal(secondStartedAt) || snap.LastFailureDuration != 4*time.Minute {
		t.Fatalf("a new outage should replace the previous episode: %+v", snap)
	}
}

func TestRecordNode_SubsecondFailureDuration(t *testing.T) {
	key, subtag, name := t.Name()+"\x1fnode", "sub", "node-short-episode"
	a := nodeAvailability(key, subtag, name)
	startedAt := time.Now()

	a.record(false, true, startedAt)
	a.record(true, true, startedAt.Add(150*time.Millisecond))
	snap := a.snapshotAt(startedAt.Add(time.Second))
	if snap.LastFailureDuration != 150*time.Millisecond {
		t.Fatalf("subsecond failure duration = %v, want 150ms", snap.LastFailureDuration)
	}
}

func TestRecordNode_CheckCounters(t *testing.T) {
	key, subtag, name := t.Name()+"\x1fnode", "sub", "node-e"
	labels := func() prometheus.Labels {
		return prometheus.Labels{"id": nodeID(key), "subtag": subtag, "dialer": name}
	}
	RecordNode(key, subtag, name, true, false) // registration: not a check
	if avail := GetNode(key); avail.ChecksTotal != 0 {
		t.Fatalf("registration should not count as check: %+v", avail)
	}

	RecordNode(key, subtag, name, true, true)
	RecordNode(key, subtag, name, true, true)
	avail := GetNode(key)
	if avail.ChecksTotal != 2 || avail.ChecksFailed != 0 {
		t.Errorf("want 2/0 checks, got %v/%v", avail.ChecksTotal, avail.ChecksFailed)
	}
	if avail.ChecksSinceAlive != 2 {
		t.Errorf("want ChecksSinceAlive 2, got %v", avail.ChecksSinceAlive)
	}

	RecordNode(key, subtag, name, false, true)
	RecordNode(key, subtag, name, false, true)
	avail = GetNode(key)
	if avail.ChecksTotal != 4 || avail.ChecksFailed != 2 {
		t.Errorf("want 4/2 checks, got %v/%v", avail.ChecksTotal, avail.ChecksFailed)
	}
	if avail.Recent24h.ChecksTotal != 4 || avail.Recent24h.ChecksFailed != 2 {
		t.Errorf("want recent 4/2 checks, got %v/%v", avail.Recent24h.ChecksTotal, avail.Recent24h.ChecksFailed)
	}
	if avail.ChecksSinceFail != 1 {
		t.Errorf("every failed check resets ChecksSinceFail to 1, got %v", avail.ChecksSinceFail)
	}

	RecordNode(key, subtag, name, true, true)
	avail = GetNode(key)
	if avail.ChecksSinceAlive != 1 {
		t.Errorf("recovery check resets ChecksSinceAlive to 1, got %v", avail.ChecksSinceAlive)
	}
	if avail.ChecksSinceFail != 2 {
		t.Errorf("want ChecksSinceFail 2 after recovery check, got %v", avail.ChecksSinceFail)
	}
	RecordNode(key, subtag, name, true, true)
	if avail = GetNode(key); avail.ChecksSinceAlive != 2 || avail.ChecksSinceFail != 3 {
		t.Errorf("want since counters 2/3, got %v/%v", avail.ChecksSinceAlive, avail.ChecksSinceFail)
	}

	if v := counterValue(common.NodeChecksTotal.With(labels())); v != avail.ChecksTotal {
		t.Errorf("dae_node_checks_total disagrees: %v", v)
	}
	if v := counterValue(common.NodeCheckFailures.With(labels())); v != avail.ChecksFailed {
		t.Errorf("dae_node_check_failures_total disagrees: %v", v)
	}
	if v := int64(gaugeValue(common.NodeChecksSinceAlive.With(labels()))); v != avail.ChecksSinceAlive {
		t.Errorf("dae_node_checks_since_alive disagrees: %v", v)
	}
	if v := int64(gaugeValue(common.NodeChecksSinceFailure.With(labels()))); v != avail.ChecksSinceFail {
		t.Errorf("dae_node_checks_since_failure disagrees: %v", v)
	}
}

func TestRecordReload(t *testing.T) {
	before := time.Now().Unix()
	RecordReload()
	last := LastReload()
	if last.IsZero() || last.Unix() < before {
		t.Errorf("LastReload should be >= %v, got %v", before, last)
	}
	if v := gaugeValue(common.LastReloadTime); v != float64(last.Unix()) {
		t.Errorf("dae_last_reload_timestamp_seconds disagrees with LastReload: %v", v)
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
	key, subtag, name := t.Name()+"\x1fnode", "sub", "node"
	identity := NodeIdentity{Key: key, Subtag: subtag, Name: name}
	a := nodeAvailability(key, subtag, name)
	startedAt := time.Now()
	a.record(false, true, startedAt)

	Reconcile([]NodeIdentity{identity}, nil)
	v, ok := nodes.Load(key)
	if !ok || v.(*availability) != a {
		t.Fatal("reconcile replaced the retained availability state")
	}
	if snap := a.snapshotAt(startedAt.Add(2 * time.Second)); snap.LastFailureDuration != 2*time.Second {
		t.Fatalf("active failure did not continue across reconcile: %+v", snap)
	}

	a.record(true, true, startedAt.Add(3*time.Second))
	if snap := a.snapshotAt(startedAt.Add(10 * time.Second)); snap.LastFailureDuration != 3*time.Second {
		t.Fatalf("post-reconcile recovery did not freeze the failure duration: %+v", snap)
	}
}

func TestReconcileRetiresRemovedIdentities(t *testing.T) {
	keepKey := t.Name() + "\x1fkeep"
	removeKey := t.Name() + "\x1fremove"
	keepGroup := t.Name() + "-keep-group"
	removeGroup := t.Name() + "-remove-group"

	RecordNode(keepKey, "sub", "keep", true, true)
	RecordNode(removeKey, "sub", "remove", true, true)
	RecordNode(removeKey, "sub", "remove", true, true)
	RecordGroup(keepGroup, 0, true)
	RecordGroup(removeGroup, 0, true)

	Reconcile([]NodeIdentity{{Key: keepKey, Subtag: "sub", Name: "keep"}}, []string{keepGroup})

	if avail := GetNode(keepKey); !avail.Seen || avail.ChecksTotal != 1 {
		t.Fatalf("retained node lost its history: %+v", avail)
	}
	if avail := GetNode(removeKey); avail.Seen {
		t.Fatalf("removed node is still visible: %+v", avail)
	}
	if avail := GetGroup(keepGroup, 0); !avail.Seen {
		t.Fatalf("retained group lost its history")
	}
	if avail := GetGroup(removeGroup, 0); avail.Seen {
		t.Fatalf("removed group is still visible: %+v", avail)
	}
	if collectorHasLabelValue(t, common.NodeAlive, "id", NodeID(removeKey)) {
		t.Fatalf("removed node prometheus series still exists")
	}
	if collectorHasLabelValue(t, common.GroupAlive, "outbound", removeGroup) {
		t.Fatalf("removed group prometheus series still exists")
	}

	// Re-adding a retired identity starts fresh instead of treating the time
	// it was absent from the configuration as part of its history.
	RecordNode(removeKey, "sub", "remove", true, true)
	if avail := GetNode(removeKey); avail.ChecksTotal != 1 {
		t.Fatalf("re-added node should have fresh counters: %+v", avail)
	}
}

func TestReconcileConcurrentWithNodeAccess(t *testing.T) {
	key := t.Name() + "\x1fnode"
	identity := NodeIdentity{Key: key, Subtag: "sub", Name: "node"}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			RecordNode(key, identity.Subtag, identity.Name, i%2 == 0, true)
			_ = GetNode(key)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if i%2 == 0 {
				Reconcile([]NodeIdentity{identity}, nil)
			} else {
				Reconcile(nil, nil)
			}
		}
	}()
	wg.Wait()
}
