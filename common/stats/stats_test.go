/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package stats

import (
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
	if !avail.LastFailAt.IsZero() {
		t.Errorf("never-failed node should have zero LastFailAt")
	}
	if avail.UpRatio <= 0 || avail.UpRatio > 1 {
		t.Errorf("UpRatio out of range: %v", avail.UpRatio)
	}

	RecordNode(key, subtag, name, false, true)
	avail = GetNode(key)
	if avail.Alive {
		t.Errorf("node should be down")
	}
	if avail.LastFailAt.IsZero() {
		t.Errorf("failed record should set LastFailAt")
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
	if v := nodeGaugeValue(t, common.NodeLastFailure, key, subtag, name); v == 0 {
		t.Errorf("dae_node_last_failure_timestamp_seconds should be set")
	}
	avail := GetNode(key)
	if got := float64(avail.LastFailAt.Unix()); got != nodeGaugeValue(t, common.NodeLastFailure, key, subtag, name) {
		t.Errorf("LastFailAt disagrees with gauge: %v", got)
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
	if avail := GetNode(key2); avail.Alive || avail.LastFailAt.IsZero() {
		t.Errorf("node-2 should be down with LastFailAt: %+v", avail)
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
	if !avail.Alive || !avail.LastFailAt.IsZero() {
		t.Errorf("conn-fail should not affect aliveness or LastFailAt: %+v", avail)
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
	if avail.Alive || avail.LastFailAt.IsZero() {
		t.Errorf("group network 2 should be down with LastFailAt: %+v", avail)
	}
	if avail := GetGroup(name, 1); avail.Seen {
		t.Errorf("unrecorded network index should not be seen")
	}
	labels := prometheus.Labels{"outbound": name, "network": common.IndexToNetworkType(2).String()}
	if v := gaugeValue(common.GroupAlive.With(labels)); v != 0 {
		t.Errorf("dae_group_alive should be 0, got %v", v)
	}
	if v := gaugeValue(common.GroupLastFailure.With(labels)); v == 0 {
		t.Errorf("dae_group_last_failure_timestamp_seconds should be set")
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
