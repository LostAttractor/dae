// SPDX-License-Identifier: AGPL-3.0-only

package stats

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/prometheus/client_golang/prometheus"
)

func TestRetirementPreservesProcessTotalsAndCurrentPaths(t *testing.T) {
	now := time.Now()
	store := newStoreAt(now)
	current := trafficTestPath("current")
	current.NodeID = NodeID("current")
	old := trafficTestPath("removed")
	live := trafficTestPath("draining")
	failed := trafficTestPath("failed")
	store.Reconcile(map[string]NodeIdentity{"current": {Name: current.Dialer, Subtag: current.Subtag}}, map[string]struct{}{current.Outbound: {}})
	for _, path := range []Path{current, old} {
		c := store.OpenConnection(path, true)
		c.RecordUpload(100)
		c.RecordDownload(200)
		c.Close()
		store.RecordDial(path, time.Millisecond)
		store.RecordError(path)
	}
	connection := store.OpenConnection(live, false)
	store.RecordError(failed)
	for range api.TrafficHistorySampleCount + 1 {
		now = now.Add(api.TrafficHistoryInterval)
		store.sampleAt(now)
	}
	snapshot := store.TrafficSnapshot()
	if len(snapshot.Paths) != 2 || snapshot.Paths[current].TotalConnections != 1 || snapshot.Paths[live].ActiveConnections != 1 {
		t.Fatalf("retained detail = %+v", snapshot.Paths)
	}
	totals := snapshot.Networks[common.NetworkTCP4]
	if totals.TotalConnections != 3 || totals.ActiveConnections != 1 || totals.UploadBytes != 200 || totals.DownloadBytes != 400 || snapshot.DirectFallbackConnections != 2 {
		t.Fatalf("retirement lost totals: %+v", snapshot)
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(store)
	for _, name := range []string{"dae_connections_total", "dae_traffic_bytes_total", "dae_dial_duration_seconds", "dae_path_errors_total"} {
		if _, ok := gatheredPathMetric(t, registry, name, old, nil); ok {
			t.Fatalf("retired path retained %s", name)
		}
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var upload float64
	for _, family := range families {
		if family.GetName() != "dae_process_traffic_bytes_total" {
			continue
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "direction" && label.GetValue() == "upload" {
					upload += metric.GetCounter().GetValue()
				}
			}
		}
	}
	if upload != float64(totals.UploadBytes) {
		t.Fatalf("Prometheus total = %v, status = %v", upload, totals.UploadBytes)
	}
	reopened := store.OpenConnection(old, false)
	reopened.RecordUpload(25)
	reopened.Close()
	connection.Close()
	if total := store.TrafficSnapshot().Networks[common.NetworkTCP4]; total.TotalConnections != 4 || total.ActiveConnections != 0 || total.UploadBytes != 225 {
		t.Fatalf("reappearing path reset or doubled totals: %+v", total)
	}
}

func TestIdleDeviceRetirementStartsNewObservation(t *testing.T) {
	now := time.Now()
	store := newStoreAt(now)
	path := trafficTestPath("device")
	mac := [6]byte{2, 1}
	connection := store.OpenDeviceConnection(path, true, mac)
	connection.RecordUpload(100)
	first := store.devices[mac]
	connection.Close()
	for range api.TrafficHistorySampleCount + 1 {
		now = now.Add(api.TrafficHistoryInterval)
		store.sampleAt(now)
	}
	if len(store.devices) != 0 {
		t.Fatal("idle devices retained")
	}
	if snapshot := store.DeviceTrafficSnapshot(mac); len(snapshot.Paths) != 0 || !snapshot.StartedAt.IsZero() {
		t.Fatal("expired device still has observation")
	}
	returned := store.OpenDeviceConnection(path, false, mac)
	defer returned.Close()
	returned.RecordUpload(50)
	snapshot := store.DeviceTrafficSnapshot(mac)
	if store.devices[mac] == first || snapshot.Networks[path.Network].UploadBytes != 50 || snapshot.DirectFallbackConnections != 0 {
		t.Fatal("new device observation reused retired counters")
	}
	if total := store.TrafficSnapshot().Networks[path.Network]; total.UploadBytes != 150 || total.TotalConnections != 2 {
		t.Fatal(total)
	}
}

func TestRetirementConcurrentWithAdmissionAndSnapshots(t *testing.T) {
	now := time.Now()
	store := newStoreAt(now)
	var workers sync.WaitGroup
	for i := range 4 {
		workers.Go(func() {
			path := trafficTestPath(fmt.Sprint(i))
			mac := [6]byte{2, byte(i)}
			for range 500 {
				connection := store.OpenDeviceConnection(path, false, mac)
				connection.RecordUpload(3)
				store.DeviceTrafficSnapshot(mac)
				connection.Close()
			}
		})
	}
	for range 100 {
		now = now.Add(api.TrafficHistoryInterval)
		store.sampleAt(now)
		store.TrafficSnapshot()
		store.Reconcile(nil, nil)
	}
	workers.Wait()
	for range api.TrafficHistorySampleCount + 1 {
		now = now.Add(api.TrafficHistoryInterval)
		store.sampleAt(now)
	}
	snapshot := store.TrafficSnapshot()
	if len(snapshot.Paths) != 0 || len(store.devices) != 0 || snapshot.Networks[common.NetworkTCP4].UploadBytes != 6000 || snapshot.Networks[common.NetworkTCP4].TotalConnections != 2000 {
		t.Fatalf("lost or retained traffic: %+v", snapshot)
	}
}

func BenchmarkRetiredTrafficSnapshot(b *testing.B) {
	for _, count := range []int{100, 10000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			store, now := benchmarkTrafficStore(count)
			for range api.TrafficHistorySampleCount + 1 {
				now = now.Add(api.TrafficHistoryInterval)
				store.sampleAt(now)
			}
			b.ReportAllocs()
			for b.Loop() {
				benchmarkTrafficSnapshot = store.TrafficSnapshot().Paths
			}
		})
	}
}

func TestRetiredNodeKeepsCurrentGroupTotals(t *testing.T) {
	now := time.Now()
	store := newStoreAt(now)
	path := trafficTestPath("removed-node")
	store.Reconcile(nil, map[string]struct{}{path.Outbound: {}})
	connection := store.OpenConnection(path, false)
	connection.RecordUpload(123)
	connection.Close()
	for range api.TrafficHistorySampleCount + 1 {
		now = now.Add(api.TrafficHistoryInterval)
		store.sampleAt(now)
	}
	snapshot := store.TrafficSnapshot()
	if len(snapshot.Paths) != 0 || snapshot.RetiredGroups[path.Outbound][path.Network].UploadBytes != 123 {
		t.Fatalf("retiring a node lost current group totals: %+v", snapshot)
	}
	store.Reconcile(nil, nil)
	if len(store.TrafficSnapshot().RetiredGroups) != 0 {
		t.Fatal("removed group retained detail")
	}
	if store.TrafficSnapshot().Networks[path.Network].UploadBytes != 123 {
		t.Fatal("removing group lost process total")
	}
}
