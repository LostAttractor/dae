// SPDX-License-Identifier: AGPL-3.0-only

package stats

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
)

func TestDeviceTrafficIsolationExternalCountersAndReload(t *testing.T) {
	store := newStoreAt(time.Now())
	path := trafficTestPath(t.Name())
	a, b := [6]byte{2, 0, 0, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 2}
	first := store.OpenDeviceConnection(path, true, a)
	second := store.OpenDeviceConnection(path, false, b)
	daemon := store.OpenDeviceConnection(path, false, [6]byte{})
	first.RecordUpload(100)
	second.RecordUpload(200)
	daemon.RecordUpload(400)
	external := api.TrafficCounters{UploadBytes: 300, DownloadBytes: 500}
	if err := first.AttachExternalCounters(func() (api.TrafficCounters, error) { return external, nil }); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		got, fallback := store.DeviceSnapshot(a)
		if got[path].UploadBytes != 400 || got[path].DownloadBytes != 500 || fallback != 1 || got[path].ActiveConnections != 1 {
			t.Fatalf("first device (including splice) = %+v, fallback=%d", got, fallback)
		}
	}
	got, fallback := store.DeviceSnapshot(b)
	if got[path].UploadBytes != 200 || got[path].DownloadBytes != 0 || fallback != 0 {
		t.Fatalf("second device includes another device: %+v", got)
	}
	if total := store.Snapshot()[path]; total.UploadBytes != 1000 || total.TotalConnections != 3 {
		t.Fatalf("global counts were duplicated: %+v", total)
	}
	store.RecordReload()
	external.UploadBytes += 50
	first.Close()
	first.Close()
	second.Close()
	daemon.Close()
	got, _ = store.DeviceSnapshot(a)
	if got[path].UploadBytes != 450 || got[path].ActiveConnections != 0 || got[path].TotalConnections != 1 {
		t.Fatalf("close/reload lost attribution: %+v", got)
	}
	if unknown, _ := store.DeviceSnapshot([6]byte{2, 3}); len(unknown) != 0 || len(store.devices) != 2 {
		t.Fatal("unseen device query allocated or exposed counters")
	}
}

func TestDeviceExternalFailureInvalidatesOnlyItsRate(t *testing.T) {
	start := time.Now()
	store := newStoreAt(start)
	path := trafficTestPath(t.Name())
	mac := [6]byte{2, 1}
	connection := store.OpenDeviceConnection(path, false, mac)
	defer connection.Close()
	store.devices[mac].windowStartedAt = start
	fail := true
	connection.AttachExternalCounters(func() (api.TrafficCounters, error) {
		if fail {
			return api.TrafficCounters{}, errors.New("unavailable")
		}
		return api.TrafficCounters{UploadBytes: 1000}, nil
	})
	store.sampleAt(start.Add(5 * time.Second))
	fail = false
	store.sampleAt(start.Add(10 * time.Second))
	connection.RecordUpload(500)
	store.sampleAt(start.Add(15 * time.Second))
	got, _ := store.DeviceSnapshot(mac)
	history := got[path].History.UploadBytesPerSecond
	if len(history) != 3 || history[0] != 0 || history[1] != 0 || history[2] != 100 {
		t.Fatalf("invalid external delta became a device rate: %v", history)
	}
}

func TestDeviceConnectionsConcurrentSnapshots(t *testing.T) {
	store := newStoreAt(time.Now())
	path := trafficTestPath(t.Name())
	mac := [6]byte{2, 2}
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 200 {
				connection := store.OpenDeviceConnection(path, false, mac)
				connection.RecordUpload(10)
				store.DeviceSnapshot(mac)
				connection.Close()
			}
		})
	}
	workers.Wait()
	got, _ := store.DeviceSnapshot(mac)
	if got[path].UploadBytes != 8000 || got[path].TotalConnections != 800 || got[path].ActiveConnections != 0 {
		t.Fatalf("concurrent attribution = %+v", got)
	}
}
