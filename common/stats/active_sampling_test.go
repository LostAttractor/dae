// SPDX-License-Identifier: AGPL-3.0-only

package stats

import (
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
)

func TestSamplingRetiresIdlePathsAndCollectsLateDeviceTraffic(t *testing.T) {
	now := time.Now()
	store := newStoreAt(now)
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	path := trafficTestPath("closed")
	connection := store.OpenDeviceConnection(path, false, mac)
	connection.RecordUpload(50)
	connection.Close()
	store.sampleAt(now.Add(api.TrafficHistoryInterval))
	if len(store.samplePaths) != 0 || len(store.devices[mac].samplePaths) != 0 {
		t.Fatal("idle paths remain enrolled")
	}
	connection.RecordUpload(100)
	connection.RecordDownload(200)
	store.sampleAt(now.Add(2 * api.TrafficHistoryInterval))
	global := store.SnapshotWithHistory()[path]
	device, _ := store.DeviceSnapshot(mac)
	if global.UploadBytes != 150 || global.DownloadBytes != 200 || !slices.Equal(global.History.UploadBytesPerSecond, []uint64{10, 20}) || !slices.Equal(global.History.DownloadBytesPerSecond, []uint64{0, 40}) {
		t.Fatal(global)
	}
	if device[path].TrafficCounters != global.TrafficCounters || !slices.Equal(device[path].History.UploadBytesPerSecond, global.History.UploadBytesPerSecond) {
		t.Fatal(device[path], global)
	}
	if len(store.samplePaths) != 0 || len(store.paths) != 1 {
		t.Fatal("retirement dropped totals or retained work")
	}
}

func TestSamplingRetirementRacesLateWrites(t *testing.T) {
	now := time.Now()
	store := newStoreAt(now)
	connection := store.OpenConnection(trafficTestPath("late"), false)
	connection.Close()
	var writers sync.WaitGroup
	for range 4 {
		writers.Go(func() {
			for range 10000 {
				connection.RecordUpload(1)
				connection.RecordDownload(2)
			}
		})
	}
	for range 1000 {
		now = now.Add(time.Second)
		store.sampleAt(now)
	}
	writers.Wait()
	store.sampleAt(now.Add(time.Second))
	if connection.stats.lastSample.UploadBytes != 40000 || connection.stats.lastSample.DownloadBytes != 80000 || len(store.samplePaths) != 0 {
		t.Fatal(connection.stats.lastSample, len(store.samplePaths))
	}
}

func TestActiveTrafficDoesNotAcquireSamplingLock(t *testing.T) {
	store := newStoreAt(time.Now())
	connection := store.OpenConnection(trafficTestPath("active"), false)
	defer connection.Close()
	store.samplePathsMu.Lock()
	defer store.samplePathsMu.Unlock()
	connection.RecordUpload(1)
	connection.RecordDownload(1)
}

func BenchmarkTrafficSampleFixedActivity(b *testing.B) {
	for _, historical := range []int{100, 10000} {
		for _, active := range []int{0, 32} {
			b.Run(fmt.Sprintf("historical=%d/active=%d", historical, active), func(b *testing.B) {
				store, now := benchmarkTrafficStore(historical)
				for i := range active {
					store.OpenConnection(trafficTestPath(fmt.Sprint("active-", i)), false)
				}
				now = now.Add(api.TrafficHistoryInterval)
				store.sampleAt(now)
				b.ReportAllocs()
				for b.Loop() {
					now = now.Add(api.TrafficHistoryInterval)
					store.sampleAt(now)
				}
			})
		}
	}
}
