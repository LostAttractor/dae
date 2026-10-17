// SPDX-License-Identifier: AGPL-3.0-only

package stats

import (
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/api"
)

func TestSamplingLifecyclePreservesTrafficAndDeviceHistory(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := newStoreAt(time.Now())
		path := trafficTestPath(t.Name())
		mac := [6]byte{2, 1}
		connection := store.OpenDeviceConnection(path, false, mac)
		defer connection.Close()
		assertTraffic := func(total uint64, history ...uint64) {
			t.Helper()
			device, _ := store.DeviceSnapshot(mac)
			for _, snapshot := range []api.PathStats{store.SnapshotWithHistory()[path], device[path]} {
				if snapshot.UploadBytes != total || snapshot.TotalConnections != 1 {
					t.Fatalf("traffic changed across sampler lifecycle: %+v", snapshot)
				}
				if !slices.Equal(snapshot.History.UploadBytesPerSecond, history) {
					t.Fatalf("history = %v, want %v", snapshot.History.UploadBytesPerSecond, history)
				}
			}
		}

		// Recording works before startup, with no implicit background sampling.
		connection.RecordUpload(1500)
		time.Sleep(2 * api.TrafficHistoryInterval)
		synctest.Wait()
		assertTraffic(1500)

		stop, err := store.StartSampling()
		if err != nil {
			t.Fatal(err)
		}
		defer stop()
		if duplicate, err := store.StartSampling(); err == nil {
			duplicate()
			t.Fatal("duplicate sampler was accepted")
		}
		time.Sleep(api.TrafficHistoryInterval)
		synctest.Wait()
		assertTraffic(1500, 100)

		// A control-plane reload does not own or reset the sampler.
		store.Reconcile(map[string]NodeIdentity{"node": {Name: "node"}}, nil)
		store.RecordNodeState("node", true, time.Time{})
		store.RecordReload()
		connection.RecordUpload(500)
		time.Sleep(api.TrafficHistoryInterval)
		synctest.Wait()
		assertTraffic(2000, 100, 100)

		// Every concurrent stop waits for exit; no later tick may mutate history.
		var stops sync.WaitGroup
		for range 4 {
			stops.Go(stop)
		}
		stops.Wait()
		connection.RecordUpload(750)
		time.Sleep(2 * api.TrafficHistoryInterval)
		synctest.Wait()
		assertTraffic(2750, 100, 100)

		restarted, err := store.StartSampling()
		if err != nil {
			t.Fatal(err)
		}
		defer restarted()
		stop() // An old owner cannot stop a new sampler.
		time.Sleep(api.TrafficHistoryInterval)
		synctest.Wait()
		assertTraffic(2750, 100, 100, 50)
		if !store.GetNode("node").Alive || store.LastReload().IsZero() {
			t.Fatal("sampler lifecycle discarded availability or process state")
		}
	})
}
