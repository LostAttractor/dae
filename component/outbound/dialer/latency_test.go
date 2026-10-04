// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
)

func TestDialerLatencyWindow(t *testing.T) {
	d := &Dialer{pathRuntime: new(pathRuntime)}
	if _, ok := d.latencyStats(); ok {
		t.Fatal("unbound dialer has latency")
	}
	d.RegisterDialerGroup(nil, 0.5, time.Second)
	if _, ok := d.latencyStats(); ok {
		t.Fatal("new binding has latency")
	}
	type observation struct {
		latency time.Duration
		failed  bool
	}
	var history []observation
	var movingAverage time.Duration
	for i := range 64 {
		sample := time.Duration((i*37)%31) * time.Millisecond // Includes valid zero latency.
		failed := i%17 == 2
		d.mu.Lock()
		d.group.recordLatency(sample, !failed)
		d.mu.Unlock()
		if failed {
			sample = time.Second
		}
		history = append(history, observation{sample, failed})
		window := history[max(0, len(history)-10):]
		want := api.LatencyStats{Last: sample}
		for _, observation := range window {
			want.Avg10 += observation.latency
			want.Avg10HasFailure = want.Avg10HasFailure || observation.failed
		}
		want.Avg10 /= time.Duration(len(window))
		if movingAverage == 0 {
			movingAverage = sample
		} else {
			movingAverage = time.Duration(float64(movingAverage)*0.5 + float64(sample)*0.5)
		}
		want.MovingAvg = movingAverage
		got, ok := d.latencyStats()
		if !ok || got != want {
			t.Fatalf("sample %d: got %+v, %v; want %+v", i, got, ok, want)
		}
	}
	d.RegisterDialerGroup(nil, 0.5, time.Second)
	if _, ok := d.latencyStats(); ok {
		t.Fatal("replacement binding inherited old latency samples")
	}
}

func TestDialerLatencyConcurrentSnapshots(t *testing.T) {
	d := &Dialer{pathRuntime: &pathRuntime{ctx: context.Background(), health: healthHealthy}}
	d.RegisterDialerGroup(nil, 0.5, time.Second)
	network := common.NetworkIndex(0).NetworkType()
	d.networks[network.Index()] = networkSupported
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 100 {
				d.mu.Lock()
				d.group.recordLatency(time.Millisecond, true)
				d.mu.Unlock()
			}
		})
		workers.Go(func() {
			for range 100 {
				snapshot := d.SelectionSnapshot(network)
				if !snapshot.Usable {
					t.Error("healthy dialer became unavailable")
				}
				if snapshot.HasLatency && snapshot.Latency != (api.LatencyStats{Last: time.Millisecond, Avg10: time.Millisecond, MovingAvg: time.Millisecond}) {
					t.Errorf("incoherent concurrent snapshot: %+v", snapshot)
				}
			}
		})
	}
	workers.Wait()
	latency, ok := d.latencyStats()
	if !ok || latency.Avg10 != time.Millisecond || latency.Avg10HasFailure {
		t.Fatalf("final latency: %+v, %v", latency, ok)
	}
}
