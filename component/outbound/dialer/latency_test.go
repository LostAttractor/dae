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
	d := &Dialer{pathRuntime: new(pathRuntime), active: true}
	d.members = map[*Dialer]struct{}{d: {}}
	if _, ok := d.latencyStats(); ok {
		t.Fatal("unbound dialer has latency")
	}
	d.RegisterDialerGroup(nil, 0.5, 0, 0)
	if _, ok := d.latencyStats(); ok {
		t.Fatal("new binding has latency")
	}
	var history []time.Duration
	var movingAverage time.Duration
	for i := range 64 {
		sample := time.Duration((i*37)%31) * time.Millisecond // Includes valid zero latency.
		failed := i%17 == 2
		d.mu.Lock()
		d.recordLatencyLocked(sample, !failed)
		d.mu.Unlock()
		if !failed {
			history = append(history, sample)
		}
		window := history[max(0, len(history)-10):]
		want := api.LatencyStats{Last: history[len(history)-1]}
		for _, observation := range window {
			want.Avg10 += observation
		}
		want.Avg10 /= time.Duration(len(window))
		if len(history) == 1 {
			movingAverage = sample
		} else if !failed {
			movingAverage = time.Duration(float64(movingAverage)*0.5 + float64(sample)*0.5)
		}
		want.MovingAvg = movingAverage
		got, ok := d.latencyStats()
		if !ok || got != want {
			t.Fatalf("sample %d: got %+v, %v; want %+v", i, got, ok, want)
		}
	}
	d.RegisterDialerGroup(nil, 0.5, 0, 0)
	if _, ok := d.latencyStats(); ok {
		t.Fatal("replacement binding inherited old latency samples")
	}
}

func TestDialerLatencyConcurrentSnapshots(t *testing.T) {
	d := &Dialer{pathRuntime: &pathRuntime{ctx: context.Background(), health: pathHealth{phase: healthHealthy}}}
	d.RegisterDialerGroup(nil, 0.5, 0, 0)
	network := common.NetworkIndex(0).NetworkType()
	d.health.networks[network.Index()] = networkSupported
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 100 {
				d.mu.Lock()
				d.group.latency.record(time.Millisecond)
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
	if !ok || latency.Avg10 != time.Millisecond {
		t.Fatalf("final latency: %+v, %v", latency, ok)
	}
}
