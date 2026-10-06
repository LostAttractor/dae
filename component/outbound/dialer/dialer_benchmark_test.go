// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
)

// This isolates the healthy dialer's read path with latency history populated.
// Protocol Session snapshots are excluded; their work depends on the transport.
func BenchmarkDialerUsable(b *testing.B) {
	d := benchmarkDialerWithLatency()
	network := common.NetworkIndex(0).NetworkType()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !d.Usable(network) {
				b.Error("healthy dialer is not usable")
			}
		}
	})
}

func benchmarkDialerWithLatency() *Dialer {
	d := &Dialer{pathRuntime: &pathRuntime{ctx: context.Background(), health: healthHealthy}}
	d.RegisterDialerGroup(nil, 0.5, 0, 0)
	for i := range d.networks {
		d.networks[i] = networkSupported
	}
	for range 10 {
		d.group.recordLatency(time.Millisecond)
	}
	return d
}

func BenchmarkDialerSelectionSnapshot(b *testing.B) {
	d := benchmarkDialerWithLatency()
	network := common.NetworkIndex(0).NetworkType()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			snapshot := d.SelectionSnapshot(network)
			if !snapshot.Usable || !snapshot.HasLatency || snapshot.Latency.Avg10 != time.Millisecond {
				b.Error("incorrect latency snapshot")
			}
		}
	})
}

func BenchmarkDialerLatencyUpdateAndSnapshot(b *testing.B) {
	d := benchmarkDialerWithLatency()
	b.ReportAllocs()
	for b.Loop() {
		d.mu.Lock()
		d.group.recordLatency(time.Millisecond)
		_, ok := d.latencyStatsLocked()
		d.mu.Unlock()
		if !ok {
			b.Fatal("missing latency")
		}
	}
}

func BenchmarkSharedSuccessfulLatency(b *testing.B) {
	d := &Dialer{pathRuntime: new(pathRuntime), active: true}
	d.members = map[*Dialer]struct{}{d: {}}
	d.RegisterDialerGroup(nil, 0.5, 0, 0)
	b.ReportAllocs()
	for b.Loop() {
		d.mu.Lock()
		d.recordLatencyLocked(time.Millisecond, true)
		d.mu.Unlock()
	}
}
