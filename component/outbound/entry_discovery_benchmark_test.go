//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// The controlled-delay cases measure scheduling, not Internet DNS latency.
// The DNS cases perform real loopback DNS and kernel route/source queries.
func BenchmarkEntryDiscovery(b *testing.B) {
	for _, scenario := range []struct {
		name          string
		paths, unique int
		delay         time.Duration
		dns           bool
	}{
		{"cpu_shared", 1024, 32, 0, false},
		{"cpu_unique", 256, 256, 0, false},
		{"delay_shared", 128, 16, time.Millisecond, false},
		{"delay_unique", 128, 128, time.Millisecond, false},
		{"dns_shared", 128, 16, 0, true},
		{"dns_unique", 32, 32, 0, true},
	} {
		b.Run(scenario.name, func(b *testing.B) {
			paths := make([]*PathSpec, scenario.paths)
			for i := range paths {
				paths[i] = &PathSpec{Nodes: []*NodeInfo{{Property: &dialer.Property{
					Name: fmt.Sprintf("node-%d", i), Address: fmt.Sprintf("entry-%d.test.:1080", i%scenario.unique),
				}}}}
			}
			option := new(dialer.GlobalOption)
			var queries *atomic.Int32
			if scenario.dns {
				mask := new(atomic.Uint32)
				mask.Store(uint32(family4))
				option.DNSResolver, queries = entryTestDNS(b, mask)
			}
			var calls, active, peak atomic.Int64
			discover := func(ctx context.Context, path *PathSpec) (uint8, error) {
				calls.Add(1)
				n := active.Add(1)
				defer active.Add(-1)
				for old := peak.Load(); n > old; old = peak.Load() {
					if peak.CompareAndSwap(old, n) {
						break
					}
				}
				if scenario.dns {
					return path.availableEntryFamilies(ctx, option, entryAddressUsable)
				}
				if scenario.delay > 0 {
					timer := time.NewTimer(scenario.delay)
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-ctx.Done():
						return 0, ctx.Err()
					}
				}
				return family4, nil
			}
			b.ReportAllocs()
			for b.Loop() {
				variants, err := expandIPVariants(b.Context(), paths, discover)
				if err != nil || len(variants) != len(paths) {
					b.Fatalf("expansion: %d candidates, %v", len(variants), err)
				}
			}
			b.ReportMetric(float64(calls.Load())/float64(b.N), "lookups/op")
			b.ReportMetric(float64(peak.Load()), "peak-lookups")
			if queries != nil {
				b.ReportMetric(float64(queries.Load())/float64(b.N), "dns-queries/op")
			}
		})
	}
}
