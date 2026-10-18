// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestDomainProjectionBatchRebuildAndFallback(t *testing.T) {
	for _, mode := range []string{"success", "unsupported", "partial", "retry"} {
		t.Run(mode, func(t *testing.T) {
			g, fake := newTestRegistry(600, time.Hour)
			now := time.Now()
			for i := range 600 {
				ip := netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)})
				g.Upsert(fmt.Sprintf("d%d.test.", i), ip, testBitmap(i%32), 3600, now)
			}
			clear(fake.bump)
			clear(fake.routing)
			batches, scalars := 0, 0
			failure := errors.New("batch unavailable")
			var failedIP netip.Addr
			g.kernel.batchUpdate = func(entries []domainMapEntry) error {
				batches++
				if len(entries) > 256 {
					t.Fatal("unbounded batch")
				}
				if mode == "unsupported" {
					return failure
				}
				for i, entry := range entries {
					if mode != "success" && i == len(entries)/2 {
						failedIP = entry.ip
						return failure
					}
					if err := fake.update(entry.ip, entry.bump, entry.routing); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}
			g.kernel.update = func(ip netip.Addr, bump, routing []uint32) error {
				scalars++
				if mode == "retry" && ip == failedIP {
					return failure
				}
				return fake.update(ip, bump, routing)
			}
			err := g.rebuildProjection(now)
			if mode == "retry" {
				if !errors.Is(err, failure) || len(g.kernel.pending) != 1 {
					t.Fatalf("partial retry state: %v, %d", err, len(g.kernel.pending))
				}
				g.kernel.update = fake.update
				g.retryProjection(now.Add(time.Second))
			} else if err != nil {
				t.Fatal(err)
			}
			if mode == "success" && (batches != 3 || scalars != 0) {
				t.Fatalf("batches=%d scalars=%d", batches, scalars)
			}
			if mode != "success" && (batches != 1 || scalars != 600) {
				t.Fatalf("fallback batches=%d scalars=%d", batches, scalars)
			}
			if len(g.kernel.pending) != 0 {
				t.Fatal("unfinished publication")
			}
			checkInvariants(t, g, fake)
		})
	}
}

func TestDomainProjectionBatchKeepsFailedRemovalCapacity(t *testing.T) {
	g, fake := newTestRegistry(2, time.Hour)
	now := time.Now()
	oldIP := netip.MustParseAddr("192.0.2.1")
	g.Upsert("old.test.", oldIP, testBitmap(0), 3600, now)
	failure := errors.New("removal failed")
	g.kernel.remove = func(netip.Addr) error { return failure }
	g.kernel.want(oldIP, nil, false)
	for _, ip := range []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")} {
		g.kernel.desired[ip] = domainBitmaps{testBitmap(1), testBitmap(1)}
		g.kernel.pending[ip] = domainPublication{}
	}
	g.kernel.batchUpdate = func(entries []domainMapEntry) error {
		if len(entries) != 1 {
			t.Fatalf("batch overbooked occupied slot: %d", len(entries))
		}
		return fake.update(entries[0].ip, entries[0].bump, entries[0].routing)
	}
	g.kernel.force = true
	g.kernel.publish(now)
	if len(g.kernel.resident) != 2 || len(fake.bump) != 2 || !fake.has(oldIP) || len(g.kernel.pending) != 2 {
		t.Fatal("failed removal freed capacity")
	}
}

// Private map only: no program attachment or host routing changes.
func TestDomainBitmapBatchKernelIntegration(t *testing.T) {
	m := newRoutingLayoutTestMap(t, "domain_routing_map", 4)
	core := &controlPlaneCore{bpf: &BPFState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{DomainRoutingMap: m}}}}
	entries := []domainMapEntry{
		{netip.MustParseAddr("192.0.2.1"), domainBitmaps{testBitmap(1, 2), testBitmap(1)}},
		{netip.MustParseAddr("2001:db8::1"), domainBitmaps{testBitmap(3), testBitmap()}},
	}
	if err := core.writeDomainBitmapBatch(entries); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		ip := entry.ip.As16()
		var got bpfDomainRouting
		if err := m.Lookup(ipv6BytesToWords(ip[:]), &got); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got.Bump[:], entry.bump) || !slices.Equal(got.Routing[:], entry.routing) {
			t.Fatal("batch changed bitmap encoding")
		}
	}
}
