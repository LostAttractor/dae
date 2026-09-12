// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"compress/gzip"
	"encoding/json/v2"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkDomainRegistry uses 1024 domains with four addresses each. Shared
// models eight names per IP, including zero-bit names that participate in AND.
// Kernel syscalls are excluded so the index/aggregation cost can be compared.
func BenchmarkDomainRegistry(b *testing.B) {
	for _, sharing := range []int{1, 8} {
		b.Run(fmt.Sprintf("names-per-IP=%d", sharing), func(b *testing.B) {
			now := time.Now()
			entries := make(map[string]map[string]time.Time, 1024)
			for domain := range 1024 {
				addresses := make(map[string]time.Time, 4)
				for offset := range 4 {
					i := domain/sharing*4 + offset + 1
					ip := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
					addresses[ip.String()] = now.Add(time.Hour)
				}
				entries[fmt.Sprintf("d%d.example.", domain)] = addresses
			}
			path := filepath.Join(b.TempDir(), "domain-registry.json.gz")
			f, err := os.Create(path)
			if err != nil {
				b.Fatal(err)
			}
			w := gzip.NewWriter(f)
			if err := json.MarshalWrite(w, entries, json.Deterministic(true)); err != nil {
				b.Fatal(err)
			}
			if err := w.Close(); err != nil {
				b.Fatal(err)
			}
			if err := f.Close(); err != nil {
				b.Fatal(err)
			}
			match := func(name string) []uint32 {
				bitmap := make([]uint32, domainBitmapWords())
				if !strings.HasSuffix(name, "0.example.") {
					bitmap[0] = 1
				}
				return bitmap
			}
			restore := func(b *testing.B) *DomainRegistry {
				g := newDomainRegistry(4096, time.Hour, func(netip.Addr, []uint32, []uint32) {}, func(netip.Addr) {})
				if err := g.Restore(path, match, now); err != nil {
					b.Fatal(err)
				}
				return g
			}
			for _, domain := range []string{"d0.example.", ""} {
				label := "named"
				if domain == "" {
					label = "unnamed"
				}
				b.Run(label, func(b *testing.B) {
					g := restore(b)
					ip := netip.MustParseAddr("198.18.0.1")
					at := now
					b.ReportAllocs()
					for b.Loop() {
						at = at.Add(time.Nanosecond)
						g.activity.observe(ip, domain, at)
					}
				})
			}
			b.Run("restore", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					restore(b)
				}
			})
		})
	}
}

// benchmarkActivityRegistry models a retained history with 2,553 domains,
// 28,042 pairs and 6,276 IPs (4,460 IPv4). Half the pairs share 128 hot IPs;
// the rest span the other IPs. Every eighth domain has a zero bitmap.
// Initialization and kernel syscalls are excluded from the timed workload.
func benchmarkActivityRegistry(b *testing.B) (*DomainRegistry, []domainActivityKey, time.Time) {
	b.Helper()
	now := time.Now()
	g := newDomainRegistry(65536, 168*time.Hour, func(netip.Addr, []uint32, []uint32) {}, func(netip.Addr) {})
	names := make([]string, 2553)
	bitmaps := make(map[string][]uint32, len(names))
	records := make(map[string]*domainRecord, len(names))
	for i := range names {
		name := fmt.Sprintf("d%d.example.", i)
		names[i] = name
		bitmap := testBitmap()
		if i%8 != 0 {
			rule := i % min(57, domainBitmapWords()*32)
			bitmap[rule/32] = 1 << (rule % 32)
		}
		bitmaps[name] = bitmap
		records[name] = &domainRecord{addresses: make(map[netip.Addr]*domainPair)}
	}
	ips := make([]netip.Addr, 6276)
	for i := range ips {
		if i < 4460 {
			ips[i] = netip.AddrFrom4([4]byte{198, 18, byte((i + 1) >> 8), byte(i + 1)})
		} else {
			ips[i] = netip.AddrFrom16([16]byte{0x20, 1, 0x0d, 0xb8, 14: byte(i >> 8), 15: byte(i)})
		}
	}
	var keys []domainActivityKey
	for i := range 28042 {
		domain := i % len(names)
		index := i % (len(ips) - 128)
		if i >= 14021 {
			index = len(ips) - 128 + i%128
		}
		ip, name := ips[index], names[domain]
		records[name].addresses[ip] = &domainPair{retainUntil: now.Add(2 * g.window)}
		if domain%8 != 0 {
			keys = append(keys, domainActivityKey{ip: ip, domain: name})
		}
	}
	g.installRecords(records, func(name string) []uint32 { return bitmaps[name] })
	g.rebuildProjection(g.clock(now))
	if usage := g.Usage(); usage.UserUsed != 28042 || usage.IPs != len(ips) || usage.Domains != len(names) {
		b.Fatalf("unexpected workload shape: %+v", usage)
	}
	return g, keys, now
}

func BenchmarkDomainRegistryActivity(b *testing.B) {
	unknownIP := netip.MustParseAddr("203.0.113.1")
	bitmap := testBitmap(0)
	// The DNS observer supplies an already assembled address slice. Prepare it
	// outside timing so this case measures Registry work, not fixture allocation.
	dnsObservation := []domainObservation{{ips: make([]netip.Addr, 1), bitmap: bitmap, ttl: 60}}
	for _, workload := range []struct {
		name    string
		refresh bool
		observe func(*DomainRegistry, domainActivityKey, time.Time)
	}{
		{"unknown-name", false, func(g *DomainRegistry, key domainActivityKey, at time.Time) {
			g.activity.observe(key.ip, "unknown.example.", at)
		}},
		{"unknown-ip", false, func(g *DomainRegistry, _ domainActivityKey, at time.Time) {
			g.activity.observe(unknownIP, "", at)
		}},
		{"named-unchanged", false, func(g *DomainRegistry, key domainActivityKey, at time.Time) {
			g.activity.observe(key.ip, key.domain, at)
		}},
		{"unnamed-unchanged", false, func(g *DomainRegistry, key domainActivityKey, at time.Time) {
			g.activity.observe(key.ip, "", at)
		}},
		{"dns-unchanged", false, func(g *DomainRegistry, key domainActivityKey, at time.Time) {
			dnsObservation[0].name, dnsObservation[0].ips[0] = key.domain, key.ip
			g.ObserveDNS(dnsObservation, at)
		}},
		{"sweep-before-expiry", false, func(g *DomainRegistry, _ domainActivityKey, at time.Time) {
			g.Sweep(at)
		}},
		{"named-refresh", true, func(g *DomainRegistry, key domainActivityKey, at time.Time) {
			g.activity.observe(key.ip, key.domain, at)
		}},
		{"unnamed-refresh", true, func(g *DomainRegistry, key domainActivityKey, at time.Time) {
			g.activity.observe(key.ip, "", at)
		}},
	} {
		b.Run(workload.name, func(b *testing.B) {
			g, keys, at := benchmarkActivityRegistry(b)
			if workload.refresh {
				at = at.Add(g.window)
			}
			i := 0
			b.ReportAllocs()
			for b.Loop() {
				at = at.Add(time.Nanosecond)
				workload.observe(g, keys[i%len(keys)], at)
				i++
			}
		})
	}
}

// Run with -cpu=1,8,32 to measure contention. One quarter of observations
// extend a known pair; the rest are unchanged, unknown-name or unknown-IP.
// Tail latency includes waiting for both registry/activity locks. Allocation
// metrics here also include the latency samples; the serial benchmark isolates
// observation allocations without sampling overhead.
func BenchmarkDomainRegistryContention(b *testing.B) {
	g, keys, now := benchmarkActivityRegistry(b)
	unknownIP := netip.MustParseAddr("203.0.113.1")
	var sequence atomic.Uint64
	var mu sync.Mutex
	var latencies []time.Duration
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var samples []time.Duration
		for pb.Next() {
			start := time.Now()
			i := sequence.Add(1) - 1
			key := keys[i%uint64(len(keys))]
			at := now.Add(time.Duration(i + 1))
			switch i % 4 {
			case 0:
				g.activity.observe(key.ip, key.domain, at.Add(g.window))
			case 1:
				g.activity.observe(key.ip, key.domain, at)
			case 2:
				g.activity.observe(key.ip, "unknown.example.", at)
			case 3:
				g.activity.observe(unknownIP, "", at)
			}
			samples = append(samples, time.Since(start))
		}
		mu.Lock()
		latencies = append(latencies, samples...)
		mu.Unlock()
	})
	b.StopTimer()
	slices.Sort(latencies)
	b.ReportMetric(float64(latencies[(len(latencies)-1)*95/100]), "p95-ns")
	b.ReportMetric(float64(latencies[(len(latencies)-1)*99/100]), "p99-ns")
}

// Use a fixed operation count to compare exactly the same replacements.
func BenchmarkDomainRegistryCapacity(b *testing.B) {
	for _, replace := range []bool{false, true} {
		label := "resident-refresh"
		if replace {
			label = "replace-resident"
		}
		b.Run(label, func(b *testing.B) {
			g, keys, at := benchmarkActivityRegistry(b)
			g.kernel.max = 1
			g.rebuildProjection(at)
			var resident, omitted domainActivityKey
			for _, key := range keys {
				if _, ok := g.kernel.resident[key.ip]; ok {
					resident = key
				} else {
					omitted = key
				}
			}
			at = at.Add(g.window)
			i := 0
			b.ReportAllocs()
			for b.Loop() {
				key := resident
				if replace && i%2 != 0 {
					key = omitted
				}
				at = at.Add(time.Nanosecond)
				g.activity.observe(key.ip, key.domain, at)
				i++
			}
		})
	}
}

// Registry-only retained heap after fixture temporaries have been collected.
// Run separately with -benchtime=1x; retained-* metrics exclude fixture keys.
func BenchmarkDomainRegistryFootprint(b *testing.B) {
	for b.Loop() {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		g, _, _ := benchmarkActivityRegistry(b)
		runtime.GC()
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(g)
		b.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc)), "retained-bytes")
		b.ReportMetric(float64(int64(after.HeapObjects)-int64(before.HeapObjects)), "retained-objects")
	}
}

// Repeated I/O from 64 connections to shared IPs. Sweep at each batch boundary
// includes application work in the timing, even with no background worker.
func BenchmarkDomainActivityBatch(b *testing.B) {
	for _, named := range []bool{true, false} {
		label := "unnamed"
		if named {
			label = "named"
		}
		b.Run(label, func(b *testing.B) {
			g, keys, _ := benchmarkActivityRegistry(b)
			g.window *= 3 // Current-time I/O really extends the fixture's deadlines.
			callbacks := make([]func(), 64)
			for i := range callbacks {
				key := keys[len(keys)-len(callbacks)+i]
				if !named {
					key.domain = ""
				}
				callbacks[i] = g.activity.connection(key.ip, key.domain)
			}
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				callbacks[i%len(callbacks)]()
				i++
				if i%1024 == 0 {
					g.Sweep(time.Now())
				}
			}
			g.Sweep(time.Now())
		})
	}
}

// Foreground latency includes queue admission, not delayed state visibility.
// Throughput includes the worker's CPU and Close draining the final batch.
func BenchmarkDomainActivityIOContention(b *testing.B) {
	g, keys, _ := benchmarkActivityRegistry(b)
	g.window *= 3
	callbacks := make([]func(), 64)
	for i := range callbacks {
		key := keys[len(keys)-len(callbacks)+i]
		if i%2 == 0 {
			key.domain = ""
		}
		callbacks[i] = g.activity.connection(key.ip, key.domain)
	}
	g.Start()
	var mu sync.Mutex
	var latencies []time.Duration
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var samples []time.Duration
		i := 0
		for pb.Next() {
			start := time.Now()
			callbacks[i%len(callbacks)]()
			samples = append(samples, time.Since(start))
			i++
		}
		mu.Lock()
		latencies = append(latencies, samples...)
		mu.Unlock()
	})
	if err := g.Close(); err != nil {
		b.Fatal(err)
	}
	b.StopTimer()
	slices.Sort(latencies)
	b.ReportMetric(float64(latencies[(len(latencies)-1)*95/100]), "p95-ns")
	b.ReportMetric(float64(latencies[(len(latencies)-1)*99/100]), "p99-ns")
}

// Stable per-worker destinations model independent connections. The single-IP
// case deliberately keeps every producer on the same key. Sample 1/64 calls so
// recording latency does not dominate the short enqueue path.
func BenchmarkDomainActivityQueue(b *testing.B) {
	for _, single := range []bool{false, true} {
		name := "many-targets"
		if single {
			name = "single-IP"
		}
		b.Run(name, func(b *testing.B) {
			g, keys, _ := benchmarkActivityRegistry(b)
			g.window *= 3
			callbacks := make([]func(), 64)
			for i := range callbacks {
				key := keys[len(keys)-len(callbacks)+i]
				if single {
					key = keys[len(keys)-1]
				}
				if single || i%2 == 0 {
					key.domain = ""
				}
				callbacks[i] = g.activity.connection(key.ip, key.domain)
			}
			g.Start()
			var worker atomic.Uint64
			var mu sync.Mutex
			var latencies []time.Duration
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				observe := callbacks[(worker.Add(1)-1)%uint64(len(callbacks))]
				var samples []time.Duration
				i := 0
				for pb.Next() {
					if i%64 == 0 {
						start := time.Now()
						observe()
						samples = append(samples, time.Since(start))
					} else {
						observe()
					}
					i++
				}
				mu.Lock()
				latencies = append(latencies, samples...)
				mu.Unlock()
			})
			if err := g.Close(); err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
			slices.Sort(latencies)
			b.ReportMetric(float64(latencies[(len(latencies)-1)*95/100]), "p95-ns")
			b.ReportMetric(float64(latencies[(len(latencies)-1)*99/100]), "p99-ns")
		})
	}
}
