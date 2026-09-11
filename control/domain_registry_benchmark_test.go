// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"compress/gzip"
	"encoding/json/v2"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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
