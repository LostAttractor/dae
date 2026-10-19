// SPDX-License-Identifier: AGPL-3.0-only

package netutils

import (
	"fmt"
	"net"
	"testing"

	"github.com/daeuniverse/dae/pkg/dnscache"
	dns "github.com/miekg/dns"
)

// Include the standard resolver and a real loopback DNS server. The cached
// case is warm; zero-TTL responses measure the uncached transaction overhead.
func BenchmarkResolverCacheLookup(b *testing.B) {
	for _, network := range []string{"ip4", "ip"} {
		for _, ttl := range []uint32{60, 0} {
			for _, cached := range []bool{false, true} {
				b.Run(fmt.Sprintf("%s/ttl=%d/cache=%t", network, ttl, cached), func(b *testing.B) {
					dial, calls := cacheTestServer(b, func(_ string, q *dns.Msg) *dns.Msg {
						r := cacheTestReply(q)
						r.Answer[0].Header().Ttl = ttl
						return r
					})
					if cached {
						dial = cacheDNSDial(dnscache.New(4096, 8<<20), dial)
					}
					resolver := &net.Resolver{PreferGo: true, Dial: dial}
					if _, err := resolver.LookupNetIP(b.Context(), network, "node.cache.test."); err != nil {
						b.Fatal(err)
					}
					start := calls.Load()
					b.ReportAllocs()
					for b.Loop() {
						if _, err := resolver.LookupNetIP(b.Context(), network, "node.cache.test."); err != nil {
							b.Fatal(err)
						}
					}
					b.ReportMetric(float64(calls.Load()-start)/float64(b.N), "dns_dials/op")
				})
			}
		}
	}
}

// Include DNS resolution and physical TCP connection establishment, with a
// local peer instead of variable external network latency.
func BenchmarkResolverCacheTCPDial(b *testing.B) {
	for _, cached := range []bool{false, true} {
		b.Run(fmt.Sprintf("cache=%t", cached), func(b *testing.B) {
			dial, calls := cacheTestServer(b, func(_ string, q *dns.Msg) *dns.Msg {
				r := cacheTestReply(q)
				r.Answer[0].(*dns.A).A = net.IPv4(127, 0, 0, 1)
				return r
			})
			if cached {
				dial = cacheDNSDial(dnscache.New(4096, 8<<20), dial)
			}
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					_ = conn.Close()
				}
			}()
			b.Cleanup(func() { _ = listener.Close(); <-done })
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			address := net.JoinHostPort("node.cache.test.", port)
			dialer := &net.Dialer{Resolver: &net.Resolver{PreferGo: true, Dial: dial}}
			conn, err := dialer.DialContext(b.Context(), "tcp4", address)
			if err != nil {
				b.Fatal(err)
			}
			_ = conn.Close()
			start := calls.Load()
			b.ReportAllocs()
			for b.Loop() {
				conn, err := dialer.DialContext(b.Context(), "tcp4", address)
				if err != nil {
					b.Fatal(err)
				}
				_ = conn.Close()
			}
			b.ReportMetric(float64(calls.Load()-start)/float64(b.N), "dns_dials/op")
		})
	}
}
