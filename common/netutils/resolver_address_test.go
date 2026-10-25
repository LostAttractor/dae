// SPDX-License-Identifier: AGPL-3.0-only

package netutils

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/internal/testutil"
	"github.com/daeuniverse/dae/pkg/dnscache"
	dns "github.com/miekg/dns"
)

func TestMain(m *testing.M) {
	testutil.InstallOfflineResolver()
	// net initializes its resolver configuration on the first lookup. Inside a
	// synctest bubble that would bind it to the bubble for the whole process.
	_, _ = (&net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("warm-up")
	}}).LookupNetIP(context.Background(), "ip4", "warm-up.invalid.")
	os.Exit(m.Run())
}

// addressTestResolver answers datagrams in memory, so it also runs in a
// synctest bubble. opened counts transports net.Resolver opens, including
// wire cache hits; answer may return nil to leave a query unanswered.
func addressTestResolver(answer func(*dns.Msg) *dns.Msg) (*net.Resolver, *atomic.Int64) {
	opened := new(atomic.Int64)
	dial := cacheDNSDial(dnscache.New(32, 1<<20), func(context.Context, string, string) (net.Conn, error) {
		return &cacheWireConn{makeReply: func(q *dns.Msg) []byte {
			if r := answer(q); r != nil {
				wire, _ := r.Pack()
				return wire
			}
			return nil
		}}, nil
	})
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		opened.Add(1)
		return dial(ctx, network, address)
	}}, opened
}

func TestAddressCacheKeepsEarliestDNSLifetime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		resolver, opened := addressTestResolver(func(q *dns.Msg) *dns.Msg {
			r := cacheTestReply(q)
			r.Answer[0].Header().Ttl = map[uint16]uint32{dns.TypeA: 30, dns.TypeAAAA: 10}[q.Question[0].Qtype]
			return r
		})
		var cache AddressCache
		lookup := cache.Lookup(resolver.LookupNetIP, "scope")
		for _, step := range []struct {
			wait   time.Duration
			opened int64
		}{
			{0, 2},
			{9 * time.Second, 2}, // A hit is not renewed.
			{time.Second, 4},     // AAAA expired at 10s; the A answer is still cached.
			{9 * time.Second, 4},
			{time.Second, 6}, // The new entry expired with the AAAA answer at 20s.
		} {
			time.Sleep(step.wait)
			ips, err := lookup(t.Context(), "ip", "Node.Cache.Test.")
			if err != nil || len(ips) != 2 || opened.Load() != step.opened {
				t.Fatalf("after %v: %v, %v; %d transports, want %d", step.wait, ips, err, opened.Load(), step.opened)
			}
			ips[0] = netip.Addr{} // Callers own returned slices.
		}
	})
}

func TestAddressCacheKeepsOnlyCacheableAnswers(t *testing.T) {
	for _, test := range []struct {
		name, network, host string
		answer              func(*dns.Msg) *dns.Msg
	}{
		{"zero TTL", "ip4", "node.cache.test.", func(q *dns.Msg) *dns.Msg {
			r := cacheTestReply(q)
			r.Answer[0].Header().Ttl = 0
			return r
		}},
		{"server failure in one family", "ip", "node.cache.test.", func(q *dns.Msg) *dns.Msg {
			r := cacheTestReply(q)
			if q.Question[0].Qtype == dns.TypeAAAA {
				r.Answer, r.Rcode = nil, dns.RcodeServerFailure
			}
			return r
		}},
		{"unanswered family", "ip", "node.cache.test.", func(q *dns.Msg) *dns.Msg {
			if q.Question[0].Qtype == dns.TypeAAAA {
				return nil
			}
			return cacheTestReply(q)
		}},
		{"hosts entry", "ip4", "localhost", cacheTestReply},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver, _ := addressTestResolver(test.answer)
			var cache AddressCache
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if ips, err := cache.Lookup(resolver.LookupNetIP, "scope")(ctx, test.network, test.host); err != nil || len(ips) == 0 {
				t.Fatalf("lookup = %v, %v", ips, err)
			}
			if entries := cache.entries().Snapshot().Entries; entries != 0 {
				t.Fatalf("kept %d address lists", entries)
			}
		})
	}
}

// net.Resolver may report an answer after ctx ends, and hides ctx values
// from the exchanges it starts after that, which then never settle. Such an
// answer is not kept, however its settled exchanges look.
func TestAddressCacheSkipsLookupsWhoseContextEnded(t *testing.T) {
	var cache AddressCache
	for _, end := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		lookup := cache.Lookup(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
			lifetime := addressLifetimeFrom(ctx)
			lifetime.open()
			lifetime.settle(time.Now().Add(time.Minute), false)
			if end {
				cancel()
			}
			return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
		}, "scope")
		cache.Reset()
		if _, err := lookup(ctx, "ip4", "node.cache.test."); err != nil {
			t.Fatal(err)
		}
		if kept := cache.entries().Snapshot().Entries != 0; kept == end {
			t.Fatalf("ctx ended: %v; answer kept: %v", end, kept)
		}
		cancel()
	}
}

// net rereads hosts, resolv.conf and nsswitch.conf at most every
// netFileRefresh, so lookups right after Reset may still see the files as
// they were before an edit. Their answers last only until net rereads them.
func TestAddressCacheResetWaitsForNetFiles(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var cache AddressCache
		lookups := 0
		lookup := cache.Lookup(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
			lookups++
			lifetime := addressLifetimeFrom(ctx)
			lifetime.open()
			lifetime.settle(time.Now().Add(time.Hour), false)
			return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
		}, "scope")
		for i, step := range []struct {
			reset   bool
			wait    time.Duration
			lookups int
		}{
			{false, 0, 1},
			{false, netFileRefresh, 1}, // Without Reset, answers last their TTL.
			{true, 0, 2},
			{false, netFileRefresh - time.Second, 2},
			{false, time.Second, 3}, // net has reread the files.
			{false, time.Hour - time.Second, 3},
		} {
			if step.reset {
				cache.Reset()
			}
			time.Sleep(step.wait)
			if _, err := lookup(t.Context(), "ip4", "node.cache.test."); err != nil || lookups != step.lookups {
				t.Fatalf("step %d: %v; %d lookups, want %d", i, err, lookups, step.lookups)
			}
		}
	})
}

func TestAddressCacheKeepsTCPCompletedTruncation(t *testing.T) {
	dial, calls := cacheTestServer(t, func(network string, q *dns.Msg) *dns.Msg {
		r := cacheTestReply(q)
		if network == "udp" {
			r.Answer, r.Truncated = nil, true
		}
		return r
	})
	var cache AddressCache
	lookup := cache.Lookup((&net.Resolver{PreferGo: true, Dial: cacheDNSDial(dnscache.New(32, 1<<20), dial)}).LookupNetIP, "scope")
	for range 2 {
		if _, err := lookup(t.Context(), "ip4", "node.cache.test."); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("want one UDP and one TCP exchange, got %d dials", calls.Load())
	}
}

func TestAddressCacheFamiliesAndReset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var block atomic.Bool
		blocked, release := make(chan struct{}), make(chan struct{})
		resolver, opened := addressTestResolver(func(q *dns.Msg) *dns.Msg {
			if block.CompareAndSwap(true, false) {
				close(blocked)
				<-release
			}
			r := cacheTestReply(q)
			r.Answer[0].Header().Ttl = 60
			return r
		})
		var cache AddressCache
		lookup := cache.Lookup(resolver.LookupNetIP, "scope")
		if ips, err := lookup(t.Context(), "ip4", "node.cache.test."); err != nil || len(ips) != 1 {
			t.Fatalf("ip4 = %v, %v", ips, err)
		}
		if ips, err := lookup(t.Context(), "ip", "node.cache.test."); err != nil || len(ips) != 2 {
			t.Fatalf("ip shared the ip4 entry: %v, %v", ips, err)
		}
		if ips, err := cache.Lookup(resolver.LookupNetIP, "other")(t.Context(), "ip4", "node.cache.test."); err != nil || len(ips) != 1 || opened.Load() != 4 {
			t.Fatalf("scopes shared an entry: %v, %v, %d transports", ips, err, opened.Load())
		}
		// A lookup that resolved before Reset cannot fill the new cache.
		block.Store(true)
		done := make(chan error)
		go func() { _, err := lookup(t.Context(), "ip6", "late.cache.test."); done <- err }()
		<-blocked
		cache.Reset()
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if entries := cache.entries().Snapshot().Entries; entries != 0 {
			t.Fatalf("Reset kept %d address lists", entries)
		}
		if _, err := lookup(t.Context(), "ip4", "node.cache.test."); err != nil || opened.Load() != 6 {
			t.Fatalf("lookup after Reset: %v, %d transports", err, opened.Load())
		}
	})
}

func TestAddressCacheConcurrentLookups(t *testing.T) {
	resolver, _ := addressTestResolver(cacheTestReply)
	var cache AddressCache
	lookup := cache.Lookup(resolver.LookupNetIP, "scope")
	var work sync.WaitGroup
	for i := range 8 {
		work.Go(func() {
			for j := range 50 {
				if j%10 == 0 && i == 0 {
					cache.Reset()
				}
				ips, err := lookup(t.Context(), "ip", "node.cache.test.")
				if err != nil || len(ips) != 2 {
					t.Errorf("lookup = %v, %v", ips, err)
					return
				}
				ips[0] = netip.Addr{}
			}
		})
	}
	work.Wait()
}
