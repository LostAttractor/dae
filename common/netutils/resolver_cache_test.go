// SPDX-License-Identifier: AGPL-3.0-only

package netutils

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/dnscache"
	dns "github.com/miekg/dns"
)

func cacheTestReply(query *dns.Msg) *dns.Msg {
	m := new(dns.Msg).SetReply(query)
	m.RecursionAvailable = true
	q := query.Question[0]
	h := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 60}
	switch q.Qtype {
	case dns.TypeA:
		m.Answer = []dns.RR{&dns.A{Hdr: h, A: net.IPv4(192, 0, 2, 1)}}
	case dns.TypeAAAA:
		m.Answer = []dns.RR{&dns.AAAA{Hdr: h, AAAA: net.ParseIP("2001:db8::1")}}
	case dns.TypeTXT:
		m.Answer = []dns.RR{&dns.TXT{Hdr: h, Txt: []string{"cached"}}}
	}
	return m
}

func cacheTestServer(t testing.TB, reply func(string, *dns.Msg) *dns.Msg) (dnsDialFunc, *atomic.Int64) {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		_ = w.WriteMsg(reply(w.LocalAddr().Network(), q))
	})
	for _, server := range []*dns.Server{{PacketConn: udp, Handler: handler}, {Listener: tcp, Handler: handler}} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go func() { _ = server.ActivateAndServe() }()
		<-ready
		t.Cleanup(func() { _ = server.Shutdown() })
	}
	calls := new(atomic.Int64)
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		calls.Add(1)
		address := udp.LocalAddr().String()
		if network == "tcp" {
			address = tcp.Addr().String()
		}
		return new(net.Dialer).DialContext(ctx, network, address)
	}, calls
}

func cacheTestExchange(t testing.TB, dial dnsDialFunc, network string, query *dns.Msg) *dns.Msg {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	conn, err := dial(ctx, network, "192.0.2.53:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	response, _, err := (&dns.Client{Net: network}).ExchangeWithConnContext(ctx, query, &dns.Conn{Conn: conn})
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestResolverCacheCoversStandardLookups(t *testing.T) {
	dial, calls := cacheTestServer(t, func(_ string, q *dns.Msg) *dns.Msg { return cacheTestReply(q) })
	r := &net.Resolver{PreferGo: true, Dial: cacheDNSDial(dnscache.New(32, 1<<20), dial)}
	for range 2 {
		ips, err := r.LookupNetIP(t.Context(), "ip", "node.cache.test.")
		if err != nil || len(ips) != 2 {
			t.Fatalf("IP lookup = %v, %v", ips, err)
		}
		txt, err := r.LookupTXT(t.Context(), "node.cache.test.")
		if err != nil || !slices.Equal(txt, []string{"cached"}) {
			t.Fatalf("TXT lookup = %v, %v", txt, err)
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("second A/AAAA/TXT lookup opened sockets: %d", calls.Load())
	}
	if _, err := r.LookupNetIP(t.Context(), "ip", "127.0.0.1"); err != nil || calls.Load() != 3 {
		t.Fatal("literal lookup entered DNS")
	}
	if _, err := r.LookupHost(t.Context(), "localhost"); err != nil || calls.Load() != 3 {
		t.Fatal("hosts lookup entered DNS")
	}
}

func TestResolverCacheTCPRetryAndTransportIsolation(t *testing.T) {
	dial, calls := cacheTestServer(t, func(network string, q *dns.Msg) *dns.Msg {
		r := cacheTestReply(q)
		if network == "udp" {
			r.Answer, r.Truncated = nil, true
		}
		return r
	})
	r := &net.Resolver{PreferGo: true, Dial: cacheDNSDial(dnscache.New(32, 1<<20), dial)}
	for range 2 {
		if _, err := r.LookupNetIP(t.Context(), "ip4", "node.cache.test."); err != nil {
			t.Fatal(err)
		}
	}
	// UDP truncation is not cached or replaced by TCP data. The completed TCP
	// answer is reused while the standard library still owns fallback policy.
	if calls.Load() != 3 {
		t.Fatalf("want two UDP queries and one TCP query, got %d dials", calls.Load())
	}
}

func TestResolverCacheCompressedResponseAndFreshOPT(t *testing.T) {
	dial, calls := cacheTestServer(t, func(_ string, q *dns.Msg) *dns.Msg {
		r := cacheTestReply(q)
		r.Compress = true
		r.SetEdns0(4096, true)
		for i := 1; i < 20; i++ {
			r.Answer = append(r.Answer, dns.Copy(r.Answer[0]))
		}
		return r
	})
	cached := cacheDNSDial(dnscache.New(32, 1<<20), dial)
	name := strings.Repeat("x", 60) + "." + strings.Repeat("y", 60) + ".test."
	q := new(dns.Msg).SetQuestion(name, dns.TypeTXT)
	q.SetEdns0(1232, false)
	first := cacheTestExchange(t, cached, "udp", q)
	q.Id++
	second := cacheTestExchange(t, cached, "udp", q)
	if calls.Load() != 1 || len(second.Answer) != 20 || second.Id != q.Id {
		t.Fatal("compressed response was lost or redialed on hit")
	}
	if first.IsEdns0().UDPSize() != 4096 || !first.IsEdns0().Do() || second.IsEdns0().UDPSize() != 1232 || second.IsEdns0().Do() {
		t.Fatal("cached OPT retained the previous transaction's negotiation")
	}
}

type cacheWireConn struct {
	net.Conn
	makeReply func(*dns.Msg) []byte
	reply     []byte
}

func (c *cacheWireConn) Write(p []byte) (int, error) {
	q := new(dns.Msg)
	if err := q.Unpack(p); err != nil {
		return 0, err
	}
	c.reply = c.makeReply(q)
	return len(p), nil
}
func (c *cacheWireConn) Read(p []byte) (int, error)     { return copy(p, c.reply), nil }
func (*cacheWireConn) Close() error                     { return nil }
func (*cacheWireConn) SetDeadline(time.Time) error      { return nil }
func (*cacheWireConn) SetReadDeadline(time.Time) error  { return nil }
func (*cacheWireConn) SetWriteDeadline(time.Time) error { return nil }

func TestResolverCacheDoesNotRepairInvalidWire(t *testing.T) {
	for _, kind := range []string{"ID", "question", "QR", "opcode", "trailing", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			cached := cacheDNSDial(dnscache.New(32, 1<<20), func(context.Context, string, string) (net.Conn, error) {
				calls++
				return &cacheWireConn{makeReply: func(q *dns.Msg) []byte {
					r := cacheTestReply(q)
					switch kind {
					case "ID":
						r.Id++
					case "question":
						r.Question[0].Name = "other.test."
					case "QR":
						r.Response = false
					case "opcode":
						r.Opcode = dns.OpcodeNotify
					case "truncated":
						r.Truncated = true
					}
					wire, _ := r.Pack()
					if kind == "trailing" {
						wire = append(wire, 0xff)
					}
					return wire
				}}, nil
			})
			q := new(dns.Msg).SetQuestion("node.cache.test.", dns.TypeA)
			wire, _ := q.Pack()
			for range 2 {
				conn, err := cached(t.Context(), "udp", "192.0.2.53:53")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := conn.Write(wire); err != nil {
					t.Fatal(err)
				}
				if _, err := conn.Read(make([]byte, 512)); err != nil {
					t.Fatal(err)
				}
				_ = conn.Close()
			}
			if calls != 2 {
				t.Fatal("invalid response was normalized into a cache hit")
			}
		})
	}
}

func TestResolverCacheNamespaces(t *testing.T) {
	dial, calls := cacheTestServer(t, func(_ string, q *dns.Msg) *dns.Msg { return cacheTestReply(q) })
	cache := dnscache.New(32, 1<<20)
	first, other := cacheDNSDial(cache, dial), cacheDNSDial(cache, dial)
	q := new(dns.Msg).SetQuestion("node.cache.test.", dns.TypeA)
	cacheTestExchange(t, first, "udp", q)
	cacheTestExchange(t, first, "udp", q)
	cacheTestExchange(t, other, "udp", q)
	cacheTestExchange(t, first, "tcp", q)
	// Different DNS destinations under the same resolver are also isolated.
	conn, err := first(t.Context(), "udp", "192.0.2.54:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, _, err := new(dns.Client).ExchangeWithConnContext(t.Context(), q, &dns.Conn{Conn: conn}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 4 {
		t.Fatalf("namespace/server/transport separation failed: %d dials", calls.Load())
	}
}

func TestInternalResolverCachePolicyHandoff(t *testing.T) {
	dial, calls := cacheTestServer(t, func(_ string, q *dns.Msg) *dns.Msg { return cacheTestReply(q) })
	r := newInternalResolver(netip.MustParseAddrPort("192.0.2.53:53"), dial)
	q := new(dns.Msg).SetQuestion("node.cache.test.", dns.TypeA)
	old, err := r.Resolver.Dial(t.Context(), "udp", "192.0.2.53:53")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	r.Configure(netip.MustParseAddrPort("192.0.2.54:53"), nil)
	// Finish an old policy's transaction after publishing the replacement.
	if _, _, err := new(dns.Client).ExchangeWithConnContext(t.Context(), q, &dns.Conn{Conn: old}); err != nil {
		t.Fatal(err)
	}
	cacheTestExchange(t, r.Resolver.Dial, "udp", q)
	cacheTestExchange(t, r.Resolver.Dial, "udp", q)
	cacheTestExchange(t, r.Bootstrap.Dial, "udp", q)
	if calls.Load() != 3 {
		t.Fatalf("old/routed/bootstrap caches were mixed: %d dials", calls.Load())
	}
	r.SetRoute(func(context.Context, string, netip.AddrPort) (net.Conn, error) {
		return nil, errors.New("blocked by replacement route")
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := r.Resolver.LookupNetIP(ctx, "ip4", "node.cache.test."); err == nil {
		t.Fatal("cached answer bypassed the new blocked route")
	}
}

func TestResolverCacheBypassAndNegative(t *testing.T) {
	for _, mode := range []string{"zero-ttl", "negative", "no-soa", "edns-query", "edns-response"} {
		t.Run(mode, func(t *testing.T) {
			dial, calls := cacheTestServer(t, func(_ string, q *dns.Msg) *dns.Msg {
				r := cacheTestReply(q)
				switch mode {
				case "zero-ttl":
					r.Answer[0].Header().Ttl = 0
				case "negative", "no-soa":
					r.Answer, r.Rcode = nil, dns.RcodeNameError
					if mode == "negative" {
						r.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "cache.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.cache.test.", Mbox: "hostmaster.cache.test.", Minttl: 10}}
					}
				case "edns-response":
					r.SetEdns0(1232, false)
					r.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "abcd"}}
				}
				return r
			})
			cached := cacheDNSDial(dnscache.New(32, 1<<20), dial)
			q := new(dns.Msg).SetQuestion("node.cache.test.", dns.TypeA)
			if mode == "edns-query" {
				q.SetEdns0(1232, false)
				q.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_NSID{Code: dns.EDNS0NSID}}
			}
			for range 2 {
				cacheTestExchange(t, cached, "udp", q)
			}
			want := int64(2)
			if mode == "negative" {
				want = 1
			}
			if calls.Load() != want {
				t.Fatalf("dials=%d, want %d", calls.Load(), want)
			}
		})
	}
}

func TestResolverCacheHitPreservesCancellationAndDeadline(t *testing.T) {
	dial, calls := cacheTestServer(t, func(_ string, q *dns.Msg) *dns.Msg { return cacheTestReply(q) })
	cached := cacheDNSDial(dnscache.New(32, 1<<20), dial)
	q := new(dns.Msg).SetQuestion("node.cache.test.", dns.TypeA)
	cacheTestExchange(t, cached, "udp", q)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := cached(ctx, "udp", "192.0.2.53:53"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial: %v", err)
	}
	conn, err := cached(t.Context(), "udp", "192.0.2.53:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	read := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 512)); read <- err }()
	_ = conn.SetReadDeadline(time.Now().Add(-time.Second))
	select {
	case err := <-read:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("pending read deadline: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("read deadline did not wake waiting reader")
	}
	if _, _, err := new(dns.Client).ExchangeWithConnContext(t.Context(), q, &dns.Conn{Conn: conn}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("hit created a socket")
	}
	_ = conn.Close()
	wire, _ := q.Pack()
	if _, err := conn.Write(wire); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
}

func TestResolverCacheCloseCancelsPendingDial(t *testing.T) {
	started := make(chan struct{})
	dial := cacheDNSDial(dnscache.New(32, 1<<20), func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	conn, err := dial(t.Context(), "udp", "192.0.2.53:53")
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg).SetQuestion("node.cache.test.", dns.TypeA)
	wire, _ := q.Pack()
	done := make(chan error, 1)
	go func() { _, err := conn.Write(wire); done <- err }()
	<-started
	_ = conn.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close during dial: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt lazy dial")
	}
}

type fragmentDNSConn struct{ net.Conn }

func (c fragmentDNSConn) Read(p []byte) (int, error) { return c.Conn.Read(p[:min(1, len(p))]) }

func TestResolverCacheFragmentedTCPResponse(t *testing.T) {
	dial, calls := cacheTestServer(t, func(_ string, q *dns.Msg) *dns.Msg { return cacheTestReply(q) })
	cached := cacheDNSDial(dnscache.New(32, 1<<20), func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		return fragmentDNSConn{conn}, err
	})
	q := new(dns.Msg).SetQuestion("node.cache.test.", dns.TypeA)
	for range 2 {
		cacheTestExchange(t, cached, "tcp", q)
	}
	if calls.Load() != 1 {
		t.Fatal("fragmented TCP response was not cached")
	}
}

func TestResolverCacheCloseInterruptsSocketRead(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	dial := cacheDNSDial(dnscache.New(32, 1<<20), func(context.Context, string, string) (net.Conn, error) { return client, nil })
	conn, err := dial(t.Context(), "tcp", "192.0.2.53:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	q := new(dns.Msg).SetQuestion("node.cache.test.", dns.TypeA)
	wire, _ := q.Pack()
	queryRead := make(chan error, 1)
	go func() { _, err := ReadDNSFrame(server); queryRead <- err }()
	if err := WriteDNSFrame(conn, wire); err != nil {
		t.Fatal(err)
	}
	if err := <-queryRead; err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 2)); done <- err }()
	_ = conn.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("close during read: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt socket read")
	}
}
