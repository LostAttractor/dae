// SPDX-License-Identifier: AGPL-3.0-only

package dnscache

import (
	"net"
	"sync"
	"testing"
	"time"

	dns "github.com/miekg/dns"
)

func cacheMessages() (*dns.Msg, *dns.Msg) {
	q := new(dns.Msg).SetQuestion("node.example.", dns.TypeA)
	r := new(dns.Msg).SetReply(q)
	r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
	return q, r
}

func TestCacheExpiryAndOwnership(t *testing.T) {
	c := New(4, 4096)
	q, r := cacheMessages()
	at := time.Now()
	if !c.Put(Key{Namespace: "scope/query"}, q.Question[0].Qtype, r, at) {
		t.Fatal("response not stored")
	}
	r.Answer[0].(*dns.A).A[15] = 2
	r.Answer[0].Header().Ttl = 1
	q.Id++
	q.Question[0].Name = "NoDe.Example."
	got, ok := c.Get(Key{Namespace: "scope/query"}, at.Add(5*time.Second))
	if ok {
		Replay(got, q)
	}
	if !ok || got.Id != q.Id || got.Question[0] != q.Question[0] || got.Answer[0].Header().Ttl != 55 || got.Answer[0].(*dns.A).A.String() != "192.0.2.1" {
		t.Fatalf("bad replay: %v", got)
	}
	got.Answer[0].Header().Ttl = 0
	got.Question[0].Name = "changed.example."
	again, ok := c.Get(Key{Namespace: "scope/query"}, at.Add(59*time.Second))
	if ok {
		Replay(again, q)
	}
	if !ok || again.Answer[0].Header().Ttl != 1 || again.Question[0] != q.Question[0] {
		t.Fatal("caller mutated cached state")
	}
	if _, ok := c.Get(Key{Namespace: "scope/query"}, at.Add(time.Minute)); ok || len(c.store.entries) != 0 || c.store.bytes != 0 {
		t.Fatal("expired response remained accessible")
	}
}

func TestCacheNegativeAndCNAMEExpiry(t *testing.T) {
	for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeNameError} {
		q, r := cacheMessages()
		r.Rcode = rcode
		r.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3}, Target: "missing.example."}}
		r.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.example.", Mbox: "hostmaster.example.", Minttl: 5}}
		at := time.Now()
		c := New(4, 4096)
		if !c.Put(Key{Namespace: "q"}, q.Question[0].Qtype, r, at) {
			t.Fatal("negative response not cached")
		}
		got, ok := c.Get(Key{Namespace: "q"}, at.Add(2*time.Second))
		if !ok || got.Ns[0].Header().Ttl != 1 || got.Ns[0].(*dns.SOA).Minttl != 5 {
			t.Fatalf("negative TTL renewed: %v", got)
		}
		if _, ok := c.Get(Key{Namespace: "q"}, at.Add(3*time.Second)); ok {
			t.Fatal("CNAME lifetime ignored")
		}
	}
}

func TestCacheBypassesUnsafeResponses(t *testing.T) {
	for _, change := range []func(*dns.Msg){
		func(r *dns.Msg) { r.Response = false },
		func(r *dns.Msg) { r.Truncated = true },
		func(r *dns.Msg) { r.Rcode = dns.RcodeServerFailure },
		func(r *dns.Msg) { r.Answer[0].Header().Ttl = 0 },
		func(r *dns.Msg) { r.Answer[0].Header().Ttl = 1 << 31 },
		func(r *dns.Msg) { r.Answer = nil },
		func(r *dns.Msg) { r.Answer = nil; r.Rcode = dns.RcodeNameError },
		func(r *dns.Msg) { r.Extra = []dns.RR{&dns.TSIG{Hdr: dns.RR_Header{Rrtype: dns.TypeTSIG}}} },
		func(r *dns.Msg) { r.Extra = []dns.RR{&dns.RRSIG{Hdr: dns.RR_Header{Rrtype: dns.TypeRRSIG}}} },
	} {
		q, r := cacheMessages()
		change(r)
		c := New(4, 4096)
		if c.Put(Key{Namespace: "q"}, q.Question[0].Qtype, r, time.Now()) || len(c.store.entries) != 0 {
			t.Fatalf("unsafe response cached: %v", r)
		}
	}
}

func TestCacheBoundsAndLRU(t *testing.T) {
	q, r := cacheMessages()
	at := time.Now()
	c := New(2, 4096)
	c.Put(Key{Namespace: "a"}, q.Question[0].Qtype, r, at)
	c.Put(Key{Namespace: "b"}, q.Question[0].Qtype, r, at)
	c.Get(Key{Namespace: "a"}, at)
	c.Put(Key{Namespace: "c"}, q.Question[0].Qtype, r, at)
	if _, ok := c.Get(Key{Namespace: "b"}, at); ok {
		t.Fatal("least recently used entry survived eviction")
	}
	for range 100 {
		c.Put(Key{Namespace: "a"}, q.Question[0].Qtype, r, at)
	}
	if len(c.store.entries) != 2 || c.store.bytes > c.store.memoryLimit {
		t.Fatal("replacement leaked accounting")
	}
	c = New(10, c.store.bytes/2)
	for _, key := range []string{"a", "b", "c"} {
		c.Put(Key{Namespace: key}, q.Question[0].Qtype, r, at)
	}
	if len(c.store.entries) != 1 || c.store.bytes > c.store.memoryLimit {
		t.Fatal("byte budget did not bound storage")
	}
	if New(0, 4096).Put(Key{Namespace: "q"}, q.Question[0].Qtype, r, at) || New(4, 1).Put(Key{Namespace: "q"}, q.Question[0].Qtype, r, at) {
		t.Fatal("disabled or undersized cache stored a response")
	}
}

func TestQueryKeyIdentityAndIsolation(t *testing.T) {
	q, _ := cacheMessages()
	q.SetEdns0(1232, true)
	want, ok := QueryKey(q)
	if !ok {
		t.Fatal("ordinary query bypassed")
	}
	other := q.Copy()
	other.Id++
	other.Question[0].Name = "NoDe.Example."
	if got, _ := QueryKey(other); got != want || other.Id != q.Id+1 || other.Question[0].Name != "NoDe.Example." {
		t.Fatal("query ID/case normalization failed or mutated input")
	}
	for _, change := range []func(*dns.Msg){
		func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeAAAA },
		func(m *dns.Msg) { m.CheckingDisabled = true },
		func(m *dns.Msg) { m.RecursionDesired = false },
		func(m *dns.Msg) { m.IsEdns0().SetDo(false) },
		func(m *dns.Msg) { m.IsEdns0().SetUDPSize(512) },
		func(m *dns.Msg) {
			m.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IPv4(192, 0, 2, 0)}}
		},
	} {
		m := q.Copy()
		change(m)
		if key, ok := QueryKey(m); !ok || key == want {
			t.Fatalf("query distinction lost: %v", m)
		}
	}
}

func TestCacheConcurrentOwnership(t *testing.T) {
	c := New(4, 4096)
	q, r := cacheMessages()
	q.SetEdns0(1232, false)
	q.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "abcd"}}
	var work sync.WaitGroup
	for range 8 {
		work.Go(func() {
			for range 100 {
				if _, ok := QueryKey(q); !ok {
					t.Error("ordinary shared query bypassed")
				}
				c.Put(Key{Namespace: "q"}, q.Question[0].Qtype, r.Copy(), time.Now())
				if got, ok := c.Get(Key{Namespace: "q"}, time.Now()); ok {
					got.Answer[0].Header().Ttl = 0
				}
			}
		})
	}
	work.Wait()
	if q.IsEdns0().Hdr.Rdlength != 0 {
		t.Fatal("key encoding mutated the caller's OPT")
	}
}

func TestTTLCalculationDoesNotChooseEDNSPolicy(t *testing.T) {
	q, r := cacheMessages()
	r.SetEdns0(1232, false)
	r.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0011223344556677"}}
	if ttl := Prepare(q.Question[0].Qtype, r); ttl != 60 {
		t.Fatalf("TTL calculation depends on option policy: %d", ttl)
	}
}
