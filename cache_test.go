// SPDX-License-Identifier: AGPL-3.0-only

package dnscache

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dns "github.com/miekg/dns"
)

func testCache(t *testing.T, body string) *Cache {
	t.Helper()
	sections, err := config_parser.Parse("cache {" + body + "}")
	if err != nil {
		t.Fatal(err)
	}
	factory, err := Configure(plugin.Spec{Config: sections[0]})
	if err != nil {
		t.Fatal(err)
	}
	p, err := factory(t.Context(), plugin.Services{})
	if err != nil {
		t.Fatal(err)
	}
	return p.(*Cache)
}
func testRequest() *plugin.DNSExchange {
	m := new(dns.Msg).SetQuestion("test.example.", dns.TypeA)
	m.SetEdns0(1232, true)
	return &plugin.DNSExchange{DNSPacket: plugin.DNSMessage(m), Network: "udp", ContextKey: "client/profile-1", Destination: netip.MustParseAddrPort("192.0.2.53:53")}
}
func testResponse(r *plugin.DNSExchange) *plugin.DNSResponse {
	m := new(dns.Msg).SetReply(r.MessageCopy())
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("198.51.100.1")}}
	return &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(m), ReceivedAt: time.Now().Add(-3 * time.Second), Origin: "surge:host"}
}

func TestFinalLocalResponseReplayAndIsolation(t *testing.T) {
	c := testCache(t, "")
	request := testRequest()
	response := testResponse(request)
	c.ObserveDNS(t.Context(), request, response)
	query := request.MessageCopy()
	query.Id++
	query.Question[0].Name = "TeSt.Example."
	request.DNSPacket = plugin.DNSMessage(query)
	hit, err := c.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		t.Fatal("cache miss")
		return nil, nil
	})(t.Context(), request)
	if err != nil || hit == nil {
		t.Fatalf("cache replay: %v, %v", hit, err)
	}
	message := hit.MessageCopy()
	if !hit.Cached || message.Id != query.Id || message.Question[0].Name != query.Question[0].Name || message.Answer[0].Header().Ttl > 57 || !hit.ReceivedAt.Equal(response.ReceivedAt) {
		t.Fatalf("replay lost identity/age: %+v %v", hit, err)
	}
	if response.MessageCopy().Answer[0].Header().Ttl != 60 {
		t.Fatal("cache mutated source")
	}
	for _, change := range []func(*plugin.DNSExchange, *dns.Msg){
		func(r *plugin.DNSExchange, _ *dns.Msg) { r.ContextKey = "client/profile-2" }, func(r *plugin.DNSExchange, _ *dns.Msg) { r.Network = "tcp" }, func(r *plugin.DNSExchange, _ *dns.Msg) { r.Destination = netip.MustParseAddrPort("192.0.2.54:53") },
		func(_ *plugin.DNSExchange, m *dns.Msg) { m.CheckingDisabled = true }, func(_ *plugin.DNSExchange, m *dns.Msg) { m.RecursionDesired = false }, func(_ *plugin.DNSExchange, m *dns.Msg) { m.IsEdns0().SetDo(false) },
	} {
		r := request.Copy()
		message := r.MessageCopy()
		change(r, message)
		r.DNSPacket = plugin.DNSMessage(message)
		called := false
		_, err := c.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
			called = true
			return nil, nil
		})(t.Context(), r)
		if err != nil || !called {
			t.Fatal("cache crossed query/policy boundary")
		}
	}
}

func TestNegativeExpirySignaturesAndCapacity(t *testing.T) {
	c := testCache(t, "size:1")
	request := testRequest()
	response := testResponse(request)
	message := response.MessageCopy()
	message.Answer = nil
	message.Rcode = dns.RcodeNameError
	message.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.example.", Mbox: "hostmaster.example.", Minttl: 5}}
	response.DNSPacket = plugin.DNSMessage(message)
	c.ObserveDNS(t.Context(), request, response)
	if len(c.entries) != 1 {
		t.Fatal("negative answer not cached")
	}
	for _, elem := range c.entries {
		if !elem.Value.(*entry).expires.Equal(response.ReceivedAt.Add(5 * time.Second)) {
			t.Fatal("SOA minimum ignored")
		}
	}
	next := request.Copy()
	query := next.MessageCopy()
	query.Question[0].Name = "next.example."
	next.DNSPacket = plugin.DNSMessage(query)
	positive := testResponse(next)
	c.ObserveDNS(t.Context(), next, positive)
	if len(c.entries) != 1 || c.bytes > c.memoryLimit {
		t.Fatal("capacity not bounded")
	}
	key, _ := cacheKey(request)
	if c.entries[key] != nil {
		t.Fatal("LRU entry not evicted")
	}
	message = positive.MessageCopy()
	message.Answer = append(message.Answer, &dns.RRSIG{Hdr: dns.RR_Header{Name: "next.example.", Rrtype: dns.TypeRRSIG, Ttl: 60}})
	positive.DNSPacket = plugin.DNSMessage(message)
	c2 := testCache(t, "")
	c2.ObserveDNS(t.Context(), next, positive)
	if len(c2.entries) != 0 {
		t.Fatal("signed response cached")
	}
	response.ReceivedAt = time.Now().Add(-time.Minute)
	c2.ObserveDNS(t.Context(), request, response)
	if len(c2.entries) != 0 {
		t.Fatal("expired negative answer renewed")
	}
}

func TestFixedTTLAndMalformedPassthrough(t *testing.T) {
	c := testCache(t, "fixed_domain_ttl { test.example: 0 }")
	request := testRequest()
	response := testResponse(request)
	got, err := c.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) { return response, nil })(t.Context(), request)
	if err != nil || got.MessageCopy().Answer[0].Header().Ttl != 0 {
		t.Fatalf("TTL override: %+v %v", got, err)
	}
	c.ObserveDNS(t.Context(), request, got)
	if len(c.entries) != 0 {
		t.Fatal("TTL zero was cached")
	}
	query := request.MessageCopy()
	query.Question = nil
	request.DNSPacket = plugin.DNSMessage(query)
	if _, err := c.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) { return response, nil })(t.Context(), request); err != nil {
		t.Fatal(err)
	}
}

func TestCNAMEOnlyNODATAUsesSOAMinimum(t *testing.T) {
	c := testCache(t, "")
	request := testRequest()
	response := testResponse(request)
	message := response.MessageCopy()
	message.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "test.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "missing.example."}}
	message.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.example.", Mbox: "hostmaster.example.", Minttl: 5}}
	response.DNSPacket = plugin.DNSMessage(message)
	c.ObserveDNS(t.Context(), request, response)
	k, _ := cacheKey(request)
	if elem := c.entries[k]; elem == nil || !elem.Value.(*entry).expires.Equal(response.ReceivedAt.Add(5*time.Second)) {
		t.Fatal("CNAME-only NODATA ignored SOA minimum")
	}
	c2 := testCache(t, "")
	message.Ns = nil
	response.DNSPacket = plugin.DNSMessage(message)
	c2.ObserveDNS(t.Context(), request, response)
	if len(c2.entries) != 0 {
		t.Fatal("cached negative alias without authority SOA")
	}
}

func TestFixedZeroDisablesNegativeCaching(t *testing.T) {
	c := testCache(t, "fixed_domain_ttl { test.example: 0 }")
	request := testRequest()
	response := testResponse(request)
	message := response.MessageCopy()
	message.Answer = nil
	message.Rcode = dns.RcodeNameError
	message.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.example.", Mbox: "hostmaster.example.", Minttl: 30}}
	response.DNSPacket = plugin.DNSMessage(message)
	c.ObserveDNS(t.Context(), request, response)
	if len(c.entries) != 0 {
		t.Fatal("fixed TTL zero cached a negative response")
	}
}

func TestTransactionEDNSResponseIsNotCached(t *testing.T) {
	for _, option := range []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0011223344556677"}, &dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE, Timeout: 100}} {
		c := testCache(t, "")
		request := testRequest()
		response := testResponse(request)
		message := response.MessageCopy()
		message.SetEdns0(1232, false)
		message.IsEdns0().Option = []dns.EDNS0{option}
		response.DNSPacket = plugin.DNSMessage(message)
		c.ObserveDNS(t.Context(), request, response)
		if len(c.entries) != 0 {
			t.Fatalf("cached transaction-specific EDNS %T", option)
		}
	}
}
