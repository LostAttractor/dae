// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

func TestPassiveDNSObservationBoundaries(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	ip := netip.MustParseAddr("198.51.100.1")
	for _, test := range []struct {
		name   string
		mutate func(*plugin.DNSRequest, *plugin.DNSResponse)
		want   bool
	}{
		{"valid CNAME", func(*plugin.DNSRequest, *plugin.DNSResponse) {}, true},
		{"mismatched ID", func(_ *plugin.DNSRequest, r *plugin.DNSResponse) { r.Message.Id++ }, false},
		{"mismatched question", func(_ *plugin.DNSRequest, r *plugin.DNSResponse) { r.Message.Question[0].Name = "other.example." }, false},
		{"mismatched question type", func(_ *plugin.DNSRequest, r *plugin.DNSResponse) { r.Message.Question[0].Qtype = dns.TypeAAAA }, false},
		{"wrong address record type", func(q *plugin.DNSRequest, r *plugin.DNSResponse) {
			q.Message.Question[0].Qtype = dns.TypeAAAA
			r.Message.Question[0].Qtype = dns.TypeAAAA
		}, false},
		{"truncated", func(_ *plugin.DNSRequest, r *plugin.DNSResponse) { r.Message.Truncated = true }, false},
		{"error", func(_ *plugin.DNSRequest, r *plugin.DNSResponse) { r.Message.Rcode = dns.RcodeServerFailure }, false},
		{"cached", func(_ *plugin.DNSRequest, r *plugin.DNSResponse) { r.Cached = true }, true},
		{"notify", func(q *plugin.DNSRequest, r *plugin.DNSResponse) {
			q.Message.Opcode = dns.OpcodeNotify
			r.Message.Opcode = dns.OpcodeNotify
		}, false},
		{"cycle", func(_ *plugin.DNSRequest, r *plugin.DNSResponse) {
			r.Message.Answer = append(r.Message.Answer, testCNAMERecord("edge.example.", "original.example."))
		}, false},
		{"invalid alias signature", func(_ *plugin.DNSRequest, r *plugin.DNSResponse) {
			r.Message.Answer = append(r.Message.Answer, &dns.RRSIG{Hdr: dns.RR_Header{Name: "original.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60}, TypeCovered: dns.TypeCNAME, Inception: uint32(now.Add(-time.Hour).Unix()), Expiration: uint32(now.Add(-time.Second).Unix()), OrigTtl: 60})
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			g, fake := newTestRegistry(16, 7*24*time.Hour)
			request := dnsTestRequest(t, "original.example.", 1)
			response := &plugin.DNSResponse{Message: new(dns.Msg).SetReply(request.Message), ReceivedAt: now}
			response.Message.Answer = []dns.RR{testARecord("unrelated.example.", "203.0.113.9"), testCNAMERecord("original.example.", "edge.example."), testARecord("edge.example.", ip.String())}
			test.mutate(request, response)
			observeDNSRegistryAt(g, func(string) []uint32 { return make([]uint32, domainBitmapWords()) }, request, response, now)
			for _, name := range []string{"original.example.", "edge.example."} {
				if g.Verify(name, ip).Paired != test.want {
					t.Fatalf("unexpected evidence for %s", name)
				}
				if test.want && !g.retention(name, ip).Equal(now.Add(7*24*time.Hour)) {
					t.Fatal("ordinary seven-day lease changed")
				}
			}
			if g.Verify("unrelated.example.", netip.MustParseAddr("203.0.113.9")).Paired {
				t.Fatal("unrelated answer published")
			}
			checkInvariants(t, g, fake)
		})
	}
}

func TestPassiveDNSRetentionIsIndependentOfSignatureAndReceipt(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	g, _ := newTestRegistry(16, 7*24*time.Hour)
	request := dnsTestRequest(t, "signed.example.", 1)
	response := &plugin.DNSResponse{Message: new(dns.Msg).SetReply(request.Message), ReceivedAt: now}
	response.Message.Answer = []dns.RR{testARecord("signed.example.", "198.51.100.1"), &dns.RRSIG{Hdr: dns.RR_Header{Name: "signed.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60}, TypeCovered: dns.TypeA, Inception: uint32(now.Add(-time.Hour).Unix()), Expiration: uint32(now.Add(20 * time.Second).Unix()), OrigTtl: 60}}
	match := func(string) []uint32 { return make([]uint32, domainBitmapWords()) }
	observeDNSRegistryAt(g, match, request, response, now)
	name, ip := "signed.example.", netip.MustParseAddr("198.51.100.1")
	deadline := g.retention(name, ip)
	if !deadline.Equal(now.Add(7 * 24 * time.Hour)) {
		t.Fatalf("signature incorrectly capped historical retention: %s", deadline)
	}
	response.Cached = true
	observeDNSRegistryAt(g, match, request, response, now.Add(10*time.Second))
	if !g.retention(name, ip).Equal(deadline.Add(10*time.Second)) || !response.ReceivedAt.Equal(now) {
		t.Fatal("cache delivery did not renew retention independently of original receipt")
	}
	observeDNSRegistryAt(g, match, request, response, now.Add(time.Minute))
	if !g.retention(name, ip).Equal(deadline.Add(10 * time.Second)) {
		t.Fatal("accepted an expired signature at delivery")
	}
}

func TestPassiveDNSHighBitTTLsMeanZero(t *testing.T) {
	const window = 168 * time.Hour
	for _, test := range []struct {
		name                       string
		addressTTL, aliasTTL       uint32
		addressWindow, aliasWindow time.Duration
	}{
		{"high address", 0x80000000, 1209600, window, window},
		{"all bits", 0xffffffff, 1209600, window, window},
		{"high alias", 1209600, 0x80000000, 2 * window, window},
		{"valid large TTL", 0x7fffffff, 0x7fffffff, 0x7fffffff * time.Second, 0x7fffffff * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			g, _ := newTestRegistry(4, window)
			now := time.Now()
			ip := netip.MustParseAddr("192.0.2.9")
			q := dnsTestRequest(t, "alias.example.", 1)
			response := &plugin.DNSResponse{Message: new(dns.Msg).SetReply(q.Message)}
			alias := testCNAMERecord("alias.example.", "target.example.")
			address := testARecord("target.example.", ip.String())
			alias.Header().Ttl, address.Header().Ttl = test.aliasTTL, test.addressTTL
			response.Message.Answer = []dns.RR{alias, address}
			observeDNSRegistryAt(g, func(string) []uint32 { return testBitmap(0) }, q, response, now)
			if !g.retention("alias.example.", ip).Equal(now.Add(test.aliasWindow)) || !g.retention("target.example.", ip).Equal(now.Add(test.addressWindow)) {
				t.Fatal("high-bit TTL changed evidence deadline")
			}
			if alias.Header().Ttl != test.aliasTTL || address.Header().Ttl != test.addressTTL {
				t.Fatal("evidence calculation mutated delivered TTLs")
			}
		})
	}
}
