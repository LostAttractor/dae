// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"
	"slices"
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
		mutate func(*dns.Msg, *dns.Msg)
		want   bool
	}{
		{"valid CNAME", func(*dns.Msg, *dns.Msg) {}, true},
		{"mismatched ID", func(_ *dns.Msg, r *dns.Msg) { r.Id++ }, false},
		{"mismatched question", func(_ *dns.Msg, r *dns.Msg) { r.Question[0].Name = "other.example." }, false},
		{"mismatched question type", func(_ *dns.Msg, r *dns.Msg) { r.Question[0].Qtype = dns.TypeAAAA }, false},
		{"wrong address record type", func(q *dns.Msg, r *dns.Msg) {
			q.Question[0].Qtype = dns.TypeAAAA
			r.Question[0].Qtype = dns.TypeAAAA
		}, false},
		{"truncated", func(_ *dns.Msg, r *dns.Msg) { r.Truncated = true }, false},
		{"error", func(_ *dns.Msg, r *dns.Msg) { r.Rcode = dns.RcodeServerFailure }, false},
		{"cached", func(*dns.Msg, *dns.Msg) {}, true},
		{"notify", func(q *dns.Msg, r *dns.Msg) {
			q.Opcode = dns.OpcodeNotify
			r.Opcode = dns.OpcodeNotify
		}, false},
		{"cycle", func(_ *dns.Msg, r *dns.Msg) {
			r.Answer = append(r.Answer, testCNAMERecord("edge.example.", "original.example."))
		}, false},
		{"invalid alias signature", func(_ *dns.Msg, r *dns.Msg) {
			r.Answer = append(r.Answer, &dns.RRSIG{Hdr: dns.RR_Header{Name: "original.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60}, TypeCovered: dns.TypeCNAME, Inception: uint32(now.Add(-time.Hour).Unix()), Expiration: uint32(now.Add(-time.Second).Unix()), OrigTtl: 60})
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			g, fake := newTestRegistry(16, 7*24*time.Hour)
			request := dnsTestRequest(t, "original.example.", 1)
			query := request.MessageCopy()
			message := new(dns.Msg).SetReply(query)
			message.Answer = []dns.RR{testARecord("unrelated.example.", "203.0.113.9"), testCNAMERecord("original.example.", "edge.example."), testARecord("edge.example.", ip.String())}
			test.mutate(query, message)
			request.DNSPacket = plugin.DNSMessage(query)
			response := &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(message), ReceivedAt: now, Cached: test.name == "cached"}
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
	message := new(dns.Msg).SetReply(request.MessageCopy())
	message.Answer = []dns.RR{testARecord("signed.example.", "198.51.100.1"), &dns.RRSIG{Hdr: dns.RR_Header{Name: "signed.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60}, TypeCovered: dns.TypeA, Inception: uint32(now.Add(-time.Hour).Unix()), Expiration: uint32(now.Add(20 * time.Second).Unix()), OrigTtl: 60}}
	response := &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(message), ReceivedAt: now}
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
			message := new(dns.Msg).SetReply(q.MessageCopy())
			alias := testCNAMERecord("alias.example.", "target.example.")
			address := testARecord("target.example.", ip.String())
			alias.Header().Ttl, address.Header().Ttl = test.aliasTTL, test.addressTTL
			message.Answer = []dns.RR{alias, address}
			response := &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(message)}
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

func TestPassiveDNSBatchPublishesCompleteIPOnce(t *testing.T) {
	now := time.Now()
	g, fake := newTestRegistry(8, time.Second)
	untouched := netip.MustParseAddr("203.0.113.1")
	g.Upsert("untouched.example.", untouched, testBitmap(2), 100, now)
	ips := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
	writes := make(map[netip.Addr]int)
	wantRouting := testBitmap()
	g.kernel.update = func(ip netip.Addr, bump, routing []uint32) {
		if ip == untouched || !slices.Equal(bump, testBitmap(1)) || !slices.Equal(routing, wantRouting) {
			t.Fatal("published an unrelated or incomplete shared-IP state")
		}
		writes[ip]++
		fake.update(ip, bump, routing)
	}
	request := dnsTestRequest(t, "alias.example.", 1)
	message := new(dns.Msg).SetReply(request.MessageCopy())
	alias := testCNAMERecord("alias.example.", "edge.example.")
	alias.Header().Ttl = 10
	message.Answer = []dns.RR{alias}
	for _, ip := range ips {
		rr := testARecord("edge.example.", ip.String())
		rr.Header().Ttl = 60
		message.Answer = append(message.Answer, rr, dns.Copy(rr))
	}
	response := &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(message)}
	match := func(name string) []uint32 {
		if name == "edge.example." {
			return testBitmap(1)
		}
		return testBitmap()
	}
	observeDNSRegistryAt(g, match, request, response, now)
	for _, ip := range ips {
		if writes[ip] != 1 || !g.retention("alias.example.", ip).Equal(now.Add(10*time.Second)) || !g.retention("edge.example.", ip).Equal(now.Add(time.Minute)) {
			t.Fatal("batch duplicated publication or lost per-pair deadlines")
		}
	}
	clear(writes)
	observeDNSRegistryAt(g, match, request, response, now.Add(time.Second))
	if len(writes) != 0 {
		t.Fatal("deadline-only replay republished bitmaps")
	}
	wantRouting = testBitmap(1)
	g.Sweep(now.Add(11 * time.Second))
	for _, ip := range ips {
		if writes[ip] != 1 || g.Verify("alias.example.", ip).Paired {
			t.Fatal("alias collection did not locally update both IPs")
		}
	}
	checkInvariants(t, g, fake)
}
