// SPDX-License-Identifier: AGPL-3.0-only

package dnscache

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

func TestHighBitTTLIsNotCached(t *testing.T) {
	for _, section := range []string{"answer", "authority", "additional", "minimum"} {
		for _, ttl := range []uint32{0x80000000, 0xffffffff} {
			c := testCache(t, "")
			q := testRequest()
			r := testResponse(q)
			message := r.MessageCopy()
			switch section {
			case "answer":
				message.Answer[0].Header().Ttl = ttl
			case "authority", "minimum":
				message.Answer = nil
				soa := &dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.example.", Mbox: "hostmaster.example.", Minttl: 60}
				if section == "authority" {
					soa.Hdr.Ttl = ttl
				} else {
					soa.Minttl = ttl
				}
				message.Ns = []dns.RR{soa}
			case "additional":
				message.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: message.Answer[0].(*dns.A).A}}
			}
			r.DNSPacket = plugin.DNSMessage(message)
			c.ObserveDNS(t.Context(), q, r)
			if len(c.entries) != 0 {
				t.Fatalf("cached high-bit %s TTL %x", section, ttl)
			}
		}
	}
}

func TestFixedTTLStrictWireAndCorrelation(t *testing.T) {
	for _, kind := range []string{"trailing", "ID", "question", "QR", "opcode", "header-only error", "valid"} {
		t.Run(kind, func(t *testing.T) {
			c := testCache(t, "fixed_domain_ttl { test.example: 120 }")
			q := testRequest()
			r := testResponse(q)
			m := r.MessageCopy()
			switch kind {
			case "ID":
				m.Id++
			case "question":
				m.Question[0].Name = "other.example."
			case "QR":
				m.Response = false
			case "opcode":
				m.Opcode = dns.OpcodeNotify
			case "header-only error":
				m.Question, m.Answer, m.Rcode = nil, nil, dns.RcodeRefused
			}
			wire, _ := m.Pack()
			if kind == "trailing" {
				wire = append(wire, 0xff)
			}
			r.DNSPacket = plugin.DNSWire(wire)
			original := bytes.Clone(wire)
			got, err := c.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) { return r, nil })(t.Context(), q)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "valid" {
				if got.IsWire() || got.MessageCopy().Answer[0].Header().Ttl != 120 {
					t.Fatal("fixed TTL not applied")
				}
			} else if !bytes.Equal(packetWire(t, got), original) {
				t.Fatal("invalid response was rewritten")
			}
			if !bytes.Equal(packetWire(t, r), original) {
				t.Fatal("downstream response mutated")
			}
		})
	}
}

func TestNegativeReplayAgesSOAMinimum(t *testing.T) {
	for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeNameError} {
		c := testCache(t, "")
		q := testRequest()
		r := testResponse(q)
		message := r.MessageCopy()
		message.Answer, message.Rcode = nil, rcode
		message.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.example.", Mbox: "hostmaster.example.", Minttl: 5}}
		r.DNSPacket = plugin.DNSMessage(message)
		r.ReceivedAt = time.Now().Add(-3 * time.Second)
		c.ObserveDNS(t.Context(), q, r)
		got, err := c.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
			t.Fatal("cache miss")
			return nil, nil
		})(t.Context(), q)
		if err != nil {
			t.Fatal(err)
		}
		soa := got.MessageCopy().Ns[0].(*dns.SOA)
		if soa.Hdr.Ttl > 2 || soa.Minttl != 5 {
			t.Fatalf("negative lifetime extended: %s", soa)
		}
		if r.MessageCopy().Ns[0].Header().Ttl != 60 {
			t.Fatal("original SOA modified")
		}
	}
}

func packetWire(t *testing.T, packet interface{ Wire() ([]byte, error) }) []byte {
	t.Helper()
	wire, err := packet.Wire()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
