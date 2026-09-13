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
			switch section {
			case "answer":
				r.Message.Answer[0].Header().Ttl = ttl
			case "authority", "minimum":
				r.Message.Answer = nil
				soa := &dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.example.", Mbox: "hostmaster.example.", Minttl: 60}
				if section == "authority" {
					soa.Hdr.Ttl = ttl
				} else {
					soa.Minttl = ttl
				}
				r.Message.Ns = []dns.RR{soa}
			case "additional":
				r.Message.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: r.Message.Answer[0].(*dns.A).A}}
			}
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
			m := r.Message.Copy()
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
			r.Wire, _ = m.Pack()
			if kind == "trailing" {
				r.Wire = append(r.Wire, 0xff)
			}
			// Even a supplied valid Message must not override invalid wire.
			original := bytes.Clone(r.Wire)
			got, err := c.WrapDNS(func(context.Context, *plugin.DNSRequest) (*plugin.DNSResponse, error) { return r, nil })(t.Context(), q)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "valid" {
				if len(got.Wire) != 0 || got.Message.Answer[0].Header().Ttl != 120 {
					t.Fatal("fixed TTL not applied")
				}
			} else if !bytes.Equal(got.Wire, original) {
				t.Fatal("invalid response was rewritten")
			}
			if !bytes.Equal(r.Wire, original) || r.Message.Answer[0].Header().Ttl != 60 {
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
		r.Message.Answer, r.Message.Rcode = nil, rcode
		r.Message.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.example.", Mbox: "hostmaster.example.", Minttl: 5}}
		r.ReceivedAt = time.Now().Add(-3 * time.Second)
		c.ObserveDNS(t.Context(), q, r)
		got, err := c.WrapDNS(func(context.Context, *plugin.DNSRequest) (*plugin.DNSResponse, error) {
			t.Fatal("cache miss")
			return nil, nil
		})(t.Context(), q)
		if err != nil {
			t.Fatal(err)
		}
		soa := got.Message.Ns[0].(*dns.SOA)
		if soa.Hdr.Ttl > 2 || soa.Minttl != 5 {
			t.Fatalf("negative lifetime extended: %s", soa)
		}
		if r.Message.Ns[0].Header().Ttl != 60 {
			t.Fatal("original SOA modified")
		}
	}
}
