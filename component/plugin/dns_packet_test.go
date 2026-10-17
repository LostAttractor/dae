// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"bytes"
	"net/netip"
	"strings"
	"sync"
	"testing"

	dns "github.com/miekg/dns"
)

func TestDNSPacketReplacementCannotReuseStaleWire(t *testing.T) {
	query := new(dns.Msg).SetQuestion("original.example.", dns.TypeA)
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	original := DNSWire(wire)
	wire[0] ^= 0xff // Constructor owns its input, including the parsed view.
	copy := original.MessageCopy()
	copy.Question[0].Name = "changed.example."
	updated := DNSMessage(copy)
	copy.Question[0].Name = "after-construction.example."
	got, err := updated.Wire()
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(dns.Msg)
	if err := decoded.Unpack(got); err != nil || decoded.Question[0].Name != "changed.example." {
		t.Fatalf("serialized stale/aliased query: %v %v", decoded, err)
	}
	if original.MessageCopy().Question[0].Name != "original.example." || original.MessageCopy().Id != query.Id || !original.IsWire() || updated.IsWire() {
		t.Fatal("replacement changed the original packet or representation")
	}
}

func TestDNSPacketOpaqueBytesAndEncodingErrors(t *testing.T) {
	query := new(dns.Msg).SetQuestion("test.example.", dns.TypeA)
	valid, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for _, wire := range [][]byte{nil, {}, {0, 1, 2}, append(valid, 0xff)} {
		packet := DNSWire(wire)
		got, err := packet.Wire()
		if err != nil || !bytes.Equal(got, wire) || !packet.IsWire() || packet.MessageCopy() != nil {
			t.Fatalf("opaque packet was normalized: %x %v", got, err)
		}
	}
	query.Question[0].Name = strings.Repeat("x", 64) + ".example."
	if _, err := DNSMessage(query).Wire(); err == nil {
		t.Fatal("invalid local message lost its encoding error")
	}
}

func TestDNSForkRetainsIdentityAndIsolatesQuery(t *testing.T) {
	original := &DNSExchange{DNSPacket: DNSMessage(new(dns.Msg).SetQuestion("test.example.", dns.TypeA)),
		Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("192.0.2.53:53"), ContextKey: "client-policy"}
	probe := original.Fork()
	message := probe.MessageCopy()
	message.Question[0].Qtype = dns.TypeAAAA
	probe.DNSPacket = DNSMessage(message)
	if original.Independent() || !probe.Independent() || original.Source != probe.Source || original.Destination != probe.Destination || original.ContextKey != probe.ContextKey || original.MessageCopy().Question[0].Qtype != dns.TypeA {
		t.Fatal("fork lost identity, changed its parent or retained its transport lifetime")
	}
}

func TestDNSPacketConcurrentEncodingPreservesEDNS(t *testing.T) {
	message := new(dns.Msg).SetQuestion("test.example.", dns.TypeA)
	message.SetEdns0(1232, true)
	message.Rcode = dns.RcodeBadVers
	originalTTL := message.IsEdns0().Hdr.Ttl
	request := &DNSExchange{DNSPacket: DNSMessage(message)}
	var wg sync.WaitGroup
	for _, copy := range []*DNSExchange{request, request.Copy(), request.Fork()} {
		wg.Go(func() {
			for range 100 {
				wire, err := copy.Wire()
				if err != nil {
					t.Error(err)
					return
				}
				decoded := new(dns.Msg)
				if err := decoded.Unpack(wire); err != nil || decoded.Rcode != dns.RcodeBadVers || decoded.IsEdns0() == nil || !decoded.IsEdns0().Do() {
					t.Errorf("lost extended RCODE or DO flag: %v, %v", decoded, err)
					return
				}
				if copy.MessageCopy().IsEdns0().Hdr.Ttl != originalTTL {
					t.Error("encoding mutated the shared message")
					return
				}
			}
		})
	}
	wg.Wait()
}

func TestDNSScalarReadsAndValidationPreservePackets(t *testing.T) {
	query := new(dns.Msg).SetQuestion("example.test.", dns.TypeA)
	query.SetEdns0(1232, true)
	packet := DNSMessage(query)
	if allocated := testing.AllocsPerRun(100, func() {
		header, parsed := packet.Header()
		question, single := packet.Question()
		if !parsed || !single || header.Id != query.Id || question.Name != "example.test." || !packet.HasAdditional(dns.TypeOPT) {
			t.Fatal("lost DNS scalars")
		}
	}); allocated != 0 {
		t.Fatal(allocated)
	}
	response := new(dns.Msg).SetRcode(query, dns.RcodeServerFailure)
	response.Question = nil
	negative := DNSMessage(response)
	if err := packet.ValidateResponse(negative, true); err != nil {
		t.Fatal(err)
	}
	if _, present := negative.Question(); present {
		t.Fatal("validation changed immutable response")
	}
	if err := packet.ValidateResponse(negative, false); err == nil {
		t.Fatal("strict validation accepted missing question")
	}
}

func TestDNSPacketReplayable(t *testing.T) {
	for _, test := range []struct {
		name   string
		modify func(*dns.Msg)
		want   bool
	}{
		{"query", func(*dns.Msg) {}, true},
		{"other class", func(m *dns.Msg) { m.Question[0].Qclass = dns.ClassCHAOS }, true},
		{"edns", func(m *dns.Msg) { m.SetEdns0(1232, true) }, true},
		{"response", func(m *dns.Msg) { m.Response = true }, false},
		{"update", func(m *dns.Msg) { m.Opcode = dns.OpcodeUpdate }, false},
		{"empty question", func(m *dns.Msg) { m.Question = nil }, false},
		{"multiple questions", func(m *dns.Msg) { m.Question = append(m.Question, m.Question[0]) }, false},
		{"zone transfer", func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeAXFR }, false},
		{"incremental transfer", func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeIXFR }, false},
		{"key negotiation", func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeTKEY }, false},
		{"transaction signature", func(m *dns.Msg) { m.SetTsig("key.", dns.HmacSHA256, 300, 0) }, false},
		{"signature", func(m *dns.Msg) {
			m.Extra = append(m.Extra, &dns.SIG{RRSIG: dns.RRSIG{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeSIG}, SignerName: "."}})
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := new(dns.Msg).SetQuestion("example.test.", dns.TypeA)
			test.modify(message)
			packet := DNSMessage(message)
			wire, err := packet.Wire()
			if err != nil {
				t.Fatal(err)
			}
			if packet.Replayable() != test.want || DNSWire(wire).Replayable() != test.want {
				t.Fatalf("replayable local/wire packet = %v/%v, want %v", packet.Replayable(), DNSWire(wire).Replayable(), test.want)
			}
		})
	}
	if (DNSPacket{}).Replayable() || DNSWire([]byte{1, 2}).Replayable() {
		t.Fatal("empty or opaque packet is replayable")
	}
}
