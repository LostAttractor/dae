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
