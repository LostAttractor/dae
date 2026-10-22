// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

func TestUpstreamResolverHonorsCancellation(t *testing.T) {
	raw, _ := url.Parse("https://dns.example/dns-query")
	resolver := &UpstreamResolver{Raw: raw}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := resolver.GetUpstream(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("GetUpstream = %v", err)
	}
}

func TestUpstreamRefreshesAddressesWithoutReload(t *testing.T) {
	original := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = original })
	var octet atomic.Uint32
	octet.Store(1)
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		client, peer := net.Pipe()
		go func() {
			defer peer.Close()
			conn := &dns.Conn{Conn: peer}
			query, err := conn.ReadMsg()
			if err != nil {
				return
			}
			reply := new(dns.Msg).SetReply(query)
			if query.Question[0].Qtype == dns.TypeA {
				reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: net.IPv4(192, 0, 2, byte(octet.Load()))}}
			}
			_ = conn.WriteMsg(reply)
		}()
		return client, nil
	}}
	raw, _ := url.Parse("https://rotating-upstream.example./dns-query")
	resolver := &UpstreamResolver{Raw: raw}
	for _, last := range []uint32{1, 2} {
		octet.Store(last)
		upstream, err := resolver.GetUpstream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		var got []netip.Addr
		for ip, err := range upstream.Addresses(t.Context()) {
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, ip)
		}
		want := netip.AddrFrom4([4]byte{192, 0, 2, byte(last)})
		if len(got) != 1 || got[0] != want {
			t.Fatalf("addresses = %v, want %s", got, want)
		}
		if snapshot := upstream.KnownAddresses(); len(snapshot) != 1 || snapshot[0] != want {
			t.Fatalf("diagnostic snapshot = %v", snapshot)
		}
	}
}

func TestUpstreamRecordsEachCompleteFamily(t *testing.T) {
	original := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = original })
	var round atomic.Uint32
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		client, peer := net.Pipe()
		go func() {
			defer peer.Close()
			conn := &dns.Conn{Conn: peer}
			query, err := conn.ReadMsg()
			if err != nil {
				return
			}
			q := query.Question[0]
			reply := new(dns.Msg).SetReply(query)
			header := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET}
			if q.Qtype == dns.TypeAAAA {
				reply.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.ParseIP(fmt.Sprintf("2001:db8::%d", round.Load()))}}
			} else {
				if round.Load() > 1 {
					<-hold // The race wins before IPv4 is answered.
					return
				}
				reply.Answer = []dns.RR{&dns.A{Hdr: header, A: net.IPv4(192, 0, 2, 1)}}
			}
			_ = conn.WriteMsg(reply)
		}()
		return client, nil
	}}
	raw, _ := url.Parse("tls://families.example.")
	upstream, err := NewUpstream(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	ipv4 := netip.MustParseAddr("192.0.2.1")
	for _, test := range []struct {
		round uint32
		take  int
		known []netip.Addr
	}{
		{1, 2, []netip.Addr{netip.MustParseAddr("2001:db8::1"), ipv4}},
		// An early winner records IPv6 and keeps the last complete IPv4 answer.
		{2, 1, []netip.Addr{netip.MustParseAddr("2001:db8::2"), ipv4}},
	} {
		round.Store(test.round)
		taken := 0
		for _, err := range upstream.Addresses(t.Context()) {
			if err != nil {
				t.Fatal(err)
			}
			if taken++; taken == test.take {
				break
			}
		}
		if known := upstream.KnownAddresses(); !slices.Equal(known, test.known) {
			t.Fatalf("round %d known = %v, want %v", test.round, known, test.known)
		}
	}
}
