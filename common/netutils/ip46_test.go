/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	outboundcommon "github.com/daeuniverse/dae/pkg/outbound/common"
	"github.com/miekg/dns"
)

func TestOutboundResolverUsesDefaultResolver(t *testing.T) {
	original := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = original })

	var dialed atomic.Bool
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			dialed.Store(true)
			return nil, errors.New("resolver dial intercepted")
		},
	}
	if _, err := outboundcommon.ResolveUDPAddrContext(t.Context(), net.DefaultResolver, "ip", "default-resolver-integration.invalid:53"); err == nil {
		t.Fatal("outbound resolver unexpectedly succeeded")
	}
	if !dialed.Load() {
		t.Fatal("outbound resolver did not use net.DefaultResolver")
	}
}

func TestResolveIp46ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ResolveIp46Context(ctx, "context-cancellation.invalid"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveIp46Context returned %v, want context cancellation", err)
	}
}

func TestResolveIp46(t *testing.T) {
	original := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = original })
	for _, test := range []struct {
		name      string
		addresses []string
		want      Ip46
	}{
		{"IPv4", []string{"192.0.2.4"}, Ip46{Ip4: netip.MustParseAddr("192.0.2.4")}},
		{"IPv6", []string{"2001:db8::6"}, Ip46{Ip6: netip.MustParseAddr("2001:db8::6")}},
		{"dual stack", []string{"192.0.2.4", "2001:db8::6"}, Ip46{
			Ip4: netip.MustParseAddr("192.0.2.4"), Ip6: netip.MustParseAddr("2001:db8::6"),
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var peers sync.WaitGroup
			t.Cleanup(peers.Wait)
			net.DefaultResolver = &net.Resolver{
				PreferGo: true,
				Dial: func(context.Context, string, string) (net.Conn, error) {
					client, server := net.Pipe()
					peers.Go(func() {
						defer server.Close()
						conn := &dns.Conn{Conn: server}
						request, err := conn.ReadMsg()
						if err != nil {
							t.Errorf("read DNS query: %v", err)
							return
						}
						if len(request.Question) != 1 || request.Question[0].Name != "ip46.test." {
							t.Errorf("unexpected DNS question: %v", request.Question)
							return
						}
						question := request.Question[0]
						response := new(dns.Msg).SetReply(request)
						for _, address := range test.addresses {
							ip := netip.MustParseAddr(address)
							header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 60}
							if ip.Is4() && question.Qtype == dns.TypeA {
								response.Answer = append(response.Answer, &dns.A{Hdr: header, A: ip.AsSlice()})
							} else if ip.Is6() && question.Qtype == dns.TypeAAAA {
								response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: ip.AsSlice()})
							}
						}
						if err := conn.WriteMsg(response); err != nil {
							t.Errorf("write DNS response: %v", err)
						}
					})
					return client, nil
				},
			}
			got, err := ResolveIp46("ip46.test.")
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || *got != test.want {
				t.Fatalf("ResolveIp46 = %+v, want %+v", got, test.want)
			}
		})
	}
}
