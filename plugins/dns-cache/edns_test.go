// SPDX-License-Identifier: AGPL-3.0-only

package dnscache

import (
	"context"
	"net"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

func TestCacheRebuildsOPTForCurrentTransaction(t *testing.T) {
	for _, edns := range []bool{false, true} {
		c := testCache(t, "")
		request := testRequest()
		query := request.MessageCopy()
		if !edns {
			query.Extra = nil
		}
		request.DNSPacket = plugin.DNSMessage(query)
		response := testResponse(request)
		message := response.MessageCopy()
		message.SetEdns0(4096, false)
		response.DNSPacket = plugin.DNSMessage(message)
		c.storeResponse(request, response)
		key, _ := cacheKey(request)
		if entry, ok := c.store.Peek(key); !ok || entry.Value.MessageCopy().IsEdns0() != nil {
			t.Fatal("missing answer or stored an OPT control record")
		}
		query.Id++
		request.DNSPacket = plugin.DNSMessage(query)
		hit, err := c.WrapDNSUpstream(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
			t.Fatal("ordinary answer missed cache")
			return nil, nil
		})(t.Context(), request)
		if err != nil || hit == nil {
			t.Fatalf("hit: %v", err)
		}
		opt := hit.MessageCopy().IsEdns0()
		if edns && (opt == nil || opt.UDPSize() != 1232 || !opt.Do() || len(opt.Option) != 0) || !edns && opt != nil {
			t.Fatalf("wrong OPT for current query: %v", opt)
		}
		if hit.MessageCopy().Id != query.Id || hit.Origin != response.Origin || !hit.ReceivedAt.Equal(response.ReceivedAt) {
			t.Fatal("replay lost identity or response metadata")
		}
		if response.MessageCopy().IsEdns0().UDPSize() != 4096 {
			t.Fatal("mutated the original delivered response")
		}
	}
}

func TestCacheBypassesEDNSOptionsWithoutChangingTTL(t *testing.T) {
	for _, option := range []dns.EDNS0{
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IPv4(192, 0, 2, 0)},
		&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "abcd"},
		&dns.EDNS0_PADDING{Padding: []byte{0, 0}},
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0011223344556677"},
		&dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE, Timeout: 100},
		&dns.EDNS0_LOCAL{Code: 65001, Data: []byte{1}},
	} {
		for _, inQuery := range []bool{false, true} {
			c := testCache(t, "fixed_domain_ttl { test.example: 10 }")
			request := testRequest()
			response := testResponse(request)
			message := response.MessageCopy()
			message.SetEdns0(1232, true)
			message.IsEdns0().Option = []dns.EDNS0{option}
			if inQuery {
				query := request.MessageCopy()
				query.IsEdns0().Option = []dns.EDNS0{option}
				request.DNSPacket = plugin.DNSMessage(query)
			} else {
				response.DNSPacket = plugin.DNSMessage(message)
			}
			calls := 0
			handler := c.WrapDNSUpstream(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
				calls++
				return response, nil
			})
			for range 2 {
				got, err := handler(t.Context(), request)
				if err != nil || got != response {
					t.Fatalf("changed unsupported option %T (query=%t)", option, inQuery)
				}
				c.storeResponse(request, got)
			}
			if calls != 2 || c.store.Snapshot().Entries != 0 {
				t.Fatalf("cached unsupported option %T (query=%t)", option, inQuery)
			}
		}
	}
}
