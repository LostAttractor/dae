// SPDX-License-Identifier: AGPL-3.0-only

package dnsrouter

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
	cache "github.com/daeuniverse/dae/plugins/dns-cache"
	policy "github.com/daeuniverse/dae/plugins/dns-router/policy"
	dns "github.com/miekg/dns"
)

func TestHTTPAgeCannotReviveCacheEntries(t *testing.T) {
	for _, scheme := range []policy.UpstreamScheme{"https", "h3"} {
		for _, test := range []struct {
			name     string
			negative bool
			ttl, age uint32
			wantTTL  uint32
		}{
			{"positive expired", false, 60, 61, 0},
			{"negative expired", true, 60, 10, 0},
			{"invalid high bit", false, 1 << 31, 1, 0},
			{"positive fresh", false, 60, 10, 50},
			{"negative fresh", true, 60, 2, 3},
		} {
			t.Run(string(scheme)+"/"+test.name, func(t *testing.T) {
				var calls atomic.Int32
				address := exchangeHTTPServer(t, scheme, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					wire, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
					query := new(dns.Msg)
					if err != nil || query.Unpack(wire) != nil {
						t.Error("invalid fixture query")
						http.Error(w, "bad query", http.StatusBadRequest)
						return
					}
					response := new(dns.Msg).SetReply(query)
					if test.negative {
						response.Rcode = dns.RcodeNameError
						response.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: test.ttl}, Ns: "ns.example.", Mbox: "hostmaster.example.", Minttl: 5}}
					} else {
						response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: test.ttl}, A: net.ParseIP("192.0.2.1")}}
					}
					wire, err = response.Pack()
					if err != nil {
						t.Error(err)
						return
					}
					w.Header().Set("Content-Type", "application/dns-message")
					w.Header().Set("Age", strconv.FormatUint(uint64(test.age), 10))
					_, _ = w.Write(wire)
				}))
				sections, err := config_parser.Parse("cache {}")
				if err != nil {
					t.Fatal(err)
				}
				factory, err := cache.Configure(plugin.Spec{Config: sections[0]})
				if err != nil {
					t.Fatal(err)
				}
				p, err := factory(t.Context(), plugin.Services{})
				if err != nil {
					t.Fatal(err)
				}
				c := p.(*cache.Cache)
				upstream := &policy.Upstream{Scheme: scheme, Hostname: "example.com", Port: address.Port(), Path: "/dns-query", Ip46: &netutils.Ip46{Ip4: address.Addr()}}
				request := safetyRequest(dns.TypeA)
				request.Destination = address
				request.DialContext = func(ctx context.Context, network, target, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, target)
				}
				request.ListenPacket = func(ctx context.Context, _, _ string) (net.PacketConn, error) {
					return (&net.ListenConfig{}).ListenPacket(ctx, "udp", "127.0.0.1:0")
				}
				handler := c.WrapDNS(func(ctx context.Context, request *plugin.DNSExchange) (*plugin.DNSResponse, error) {
					return Exchange(ctx, request, upstream)
				})
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				defer cancel()
				for attempt := range 2 {
					response, err := handler(ctx, request)
					if err != nil {
						t.Fatal(err)
					}
					if err := request.DNSPacket.ValidateResponse(response.DNSPacket, false); err != nil {
						t.Fatal(err)
					}
					message := response.MessageCopy()
					records := message.Answer
					if test.negative {
						records = message.Ns
					}
					if ttl := records[0].Header().Ttl; ttl > test.wantTTL || attempt == 0 && ttl != test.wantTTL {
						t.Fatalf("TTL=%d, want at most %d", ttl, test.wantTTL)
					}
					if response.Cached != (attempt > 0 && test.wantTTL > 0) {
						t.Fatalf("cached=%v for attempt %d, effective TTL=%d", response.Cached, attempt, test.wantTTL)
					}
					c.ObserveDNS(ctx, request, response)
				}
				wantCalls := int32(2)
				if test.wantTTL > 0 {
					wantCalls = 1
				}
				if calls.Load() != wantCalls {
					t.Fatalf("upstream calls=%d, want %d", calls.Load(), wantCalls)
				}
			})
		}
	}
}
