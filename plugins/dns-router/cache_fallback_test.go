// SPDX-License-Identifier: AGPL-3.0-only

package dnsrouter

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
	cache "github.com/daeuniverse/dae/plugins/dns-cache"
	policy "github.com/daeuniverse/dae/plugins/dns-router/policy"
	dns "github.com/miekg/dns"
)

func TestCachedTCPFallbackRespectsRouting(t *testing.T) {
	for _, test := range []struct {
		name                                               string
		differentPolicy, udpRecovered, blockTCP, newPolicy bool
		wantCached, wantError                              bool
		wantUDP, wantTCP                                   int
		wantAnswer                                         string
	}{
		{name: "dead UDP", wantCached: true, wantUDP: 1, wantTCP: 1, wantAnswer: "198.51.100.1"},
		{name: "recovered UDP", udpRecovered: true, wantCached: true, wantUDP: 1, wantTCP: 1, wantAnswer: "198.51.100.1"},
		{name: "different protocol policy", differentPolicy: true, udpRecovered: true, wantUDP: 2, wantTCP: 1, wantAnswer: "198.51.100.2"},
		{name: "blocked TCP", blockTCP: true, wantError: true, wantUDP: 2, wantTCP: 1},
		{name: "changed policy", newPolicy: true, wantUDP: 2, wantTCP: 2, wantAnswer: "198.51.100.1"},
	} {
		t.Run(test.name, func(t *testing.T) {
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
			request := safetyRequest(dns.TypeA)
			request.SelectCaches = func(plugin.DNSPacket) []plugin.DNSUpstreamCache { return []plugin.DNSUpstreamCache{c} }
			warm := false
			preparations := make(map[string]int)
			request.RouteUpstream = func(_ context.Context, r *plugin.DNSExchange, upstream plugin.DNSUpstream) (*plugin.DNSExchange, error) {
				preparations[upstream.Network]++
				if warm && test.blockTCP && upstream.Network == "tcp" {
					return nil, errors.New("TCP blocked by policy")
				}
				r.PolicyKey.Outbound = 0
				if test.differentPolicy && upstream.Network == "tcp" {
					r.PolicyKey.Outbound = 2
				}
				if warm && test.newPolicy {
					r.PolicyKey.Generation++
				}
				return r, nil
			}
			udp, tcp := 0, 0
			request.DialContext = func(ctx context.Context, network, target, hostname string) (net.Conn, error) {
				answer := "198.51.100.1"
				if network == "udp" {
					udp++
					if !warm || !test.udpRecovered {
						<-ctx.Done()
						return nil, ctx.Err()
					}
					answer = "198.51.100.2"
				} else {
					tcp++
				}
				conn, peer := net.Pipe()
				go func() {
					defer peer.Close()
					var wire []byte
					var err error
					if network == "tcp" {
						wire, err = netutils.ReadDNSFrame(peer)
					} else {
						wire = make([]byte, 4096)
						var n int
						n, err = peer.Read(wire)
						wire = wire[:n]
					}
					query := new(dns.Msg)
					if err != nil || query.Unpack(wire) != nil {
						return
					}
					message := new(dns.Msg).SetReply(query)
					message.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(answer)}}
					wire, _ = message.Pack()
					if network == "tcp" {
						_ = netutils.WriteDNSFrame(peer, wire)
					} else {
						_, _ = peer.Write(wire)
					}
				}()
				return conn, nil
			}
			upstream := &policy.Upstream{Scheme: policy.UpstreamScheme_TCP_UDP, Hostname: "192.0.2.53", Port: 53, Ip46: &netutils.Ip46{Ip4: netip.MustParseAddr("192.0.2.53")}}
			ask := func() (*plugin.DNSResponse, error) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				return exchangeForTest(ctx, request, upstream)
			}
			if response, err := ask(); err != nil || response.Cached {
				t.Fatalf("warm cache: %+v, %v", response, err)
			}
			if preparations["udp"] != 1 || preparations["tcp"] != 2 {
				t.Fatalf("primary was prepared twice or fallback reused a stale decision: %v", preparations)
			}
			warm = true
			started := time.Now()
			response, err := ask()
			t.Logf("warm request: %s, UDP dials=%d TCP dials=%d", time.Since(started), udp, tcp)
			if (err != nil) != test.wantError {
				t.Fatalf("unexpected result: %+v, %v", response, err)
			}
			if err == nil && (response.Cached != test.wantCached || response.MessageCopy().Answer[0].(*dns.A).A.String() != test.wantAnswer) {
				t.Fatalf("wrong cached policy answer: %+v", response)
			}
			if udp != test.wantUDP || tcp != test.wantTCP {
				t.Fatalf("dials: UDP=%d TCP=%d, want UDP=%d TCP=%d", udp, tcp, test.wantUDP, test.wantTCP)
			}
			stats := c.Report().(map[string]any)
			if test.wantCached && (stats["hits"] != uint64(1) || stats["misses"] != uint64(2)) {
				t.Fatalf("speculative lookups changed cache counts: %v", stats)
			}
		})
	}
}

func TestFallbackRechecksPolicyAfterTransport(t *testing.T) {
	request := safetyRequest(dns.TypeA)
	request.SelectCaches = func(plugin.DNSPacket) []plugin.DNSUpstreamCache { return nil }
	blocked := false
	denied := errors.New("TCP denied by updated routing policy")
	tcpChecks, dials := 0, 0
	request.RouteUpstream = func(_ context.Context, r *plugin.DNSExchange, upstream plugin.DNSUpstream) (*plugin.DNSExchange, error) {
		if upstream.Network == "tcp" {
			tcpChecks++
			if blocked {
				return nil, denied
			}
		}
		return r, nil
	}
	request.DialContext = func(_ context.Context, network, _, _ string) (net.Conn, error) {
		dials++
		if network != "udp" {
			t.Fatal("fallback used the policy from before the UDP attempt")
		}
		blocked = true
		return nil, net.ErrClosed
	}
	upstream := &policy.Upstream{Scheme: policy.UpstreamScheme_TCP_UDP, Hostname: "192.0.2.53", Port: 53, Ip46: &netutils.Ip46{Ip4: netip.MustParseAddr("192.0.2.53")}}
	if _, err := exchangeForTest(t.Context(), request, upstream); !errors.Is(err, denied) || tcpChecks != 2 || dials != 1 {
		t.Fatalf("stale fallback decision: TCP checks=%d, dials=%d, err=%v", tcpChecks, dials, err)
	}
}
