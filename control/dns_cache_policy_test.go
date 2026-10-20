// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/plugin"
	cache "github.com/daeuniverse/dae/plugins/dns-cache"
	router "github.com/daeuniverse/dae/plugins/dns-router"
	dns "github.com/miekg/dns"
)

type clientDNSRewrite struct{ calls int }

func (*clientDNSRewrite) Plan() plugin.Plan { return plugin.Plan{DNS: []plugin.DNSScope{{}}} }
func (p *clientDNSRewrite) WrapDNS(next plugin.DNSHandler) plugin.DNSHandler {
	return func(ctx context.Context, request *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		p.calls++
		response, err := next(ctx, request)
		if err == nil && response != nil && request.Source.Addr() == netip.MustParseAddr("192.0.2.2") {
			message := response.MessageCopy()
			message.Answer[0].(*dns.A).A = net.ParseIP("198.51.100.2")
			response.DNSPacket = plugin.DNSMessage(message)
		}
		return response, err
	}
}

func TestDNSUpstreamCacheSharesClientsAfterPolicy(t *testing.T) {
	for _, cacheFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "cache first", false: "cache last"}[cacheFirst], func(t *testing.T) {
			cachePlugin := integrationDNSPlugin(t, cache.Plugin, "")
			routerPlugin := integrationDNSPlugin(t, router.Plugin, `
upstream { test:'udp://192.0.2.54:53' }
routing { request { sip(192.0.2.3) -> reject fallback:test } }
`)
			rewrite := new(clientDNSRewrite)
			instances := []mitm.Instance{{ID: "rewrite", Plugin: rewrite}, {ID: "router", Plugin: routerPlugin}}
			if cacheFirst {
				instances = append([]mitm.Instance{{ID: "cache", Plugin: cachePlugin}}, instances...)
			} else {
				instances = append(instances, mitm.Instance{ID: "cache", Plugin: cachePlugin})
			}
			host, err := mitm.New(mitm.Options{DisableHTTP: true}, instances...)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = host.Close() })
			var dials atomic.Int32
			dial := func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				conn, peer := net.Pipe()
				go func() {
					defer peer.Close()
					wire := make([]byte, 4096)
					n, err := peer.Read(wire)
					if err != nil {
						return
					}
					query := new(dns.Msg)
					if query.Unpack(wire[:n]) != nil {
						return
					}
					message := new(dns.Msg).SetReply(query)
					message.Answer = []dns.RR{testARecord(query.Question[0].Name, "198.51.100.1")}
					wire, _ = message.Pack()
					_, _ = peer.Write(wire)
				}()
				return conn, nil
			}
			groups := []*outbound.DialerGroup{downloadTestGroup(t, "direct", dial), downloadTestGroup(t, "block", dial), downloadTestGroup(t, "proxy", dial)}
			matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "sport(40004) -> block\nsip(192.0.2.5) -> proxy(mark:37)"))
			plane := &ControlPlane{mitmHost: host, outbounds: groups, routingMatcher: matcher}
			for i, test := range []struct {
				source, destination, answer string
				wantDials                   int32
				blocked, noNodes            bool
			}{
				{"192.0.2.1:40001", "192.0.2.53:53", "198.51.100.1", 1, false, false},
				{"192.0.2.1:40002", "192.0.2.53:53", "198.51.100.1", 1, false, true},
				{"192.0.2.2:40003", "192.0.2.53:53", "198.51.100.2", 1, false, false},
				{"192.0.2.1:40003", "192.0.2.55:53", "198.51.100.1", 1, false, false},
				{"192.0.2.3:40003", "192.0.2.53:53", "", 1, false, false},
				{"192.0.2.1:40004", "192.0.2.53:53", "", 1, true, false},
				{"192.0.2.5:40005", "192.0.2.53:53", "198.51.100.1", 2, false, false},
			} {
				plane.outbounds = groups
				if test.noNodes {
					plane.outbounds = nil
				}
				query := dnsTestRequest(t, "test.example.", uint16(i))
				request, _, err := plane.dnsRequest(dnsTestWire(t, query), "udp", netip.MustParseAddrPort(test.source), netip.MustParseAddrPort(test.destination), routingResult{CaptureFlags: captureDNS})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				var answer *dns.Msg
				err = plane.processDNS(ctx, request, routingResult{}, false, relayDNSUDP, func(wire []byte) error {
					answer = unpackDNSMessage(wire)
					return nil
				})
				cancel()
				if test.blocked {
					if err == nil || answer != nil {
						t.Fatalf("routing block bypassed: %v", err)
					}
				} else if err != nil || answer == nil || answer.Id != uint16(i) {
					t.Fatalf("query %d: %v, %v", i, answer, err)
				} else if test.answer == "" {
					if len(answer.Answer) != 0 {
						t.Fatal("DNS request rejection bypassed")
					}
				} else if len(answer.Answer) != 1 || answer.Answer[0].(*dns.A).A.String() != test.answer {
					t.Fatalf("raw cache or response policy changed: %s", answer)
				}
				if dials.Load() != test.wantDials {
					t.Fatalf("query %d: dials=%d, want %d", i, dials.Load(), test.wantDials)
				}
			}
			if rewrite.calls != 7 {
				t.Fatalf("response middleware skipped: %d", rewrite.calls)
			}
		})
	}
}

func TestDNSRawCacheSurvivesFailedClientDelivery(t *testing.T) {
	host := integrationDNSHost(t, integrationDNSPlugin(t, cache.Plugin, ""))
	plane := &ControlPlane{mitmHost: host}
	query := dnsTestRequest(t, "test.example.", 1)
	query.Destination = netip.MustParseAddrPort("192.0.2.53:53")
	calls := 0
	terminal := func(_ context.Context, request *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		calls++
		message := new(dns.Msg).SetReply(request.MessageCopy())
		message.Answer = []dns.RR{testARecord("test.example.", "198.51.100.1")}
		return &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(message)}, nil
	}
	want := errors.New("client disconnected")
	if err := plane.processDNS(t.Context(), query, routingResult{}, false, terminal, func([]byte) error { return want }); !errors.Is(err, want) {
		t.Fatal(err)
	}
	if err := plane.processDNS(t.Context(), query, routingResult{}, false, terminal, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("valid upstream answer lost after delivery failure: %d", calls)
	}
}

func TestDNSCacheSeparatesClientSelectedServersAndRoutingGenerations(t *testing.T) {
	host := integrationDNSHost(t, integrationDNSPlugin(t, cache.Plugin, ""))
	plane := &ControlPlane{mitmHost: host}
	calls := 0
	terminal := func(_ context.Context, request *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		calls++
		message := new(dns.Msg).SetReply(request.MessageCopy())
		message.Answer = []dns.RR{testARecord("test.example.", request.Destination.Addr().String())}
		return &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(message)}, nil
	}
	for i, test := range []struct {
		server     string
		generation uint32
		wantCalls  int
	}{
		{"192.0.2.53:53", 1, 1},
		{"192.0.2.54:53", 1, 2},
		{"192.0.2.53:53", 1, 2},
		{"192.0.2.53:53", 2, 3},
	} {
		plane.routingGeneration = test.generation
		packet := dnsTestRequest(t, "test.example.", uint16(i))
		source := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(40000+i))
		request, _, err := plane.dnsRequest(dnsTestWire(t, packet), "udp", source, netip.MustParseAddrPort(test.server), routingResult{CaptureFlags: captureDNS})
		if err != nil {
			t.Fatal(err)
		}
		if err := plane.processDNS(t.Context(), request, routingResult{}, false, terminal, func(wire []byte) error {
			message := unpackDNSMessage(wire)
			if len(message.Answer) != 1 || message.Answer[0].(*dns.A).A.String() != request.Destination.Addr().String() {
				t.Fatalf("shared different DNS servers: %s", message)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if calls != test.wantCalls {
			t.Fatalf("query %d: calls=%d, want %d", i, calls, test.wantCalls)
		}
	}
}
