//go:build dns_plugins_integration

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

	cache "github.com/daeuniverse/dae-plugin-dns-cache"
	router "github.com/daeuniverse/dae-plugin-dns-router"
	policy "github.com/daeuniverse/dae-plugin-dns-router/policy"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dns "github.com/miekg/dns"
)

func integrationDNSPlugin(t *testing.T, definition plugin.Definition, body string) plugin.Plugin {
	t.Helper()
	sections, err := config_parser.Parse("test {" + body + "}")
	if err != nil {
		t.Fatal(err)
	}
	factory, err := definition.Configure(plugin.Spec{Config: sections[0]})
	if err != nil {
		t.Fatal(err)
	}
	p, err := factory(t.Context(), plugin.Services{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func integrationDNSHost(t *testing.T, p plugin.Plugin) *mitm.Host {
	t.Helper()
	h, err := mitm.New(mitm.Options{DisableHTTP: true}, mitm.Instance{ID: "test", Plugin: p})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func TestDNSCacheEvidenceBoundary(t *testing.T) {
	for _, malformed := range []bool{true, false} {
		t.Run(map[bool]string{true: "fixed TTL malformed wire", false: "high-bit TTL replay"}[malformed], func(t *testing.T) {
			body := ""
			if malformed {
				body = "fixed_domain_ttl { test.example: 60 }"
			}
			host := integrationDNSHost(t, integrationDNSPlugin(t, cache.Plugin, body))
			registry, _ := newTestRegistry(4, 168*time.Hour)
			matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "domain(full:test.example) -> proxy"))
			c := &ControlPlane{mitmHost: host, core: &controlPlaneCore{domainRegistry: registry}, routingMatcher: matcher}
			q := dnsTestRequest(t, "test.example.", 7)
			q.ContextKey, q.Destination = "same-client", netip.MustParseAddrPort("192.0.2.53:53")
			calls := 0
			terminal := func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
				calls++
				m := new(dns.Msg).SetReply(q.MessageCopy())
				m.Answer = []dns.RR{testARecord("test.example.", "192.0.2.66")}
				if !malformed {
					m.Answer[0].Header().Ttl = 0x80000000
				}
				wire, _ := m.Pack()
				if malformed {
					wire = append(wire, 0xff)
				}
				return &plugin.DNSResponse{DNSPacket: plugin.DNSWire(wire), ReceivedAt: time.Now().Add(-3 * time.Second)}, nil
			}
			for range 2 {
				message := q.MessageCopy()
				message.Id++
				q.DNSPacket = plugin.DNSMessage(message)
				if err := c.processDNS(t.Context(), q, bpfRoutingResult{}, false, terminal, func([]byte) error { return nil }); err != nil {
					t.Fatal(err)
				}
			}
			if calls != 2 {
				t.Fatal("invalid/zero-equivalent response was cached")
			}
			if malformed {
				if registry.Size() != 0 {
					t.Fatal("malformed packet published evidence")
				}
			} else {
				deadline := registry.retention("test.example.", netip.MustParseAddr("192.0.2.66"))
				if time.Until(deadline) > 169*time.Hour || time.Until(deadline) < 167*time.Hour {
					t.Fatalf("incorrect evidence deadline: %s", deadline)
				}
			}
		})
	}
}

func TestDNSPreferenceProbeLeavesDeliveryBudget(t *testing.T) {
	host := integrationDNSHost(t, integrationDNSPlugin(t, router.Plugin, "ipversion_prefer:6"))
	c := &ControlPlane{mitmHost: host}
	q := dnsTestRequest(t, "test.example.", 7)
	q.Network, q.Source = "udp", netip.MustParseAddrPort("192.0.2.1:2345")
	q.OriginalDestination = netip.MustParseAddrPort("192.0.2.53:53")
	q.Destination = q.OriginalDestination
	q.DialContext = func(context.Context, string, string, string) (net.Conn, error) {
		c, p := net.Pipe()
		go func() {
			defer p.Close()
			buf := make([]byte, 4096)
			n, err := p.Read(buf)
			if err != nil {
				return
			}
			request := unpackDNSMessage(buf[:n])
			if request.Question[0].Qtype == dns.TypeA {
				response := new(dns.Msg).SetReply(request)
				response.Answer = []dns.RR{testARecord("test.example.", "192.0.2.66")}
				wire, _ := response.Pack()
				_, _ = p.Write(wire)
			} else {
				_, _ = p.Read(buf)
			}
		}()
		return c, nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 400*time.Millisecond)
	defer cancel()
	delivered := false
	err := c.processDNS(ctx, q, bpfRoutingResult{}, false, relayDNSUDP, func(wire []byte) error {
		m := unpackDNSMessage(wire)
		if !dnsResponseMatches(q.MessageCopy(), m) || len(m.Answer) != 1 {
			t.Fatal("requested answer changed")
		}
		delivered = true
		return nil
	})
	if err != nil || !delivered {
		t.Fatalf("successful A lost to probe timeout: %v %v", delivered, err)
	}
}

func TestDNSRouterEndpointHostnameEnforcesBlock(t *testing.T) {
	for _, seeded := range []bool{false, true} {
		directCalled := false
		direct := downloadTestGroup(t, "direct", func(context.Context, string, string) (net.Conn, error) {
			directCalled = true
			return nil, errors.New("unexpected direct dial")
		})
		block := downloadTestGroup(t, "block", func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("blocked") })
		matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "domain(full:dns.example) -> block"))
		registry, _ := newTestRegistry(4, time.Hour)
		target := netip.MustParseAddrPort("192.0.2.54:53")
		if seeded {
			registry.Upsert("dns.example.", target.Addr(), matcher.domainMatcher.MatchDomainBitmap("dns.example."), 60, time.Now())
		}
		c := &ControlPlane{outbounds: []*outbound.DialerGroup{direct, block}, routingMatcher: matcher, core: &controlPlaneCore{domainRegistry: registry}}
		source := netip.MustParseAddrPort("192.0.2.1:2345")
		outbound, _, _, err := c.Route(source, target, "dns.example", consts.L4ProtoType_UDP, &bpfRoutingResult{})
		if err != nil || outbound != consts.OutboundBlock {
			t.Fatalf("fixture route: %v %v", outbound, err)
		}
		for _, scheme := range []policy.UpstreamScheme{policy.UpstreamScheme_UDP, policy.UpstreamScheme_TCP} {
			q, _, err := c.dnsRequest(dnsTestWire(t, dnsTestRequest(t, "test.example.", 1)), "udp", source, netip.MustParseAddrPort("192.0.2.53:53"), bpfRoutingResult{CaptureFlags: 8})
			if err != nil {
				t.Fatal(err)
			}
			upstream := &policy.Upstream{Scheme: scheme, Hostname: "dns.example", Port: 53, Ip46: &netutils.Ip46{Ip4: target.Addr()}}
			_, err = router.Exchange(t.Context(), q, upstream)
			if directCalled || err == nil {
				t.Fatalf("hostname block bypassed: seeded=%v err=%v", seeded, err)
			}
		}
	}
}

type budgetDNSPlugin struct{ plugin.DNSPlugin }

func (p budgetDNSPlugin) WrapDNS(next plugin.DNSHandler) plugin.DNSHandler {
	handler := p.DNSPlugin.WrapDNS(next)
	return func(ctx context.Context, r *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		ctx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
		defer cancel()
		return handler(ctx, r)
	}
}
func (p budgetDNSPlugin) Close() error { return p.DNSPlugin.(*router.Router).Close() }

func TestDNSPreferenceTCPCancellationPreservesClientStream(t *testing.T) {
	p := integrationDNSPlugin(t, router.Plugin, "ipversion_prefer:6").(plugin.DNSPlugin)
	host := integrationDNSHost(t, budgetDNSPlugin{p})
	var streams atomic.Int32
	group := downloadTestGroup(t, "direct", func(context.Context, string, string) (net.Conn, error) {
		streams.Add(1)
		c, p := net.Pipe()
		go func() {
			defer p.Close()
			for {
				wire, err := readDNSFrame(p)
				if err != nil {
					return
				}
				q := unpackDNSMessage(wire)
				if q.Question[0].Qtype == dns.TypeAAAA {
					continue
				}
				m := new(dns.Msg).SetReply(q)
				m.Answer = []dns.RR{testARecord("test.example.", "192.0.2.66")}
				wire, _ = m.Pack()
				if writeDNSFrame(p, wire) != nil {
					return
				}
			}
		}()
		return c, nil
	})
	c := &ControlPlane{dnsRelay: newDNSRelay(), mitmHost: host, outbounds: []*outbound.DialerGroup{group}}
	client, accepted := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer accepted.Close()
		_ = c.serveDNSTCP(accepted, netip.MustParseAddrPort("192.0.2.1:2345"), netip.MustParseAddrPort("192.0.2.53:53"), bpfRoutingResult{CaptureFlags: 8})
	}()
	t.Cleanup(func() { client.Close(); c.dnsRelay.Close(); <-done })
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	for id := range uint16(2) {
		q := dnsTestRequest(t, "test.example.", id)
		if err := writeDNSFrame(client, dnsTestWire(t, q)); err != nil {
			t.Fatal(err)
		}
		wire, err := readDNSFrame(client)
		m := unpackDNSMessage(wire)
		if err != nil || !dnsResponseMatches(q.MessageCopy(), m) || len(m.Answer) != 1 {
			t.Fatalf("client stream lost after probe cancellation: %v", err)
		}
	}
	if streams.Load() != 3 {
		t.Fatalf("expected shared client stream and two isolated probes, got %d", streams.Load())
	}
}
