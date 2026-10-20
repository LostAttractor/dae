// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/plugin"
	cache "github.com/daeuniverse/dae/plugins/dns-cache"
	router "github.com/daeuniverse/dae/plugins/dns-router"
	dns "github.com/miekg/dns"
)

type cachePolicyDNSRedirect struct{}

func (cachePolicyDNSRedirect) Plan() plugin.Plan { return plugin.Plan{DNS: []plugin.DNSScope{{}}} }
func (cachePolicyDNSRedirect) WrapDNS(next plugin.DNSHandler) plugin.DNSHandler {
	return func(ctx context.Context, r *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		r = r.Copy()
		r.Destination = netip.MustParseAddrPort("192.0.2.54:53")
		return next(ctx, r)
	}
}

func TestDNSRetainedTCPStreamDoesNotPoisonNewRoute(t *testing.T) {
	host, err := mitm.New(mitm.Options{DisableHTTP: true}, mitm.Instance{ID: "cache", Plugin: integrationDNSPlugin(t, cache.Plugin, "")}, mitm.Instance{ID: "redirect", Plugin: cachePolicyDNSRedirect{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	var directCalls, proxyCalls atomic.Int32
	dial := func(ip string, calls *atomic.Int32) func(context.Context, string, string) (net.Conn, error) {
		return func(context.Context, string, string) (net.Conn, error) {
			calls.Add(1)
			c, p := net.Pipe()
			go func() {
				defer p.Close()
				for {
					b, err := netutils.ReadDNSFrame(p)
					if err != nil {
						return
					}
					q := unpackDNSMessage(b)
					m := new(dns.Msg).SetReply(q)
					m.Answer = []dns.RR{testARecord(q.Question[0].Name, ip)}
					b, _ = m.Pack()
					if netutils.WriteDNSFrame(p, b) != nil {
						return
					}
				}
			}()
			return c, nil
		}
	}
	groups := []*outbound.DialerGroup{downloadTestGroup(t, "direct", dial("198.51.100.1", &directCalls)), downloadTestGroup(t, "block", dial("198.51.100.3", new(atomic.Int32))), downloadTestGroup(t, "proxy", dial("198.51.100.2", &proxyCalls))}
	matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "client(gaming) -> proxy"))
	plane := &ControlPlane{deviceRoutes: new(deviceRoutes), dnsRelay: newDNSRelay(), mitmHost: host, outbounds: groups, routingMatcher: matcher}
	t.Cleanup(func() { plane.dnsRelay.Close() })
	mac1, mac2 := [6]byte{2, 0, 0, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 2}
	client := func(source string, mac [6]byte) net.Conn {
		c, p := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer p.Close()
			_ = plane.serveDNSTCP(p, netip.MustParseAddrPort(source), netip.MustParseAddrPort("192.0.2.53:53"), routingResult{CaptureFlags: captureDNS, Mac: mac})
		}()
		t.Cleanup(func() { c.Close(); <-done })
		return c
	}
	ask := func(c net.Conn, name string) string {
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		q := dnsTestRequest(t, name, 1)
		if err := netutils.WriteDNSFrame(c, dnsTestWire(t, q)); err != nil {
			t.Fatal(err)
		}
		b, err := netutils.ReadDNSFrame(c)
		if err != nil {
			t.Fatal(err)
		}
		m := unpackDNSMessage(b)
		if len(m.Answer) != 1 {
			t.Fatalf("bad answer: %s", m)
		}
		return m.Answer[0].(*dns.A).A.String()
	}
	first := client("192.0.2.1:40001", mac1)
	if got := ask(first, "prime.example."); got != "198.51.100.1" {
		t.Fatal(got)
	}
	if err := matcher.SetClientMembers("gaming", [][6]byte{mac1, mac2}, false); err != nil {
		t.Fatal(err)
	}
	gotOld := ask(first, "shared.example.")
	second := client("192.0.2.2:40002", mac2)
	gotNew := ask(second, "shared.example.")
	t.Logf("retained=%s fresh=%s direct_dials=%d proxy_dials=%d", gotOld, gotNew, directCalls.Load(), proxyCalls.Load())
	if gotOld != "198.51.100.2" || gotNew != "198.51.100.2" || directCalls.Load() != 1 || proxyCalls.Load() != 1 {
		t.Fatalf("new proxy-routed client received old direct-route answer %s", gotNew)
	}
}

func TestDNSDiagnosticDoesNotDeclareDropForWarmCache(t *testing.T) {
	plane := diagnosticPlane(t, "dip(192.0.2.53) -> proxy", "")
	plane.core = nil
	plane.noConnectivityOutbound = consts.OutboundBlock
	plane.deviceRoutes = new(deviceRoutes)
	unused := func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("unexpected dial")
		return nil, net.ErrClosed
	}
	plane.outbounds = []*outbound.DialerGroup{downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), downloadTestGroup(t, "proxy", unused)}
	cachePlugin := integrationDNSPlugin(t, cache.Plugin, "").(*cache.Cache)
	host := integrationDNSHost(t, cachePlugin)
	plane.mitmHost = host
	query := dnsTestRequest(t, "cached.example.", 1)
	request, _, err := plane.dnsRequest(dnsTestWire(t, query), "udp", netip.MustParseAddrPort("192.0.2.10:40000"), netip.MustParseAddrPort("192.0.2.53:53"), routingResult{CaptureFlags: captureDNS, Outbound: 2})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	terminal := func(_ context.Context, r *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		calls++
		m := new(dns.Msg).SetReply(r.MessageCopy())
		m.Answer = []dns.RR{testARecord("cached.example.", "198.51.100.2")}
		return &plugin.DNSResponse{DNSPacket: plugin.DNSMessage(m)}, nil
	}
	for range 2 {
		if err := plane.processDNS(t.Context(), request, routingResult{}, false, terminal, func([]byte) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal("cache was not warm")
	}
	input := diagnosticRequest()
	input.Kind = "dns"
	input.Context.ProcessName = new("")
	input.Flow.Protocol = "udp"
	input.Flow.Destination = api.DiagnosticTarget{IP: "192.0.2.53", Port: 53}
	input.DNS = &api.DiagnosticDNS{Name: "cached.example.", Type: "A", DO: true, UDPSize: 1232}
	input.Compare = &api.DiagnosticAssumptions{Outbounds: map[string]bool{"proxy": false}}
	before := cachePlugin.Report()
	result, err := plane.Explain(t.Context(), input, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("live_cache_calls=%d current=%+v proxy_offline=%+v", calls, result.Current.Decision, result.Compared.Decision)
	if !result.Compared.Decision.Complete || result.Compared.Decision.Verdict != "userspace" || len(result.Compared.Decision.Targets) != 0 {
		t.Fatalf("warm cache was not diagnosed before node availability: %+v", result.Compared)
	}
	input.DNS.DO = false
	result, err = plane.Explain(t.Context(), input, false)
	if err != nil || !result.Compared.Decision.Complete || result.Compared.Decision.Verdict != "drop" {
		t.Fatalf("different query flags reused the warm answer: %+v, %v", result, err)
	}
	input.Context.SourcePort = nil
	result, err = plane.Explain(t.Context(), input, false)
	if err != nil || result.Compared.Decision.Complete {
		t.Fatalf("unknown routing identity became a definite cache miss: %+v, %v", result, err)
	}
	input.Kind, input.DNS, input.Context.SourcePort = "flow", nil, new(40000)
	result, err = plane.Explain(t.Context(), input, false)
	if err != nil || result.Compared.Decision.Complete {
		t.Fatalf("missing DNS question became a definite cache miss: %+v, %v", result, err)
	}
	if !reflect.DeepEqual(before, cachePlugin.Report()) || calls != 1 {
		t.Fatal("diagnostics changed live cache counters or performed transport I/O")
	}
}

func TestDNSDiagnosticChecksCacheAfterRouterSelection(t *testing.T) {
	for _, cacheFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "cache first", false: "cache last"}[cacheFirst], func(t *testing.T) {
			plane := diagnosticPlane(t, "dip(192.0.2.54) -> proxy", "")
			plane.core, plane.deviceRoutes, plane.noConnectivityOutbound = nil, new(deviceRoutes), consts.OutboundBlock
			cached := integrationDNSPlugin(t, cache.Plugin, "")
			resolver := integrationDNSPlugin(t, router.Plugin, "upstream { test:'udp://192.0.2.54' } routing { request { fallback:test } }")
			instances := []mitm.Instance{{ID: "cache", Plugin: cached}, {ID: "router", Plugin: resolver}}
			if !cacheFirst {
				instances[0], instances[1] = instances[1], instances[0]
			}
			host, err := mitm.New(mitm.Options{DisableHTTP: true}, instances...)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = host.Close() })
			plane.mitmHost = host
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
					query := unpackDNSMessage(wire[:n])
					message := new(dns.Msg).SetReply(query)
					message.Answer = []dns.RR{testARecord(query.Question[0].Name, "198.51.100.2")}
					wire, _ = message.Pack()
					_, _ = peer.Write(wire)
				}()
				return conn, nil
			}
			plane.outbounds = []*outbound.DialerGroup{downloadTestGroup(t, "direct", dial), downloadTestGroup(t, "block", dial), downloadTestGroup(t, "proxy", dial)}
			query := dnsTestRequest(t, "cached.example.", 1)
			request, _, err := plane.dnsRequest(dnsTestWire(t, query), "udp", netip.MustParseAddrPort("192.0.2.10:40000"), netip.MustParseAddrPort("192.0.2.53:53"), routingResult{CaptureFlags: captureDNS})
			if err != nil {
				t.Fatal(err)
			}
			input := diagnosticRequest()
			input.Kind, input.Flow.Protocol = "dns", "udp"
			input.Context.ProcessName = new("")
			input.Flow.Destination = api.DiagnosticTarget{IP: "192.0.2.53", Port: 53}
			input.DNS = &api.DiagnosticDNS{Name: "cached.example.", Type: "A", DO: true, UDPSize: 1232}
			input.Compare = &api.DiagnosticAssumptions{Outbounds: map[string]bool{"proxy": false}}
			cold, err := plane.Explain(t.Context(), input, false)
			if err != nil || !cold.Compared.Decision.Complete || cold.Compared.Decision.Verdict != "drop" {
				t.Fatalf("cold route: %+v, %v", cold, err)
			}
			if err := plane.processDNS(t.Context(), request, routingResult{}, false, relayDNSUDP, func([]byte) error { return nil }); err != nil {
				t.Fatal(err)
			}
			warm, err := plane.Explain(t.Context(), input, false)
			if err != nil || !warm.Compared.Decision.Complete || warm.Compared.Decision.Verdict != "userspace" || len(warm.Compared.Decision.Targets) != 0 {
				t.Fatalf("warm selected upstream: %+v, %v", warm, err)
			}
			if dials.Load() != 1 {
				t.Fatalf("diagnostics dialed: %d", dials.Load())
			}
		})
	}
}
