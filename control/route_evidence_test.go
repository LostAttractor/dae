// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
)

// Without a trusted hostname, userspace has no evidence beyond the kernel's:
// it keeps a kernel decision and resolves a kernel handoff with the same DNS
// evidence. Only a trusted hostname changes the route.
func TestUntrustedHostnameRoutesWithKernelEvidence(t *testing.T) {
	unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	groups := []*outbound.DialerGroup{downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), downloadTestGroup(t, "proxy", unused)}
	matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "domain(suffix: one.example) -> proxy"))
	registry := newRoutingDomainRegistry()
	unique, shared := netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")
	now := time.Now()
	for _, pair := range []struct {
		name string
		ip   netip.Addr
	}{{"one.example.", unique}, {"one.example.", shared}, {"two.example.", shared}} {
		registry.Upsert(pair.name, pair.ip, matcher.domainMatcher.MatchDomainBitmap(pair.name), 60, now)
	}
	route := func(mode consts.RerouteMode, kernel routingResult, destination netip.Addr, host string) (string, error) {
		plane := &ControlPlane{outbounds: groups, routingMatcher: matcher, sniffVerifyMode: consts.SniffVerifyMode_Strict, rerouteMode: mode,
			core: &controlPlaneCore{domainRegistry: registry}}
		p := &RouteParam{Src: netip.MustParseAddrPort("192.0.2.1:12345"), Dest: netip.AddrPortFrom(destination, 22), Domain: host,
			networkType: *common.NetworkTCP4.NetworkType(), routingResult: &kernel}
		option, err := plane.RouteDialOption(t.Context(), p)
		if err != nil {
			return "", err
		}
		return option.Outbound.Name, nil
	}
	proxy := routingResult{}
	proxy.Outbound = 2
	handoff := routingResult{}
	handoff.Outbound = uint8(consts.OutboundControlPlaneRouting)
	captured := handoff
	captured.CaptureFlags = captureHTTP
	for _, mode := range []consts.RerouteMode{consts.RerouteMode_WhileNeed, consts.RerouteMode_Force} {
		for _, host := range []string{"", "unregistered.example"} {
			if got, err := route(mode, proxy, unique, host); err != nil || got != "proxy" {
				t.Fatalf("%s, sniffed %q: kernel decision from DNS evidence became %s, %v", mode, host, got, err)
			}
			if got, err := route(mode, handoff, unique, host); err != nil || got != "proxy" {
				t.Fatalf("%s, sniffed %q: handoff ignored DNS evidence: %s, %v", mode, host, got, err)
			}
			for _, kernel := range []routingResult{handoff, captured} {
				if got, err := route(mode, kernel, shared, host); err == nil {
					t.Fatalf("%s, sniffed %q: ambiguous evidence resolved to %s without a trusted hostname", mode, host, got)
				}
			}
		}
		for host, want := range map[string]string{"one.example": "proxy", "two.example": "direct"} {
			if got, err := route(mode, handoff, shared, host); err != nil || got != want {
				t.Fatalf("%s: trusted %s routed via %s, %v; want %s", mode, host, got, err, want)
			}
		}
	}
}

// Explanations mirror live routing for an untrusted hostname.
func TestDiagnosticsUntrustedHostnameKeepsKernelEvidence(t *testing.T) {
	unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	c := diagnosticPlane(t, "domain(suffix: one.example) -> proxy", "")
	c.outbounds = []*outbound.DialerGroup{downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), downloadTestGroup(t, "proxy", unused)}
	c.sniffVerifyMode = consts.SniffVerifyMode_Strict
	request := diagnosticRequest()
	request.Flow.SNI = new("unregistered.example")
	ip := netip.MustParseAddr(request.Flow.Destination.IP)
	c.core.domainRegistry.Upsert("one.example.", ip, c.routingMatcher.domainMatcher.MatchDomainBitmap("one.example."), 120, time.Now())
	for _, mode := range []consts.RerouteMode{consts.RerouteMode_WhileNeed, consts.RerouteMode_Force} {
		c.rerouteMode = mode
		response, err := c.Explain(t.Context(), request, false)
		if err != nil || !response.Current.Decision.Complete || response.Current.Decision.Outbound != "proxy" {
			t.Fatalf("%s: untrusted hostname changed the explained route: %+v, %v", mode, response.Current.Decision, err)
		}
	}
}
