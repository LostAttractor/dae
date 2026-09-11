// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
)

func TestDestinationRoutingPreservesIdentityAndUsesNewContext(t *testing.T) {
	for _, proto := range []consts.L4ProtoStr{consts.L4ProtoStr_TCP, consts.L4ProtoStr_UDP} {
		t.Run(string(proto), func(t *testing.T) {
			prepared := prepareFlowRulesForTest(t, `
dip(192.0.2.20) -> dnat('[2001:db8::20]:1053')
dip('2001:db8::20') -> dnat(203.0.113.30)
ipversion(6) && dip('2001:db8::20') -> must`, `
domain(full: original.example) && ipversion(6) && dip('2001:db8::20') && sip(192.0.2.10) && sport(5000) && dport(1053) && dscp(46) && pname(app) -> proxy(mark:91)
dip(192.0.2.20) -> block`)
			matcher, _ := routingMatcherForTest(t, prepared)
			// A separate selected profile must survive destination reevaluation.
			matcher.profiles[42] = matcher.profiles[matcher.defaultProfileID]
			matcher.defaultProfileID = 99
			unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("routing selection must not dial")
				return nil, net.ErrClosed
			})
			plane := &ControlPlane{routingMatcher: matcher, outbounds: []*outbound.DialerGroup{
				downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), downloadTestGroup(t, "proxy", unused),
			}, core: &controlPlaneCore{domainRegistry: newDomainRegistry(32, 32, time.Second)}, sniffVerifyMode: consts.SniffVerifyMode_None}
			result := bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting), CaptureFlags: captureDestination, ProfileId: 42, Ifindex: 7, Dscp: 46, Mac: [6]byte{2, 0, 0, 0, 0, 1}}
			copy(result.Pname[:], "app")
			original := netip.MustParseAddrPort("192.0.2.20:443")
			param := &RouteParam{Dest: original, Src: netip.MustParseAddrPort("192.0.2.10:5000"), Domain: "original.example", routingResult: &result,
				networkType: common.NetworkType{L4Proto: proto, IpVersion: consts.IpVersionStr_4}}
			option, err := plane.RouteDialOption(context.Background(), param)
			if err != nil {
				t.Fatal(err)
			}
			if option.Outbound.Name != "proxy" || option.DialTarget != "[2001:db8::20]:1053" || option.NetworkType.IpVersion != consts.IpVersionStr_6 || result.Mark != 91 || result.Must != 1 {
				t.Fatalf("effective context lost: option=%+v result=%+v", option, result)
			}
			if param.Dest != original || result.ProfileId != 42 || result.Ifindex != 7 || result.Mac[5] != 1 {
				t.Fatal("destination rewrite changed ingress identity")
			}
		})
	}
}

func TestPluginDestinationRoutingUsesRewrittenTarget(t *testing.T) {
	for _, test := range []struct {
		name, domain, candidate, original string
		proto                             consts.L4ProtoStr
		override, unverified              bool
	}{
		{name: "IP dialing", proto: consts.L4ProtoStr_TCP, candidate: "proxy", original: "block"},
		{name: "override disabled with SNI", proto: consts.L4ProtoStr_TCP, domain: "original.example", candidate: "proxy", original: "block"},
		{name: "override enabled without SNI", proto: consts.L4ProtoStr_TCP, override: true, candidate: "proxy", original: "block"},
		{name: "unverified SNI", proto: consts.L4ProtoStr_TCP, domain: "original.example", override: true, unverified: true, candidate: "proxy", original: "block"},
		{name: "hostname dialing keeps rewritten context", proto: consts.L4ProtoStr_TCP, domain: "original.example", override: true, candidate: "proxy", original: "proxy"},
		{name: "original direct route does not undo destination", proto: consts.L4ProtoStr_TCP, domain: "original.example", override: true, candidate: "proxy", original: "direct"},
		{name: "direct candidate", proto: consts.L4ProtoStr_TCP, domain: "original.example", override: true, candidate: "direct", original: "block"},
		{name: "blocked candidate", proto: consts.L4ProtoStr_TCP, domain: "original.example", override: true, candidate: "block", original: "direct"},
		{name: "blocked candidate with override disabled", proto: consts.L4ProtoStr_TCP, candidate: "block", original: "direct"},
		{name: "UDP with override disabled", proto: consts.L4ProtoStr_UDP, domain: "original.example", candidate: "proxy", original: "block"},
		{name: "UDP with override enabled", proto: consts.L4ProtoStr_UDP, domain: "original.example", override: true, candidate: "proxy", original: "block"},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared := prepareFlowRulesForTest(t, "ipversion(6) -> must", fmt.Sprintf("dip('2001:db8::20') -> %s(mark:91)\ndip(192.0.2.20) -> %s(mark:19)\ndip(203.0.113.0/24) -> block", test.candidate, test.original))
			prepared.destinations = prepareFlowRulesForTest(t, `dip(192.0.2.20) -> dnat('2001:db8::20')
dip(192.0.2.20) -> dnat(203.0.113.30)
dip('2001:db8::20') -> dnat(203.0.113.40)`, "").destinations
			matcher, _ := routingMatcherForTest(t, prepared)
			unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("route selection must not dial")
				return nil, net.ErrClosed
			})
			plane := &ControlPlane{routingMatcher: matcher, dialTargetOverride: test.override, sniffVerifyMode: consts.SniffVerifyMode_None,
				core: &controlPlaneCore{domainRegistry: newDomainRegistry(32, 32, time.Second)}, outbounds: []*outbound.DialerGroup{
					downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), downloadTestGroup(t, "proxy", unused),
				}}
			if test.unverified {
				plane.sniffVerifyMode = consts.SniffVerifyMode_Strict
			}
			original := netip.MustParseAddrPort("192.0.2.20:53")
			p := &RouteParam{Src: netip.MustParseAddrPort("192.0.2.10:5000"), Dest: original, Domain: test.domain, networkType: common.NetworkType{L4Proto: test.proto, IpVersion: consts.IpVersionStr_4},
				routingResult: &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting), CaptureFlags: captureDestination}}
			option, err := plane.RouteDialOption(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			wantTarget := "[2001:db8::20]:53"
			if option.Outbound.Name != test.candidate || option.Mark != 91 || p.routingResult.Must != 1 || !p.destination.IsValid() || p.Dest != original {
				t.Fatalf("destination rewrite lost rewritten context: option=%+v result=%+v", option, p.routingResult)
			}
			if test.candidate != "block" && option.DialTarget != wantTarget {
				t.Fatalf("dial target=%s, want %s", option.DialTarget, wantTarget)
			}
			if test.candidate != "block" && option.NetworkType.IpVersion != consts.IpVersionStr_6 {
				t.Fatal("destination rewrite lost rewritten IP family")
			}
		})
	}
}

func TestPluginDestinationHTTPPlansKeepRewrittenTarget(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, override := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/override=%t", network, override), func(t *testing.T) {
				prepared := prepareFlowRulesForTest(t, "", "dip(198.51.100.20) -> proxy(mark:91)\ndip(192.0.2.20) -> proxy(mark:19)")
				prepared.destinations = prepareFlowRulesForTest(t, "dip(192.0.2.20) -> dnat(198.51.100.20)", "").destinations
				matcher, _ := routingMatcherForTest(t, prepared)
				unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) {
					t.Fatal("planning must not dial")
					return nil, net.ErrClosed
				})
				plane := &ControlPlane{routingMatcher: matcher, dialTargetOverride: override, outbounds: []*outbound.DialerGroup{
					downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), downloadTestGroup(t, "proxy", unused),
				}}
				original := netip.MustParseAddrPort("192.0.2.20:443")
				identity := bpfRoutingResult{Mark: 37, Must: 1}
				option, err := plane.selectHTTPAddress(network, netip.MustParseAddrPort("192.0.2.10:5000"), identity, "original.example", original)
				if err != nil {
					t.Fatal(err)
				}
				if option.DialTarget != "198.51.100.20:443" || option.Mark != 91 || identity.Mark != 37 || identity.Must != 1 {
					t.Fatalf("HTTP plan lost effective target: %+v", option)
				}
				request, err := http.NewRequestWithContext(t.Context(), "GET", "https://original.example/", nil)
				if err != nil {
					t.Fatal(err)
				}
				plan, err := plane.mitmUpstreamPlanner(network, "original.example", netip.MustParseAddrPort("192.0.2.10:5000"), original, identity, nil)(request)
				if err != nil || plan.Key == "" || (network == "udp" && plan.DialPacket == nil) || (network == "tcp" && plan.Dial == nil) {
					t.Fatalf("invalid HTTP upstream plan: %+v, %v", plan, err)
				}
			})
		}
	}
}

func TestDestinationCandidateMissStillRoutesOriginalTarget(t *testing.T) {
	prepared := prepareFlowRulesForTest(t, "domain(full: candidate.example) -> dnat(198.51.100.1)", "dip(192.0.2.1) -> block(mark:19)")
	matcher, _ := routingMatcherForTest(t, prepared)
	unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	plane := &ControlPlane{routingMatcher: matcher, outbounds: []*outbound.DialerGroup{downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused)}}
	p := &RouteParam{Src: netip.MustParseAddrPort("192.0.2.10:5000"), Dest: netip.MustParseAddrPort("192.0.2.1:443"), networkType: *common.NetworkTCP4.NetworkType(),
		routingResult: &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting), CaptureFlags: captureDestination}}
	option, err := plane.RouteDialOption(context.Background(), p)
	if err != nil || option.Outbound.Name != "block" || p.routingResult.Mark != 19 || p.destination.IsValid() {
		t.Fatalf("candidate miss bypassed routing: option=%+v err=%v", option, err)
	}
}

func TestRewrittenTargetDoesNotReenterAPIBypass(t *testing.T) {
	prepared := prepareFlowRulesForTest(t, "dip(192.0.2.20) -> dnat(10.0.0.1)", "dip(10.0.0.1) -> block(mark:73)")
	prepared.bypassAPI(8081, []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}})
	matcher, _ := routingMatcherForTest(t, prepared)
	unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("blocked target must not dial")
		return nil, net.ErrClosed
	})
	plane := &ControlPlane{routingMatcher: matcher, outbounds: []*outbound.DialerGroup{
		downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused),
	}}
	source, destination := netip.MustParseAddrPort("192.0.2.10:5000"), netip.MustParseAddrPort("192.0.2.20:8081")
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			param := &RouteParam{Src: source, Dest: destination, routingResult: &bpfRoutingResult{CaptureFlags: captureDestination},
				networkType: common.NetworkType{L4Proto: consts.L4ProtoStr(network), IpVersion: consts.IpVersionStr_4}}
			option, err := plane.RouteDialOption(t.Context(), param)
			if err != nil || option.Outbound.Name != "block" || option.Mark != 73 {
				t.Fatalf("DNAT target reused API ingress bypass: %+v, %v", option, err)
			}
			option, err = plane.selectHTTPAddress(network, source, bpfRoutingResult{}, "", netip.MustParseAddrPort("10.0.0.1:8081"))
			if err != nil || option.Outbound.Name != "block" || option.Mark != 73 {
				t.Fatalf("HTTP target reused API ingress bypass: %+v, %v", option, err)
			}
		})
	}
}

func TestHTTPDestinationPredicatesUseRequestedProtocol(t *testing.T) {
	prepared := prepareFlowRulesForTest(t, `
l4proto(tcp) && dip(192.0.2.20) -> dnat(198.51.100.1)
l4proto(udp) && dip(192.0.2.20) -> dnat(198.51.100.2)`, "dip(192.0.2.20) -> block")
	matcher, _ := routingMatcherForTest(t, prepared)
	unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	plane := &ControlPlane{routingMatcher: matcher, outbounds: []*outbound.DialerGroup{downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused)}}
	for _, test := range []struct {
		network string
		ingress consts.L4ProtoType
		target  string
	}{
		{"tcp", consts.L4ProtoType_UDP, "198.51.100.1:443"},
		{"udp", consts.L4ProtoType_TCP, "198.51.100.2:443"},
	} {
		identity := bpfRoutingResult{Protocol: uint8(test.ingress)}
		option, err := plane.selectHTTPAddress(test.network, netip.MustParseAddrPort("192.0.2.10:5000"), identity, "example.com", netip.MustParseAddrPort("192.0.2.20:443"))
		if err != nil || option.DialTarget != test.target || identity.Protocol != uint8(test.ingress) {
			t.Fatalf("%s destination predicate used ingress protocol: %+v, %v", test.network, option, err)
		}
	}
}
