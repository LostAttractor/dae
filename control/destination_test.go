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
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/outbound/netproxy"
)

func TestDestinationRewriteRoutesEffectiveAddress(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.10:12345")
	dst := netip.MustParseAddrPort("91.108.56.100:443")
	unused := surgeDownloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	groups := []*outbound.DialerGroup{
		surgeDownloadTestGroup(t, "direct", unused), surgeDownloadTestGroup(t, "block", unused), surgeDownloadTestGroup(t, "proxy", unused),
	}
	for _, test := range []struct {
		route, target string
		proto         consts.L4ProtoStr
	}{
		{"direct", "91.108.56.147", consts.L4ProtoStr_TCP},
		{"proxy", "91.108.56.147", consts.L4ProtoStr_TCP},
		{"block", "2001:db8::147", consts.L4ProtoStr_TCP},
		{"direct", "2001:db8::147", consts.L4ProtoStr_TCP},
		{"proxy", "2001:db8::147", consts.L4ProtoStr_UDP},
	} {
		t.Run(test.route+"/"+test.target+"/"+string(test.proto), func(t *testing.T) {
			rules := routing.DestinationRewrites{{Filter: []*config_parser.Function{{Name: "dip", Params: []*config_parser.Param{{Val: dst.Addr().String()}}}}, To: []netip.Addr{netip.MustParseAddr(test.target)}}}
			prepared := preparedRules{routing: []*config_parser.RoutingRule{{
				AndFunctions: []*config_parser.Function{{Name: "dip", Params: []*config_parser.Param{{Val: test.target}}}},
				Outbound:     config_parser.Function{Name: test.route, Params: []*config_parser.Param{{Val: "must"}, {Key: "mark", Val: "37"}}},
			}, {
				AndFunctions: []*config_parser.Function{{Name: "dip", Params: []*config_parser.Param{{Val: dst.Addr().String()}}}},
				Outbound:     config_parser.Function{Name: "block"},
			}}}
			prepared.destinations = rules
			matcher, _ := surgeRoutingMatcher(t, prepared)
			plane := &ControlPlane{routingMatcher: matcher, outbounds: groups}
			plane.markedDirectDialers.Store(uint32(37), unused)
			param := &RouteParam{
				Src: src, Dest: dst,
				networkType:   common.NetworkType{L4Proto: test.proto, IpVersion: consts.IpVersionStr_4},
				routingResult: &bpfRoutingResult{Outbound: map[string]uint8{"direct": 0, "block": 1, "proxy": 2}[test.route], Mark: 37, Must: 1, CaptureFlags: captureDestination},
			}
			option, err := plane.RouteDialOption(context.Background(), param)
			if err != nil {
				t.Fatal(err)
			}
			want := netip.AddrPortFrom(netip.MustParseAddr(test.target), dst.Port())
			if option.Outbound.Name != test.route || option.DialTarget != want.String() || option.NetworkType.IpVersion != consts.IpVersionStrFromAddr(want.Addr()) || param.routingResult.Mark != 37 || param.routingResult.Must != 1 {
				t.Fatalf("rewrite did not route the new target: %+v, %+v", option, param.routingResult)
			}
		})
	}
}

func TestDestinationRewriteUsesFallbackPolicy(t *testing.T) {
	unused := surgeDownloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	global := &dialer.GlobalOption{}
	unavailable := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: unused}), global, &dialer.Property{Name: "unavailable"}, true, "")
	group := outbound.NewDialerGroup(global, "proxy", outbound.GroupKindSelector, []*dialer.Dialer{unavailable}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, nil)
	t.Cleanup(func() { group.Close() })
	dst := netip.MustParseAddrPort("192.0.2.1:443")
	matcher, _ := surgeRoutingMatcher(t, prepareFlowRulesForTest(t, "dip(192.0.2.1) -> dnat('2001:db8::1')", "ipversion(6) -> proxy"))
	plane := &ControlPlane{routingMatcher: matcher, outbounds: []*outbound.DialerGroup{surgeDownloadTestGroup(t, "direct", unused), surgeDownloadTestGroup(t, "block", unused), group}}

	for _, fallback := range []consts.OutboundIndex{consts.OutboundDirect, consts.OutboundBlock} {
		plane.noConnectivityOutbound = fallback
		option, err := plane.RouteDialOption(context.Background(), &RouteParam{Src: netip.MustParseAddrPort("192.0.2.5:12345"), Dest: dst, routingResult: &bpfRoutingResult{Outbound: uint8(consts.OutboundUserDefinedMin)}, networkType: *common.NetworkTCP4.NetworkType()})
		if err != nil {
			t.Fatal(err)
		}
		want := netip.MustParseAddrPort("[2001:db8::1]:443")
		if option.DialTarget != want.String() || option.NetworkType.IpVersion != consts.IpVersionStrFromAddr(want.Addr()) || option.OriginalOutbound != group || option.Outbound != plane.outbounds[fallback] {
			t.Fatalf("rewrite did not follow final fallback: %+v", option)
		}
	}
}

func TestDestinationDecisionPrecedesUserspaceRouting(t *testing.T) {
	prepared := prepareFlowRulesForTest(t, `
dip(192.0.2.1) -> bump
dip('2001:db8::/32') -> must
dip(192.0.2.1) -> dnat('2001:db8::1')`, `
dip('2001:db8::/32') -> proxy(skip_while_noalive, mark:37)
dip(192.0.2.1) -> block`)
	matcher, _ := surgeRoutingMatcher(t, prepared)
	unused := surgeDownloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	plane := &ControlPlane{routingMatcher: matcher, outbounds: []*outbound.DialerGroup{
		surgeDownloadTestGroup(t, "direct", unused), surgeDownloadTestGroup(t, "block", unused), surgeDownloadTestGroup(t, "proxy", unused),
	}}
	for _, retained := range []bool{false, true} {
		src, dst := netip.MustParseAddrPort("192.0.2.10:12345"), netip.MustParseAddrPort("192.0.2.1:443")
		want := netip.MustParseAddrPort("[2001:db8::1]:443")
		p := &RouteParam{Src: src, Dest: dst, routingResult: &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting)}, networkType: *common.NetworkTCP4.NetworkType()}
		if retained {
			want = netip.MustParseAddrPort("[2001:db8::2]:443")
			p.destination = want
		}
		routed := false
		matcher.outboundUsable = func(outbound uint8, proto consts.L4ProtoType, version consts.IpVersionType) bool {
			routed = true
			if p.destination != want {
				t.Fatalf("retained=%v: routing ran before destination selection: %+v", retained, p.destination)
			}
			if outbound != uint8(consts.OutboundUserDefinedMin) || proto != consts.L4ProtoType_TCP || version != consts.IpVersion_6 || p.Src != src || p.Dest != dst {
				t.Fatal("routing must use the effective IP family and retain ingress identity")
			}
			return true
		}
		option, err := plane.RouteDialOption(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		if !routed || option.Outbound.Name != "proxy" || option.DialTarget != want.String() || option.NetworkType.IpVersion != consts.IpVersionStr_6 || p.routingResult.Mark != 37 {
			t.Fatalf("retained=%v: destination or route lost: %+v, %+v", retained, option, p.routingResult)
		}
	}
}

func TestDestinationCaptureMatchesOnlyConfiguredIPs(t *testing.T) {
	matcher, builder := destinationTestMatcher(t, "dip(91.108.56.100, '2001:db8::100') -> dnat(198.51.100.1)")
	// Expose the capture predicate's decision without userspace's marker skip.
	for i := range builder.rules {
		if builder.rules[i].CaptureFlags != 0 {
			builder.rules[i].Outbound = uint8(consts.OutboundUserDefinedMin)
			builder.rules[i].CaptureFlags = 0 // Expose the capture predicate as a test terminal.
			builder.rules[i].Action = uint8(consts.MatchActionRoute)
		}
	}
	for _, address := range []string{"91.108.56.100", "91.108.56.101", "2001:db8::100", "2001:db8::101"} {
		for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
			ip := netip.MustParseAddr(address)
			bytes := ip.As16()
			got, _, _, err := matcher.Match(bytes[:], bytes[:], 1234, 443, consts.IpVersionFromAddr(ip), proto, "", [16]uint8{}, 0, 0, make([]byte, 16))
			want := consts.OutboundDirect
			if address == "91.108.56.100" || address == "2001:db8::100" {
				want = consts.OutboundUserDefinedMin
			}
			if err != nil || got != want {
				t.Fatalf("capture %s/%v: %v, %v", address, proto, got, err)
			}
		}
	}
}

func TestDestinationUDPReplyIsolation(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	server.SetDeadline(time.Now().Add(5 * time.Second))
	var pool UdpEndpointPool
	t.Cleanup(pool.closeAll)
	source := netip.MustParseAddrPort("192.0.2.1:12345")
	destinations := []string{"91.108.56.100:443", "91.108.56.101:443"}
	for _, original := range destinations {
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		conn := &destinationPacketConn{PacketConn: socket, original: netip.MustParseAddrPort(original), target: addrPortOf(server.LocalAddr())}
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		pool.add(udpEndpointKey{Source: source, Destination: conn.original}, newUdpEndpoint(&UdpEndpointOptions{PacketConn: conn, NatTimeout: time.Hour}))
	}
	buf := make([]byte, 128)
	for _, original := range destinations {
		key := udpEndpointKey{Source: source, Destination: netip.MustParseAddrPort(original)}
		endpoint, ok := pool.Get(key)
		if !ok {
			t.Fatal("another destination replaced this UDP association")
		}
		if _, err := endpoint.conn.WriteTo([]byte(original), net.UDPAddrFromAddrPort(key.Destination)); err != nil {
			t.Fatal(err)
		}
		n, from, err := server.ReadFrom(buf)
		if err != nil || string(buf[:n]) != original {
			t.Fatalf("wrong rewritten request: %q, %v", buf[:n], err)
		}
		if _, err := server.WriteTo(buf[:n], from); err != nil {
			t.Fatal(err)
		}
		n, from, err = endpoint.conn.ReadFrom(buf)
		if err != nil || from.String() != original || string(buf[:n]) != original {
			t.Fatalf("reply lost original source: %v, %q, %v", from, buf[:n], err)
		}
	}
}
