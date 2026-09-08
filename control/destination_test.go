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
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/outbound/netproxy"
)

func TestDestinationRewriteRoutesEffectiveAddress(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.10:12345")
	dst := netip.MustParseAddrPort("91.108.56.100:443")
	unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	groups := []*outbound.DialerGroup{
		downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), downloadTestGroup(t, "proxy", unused),
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
			prepared := preparedRules{routing: testRoutingConfig([]*config_parser.RoutingRule{{
				AndFunctions: []*config_parser.Function{{Name: "dip", Params: []*config_parser.Param{{Val: test.target}}}},
				Outbound:     config_parser.Function{Name: test.route, Params: []*config_parser.Param{{Val: "must"}, {Key: "mark", Val: "37"}}},
			}, {
				AndFunctions: []*config_parser.Function{{Name: "dip", Params: []*config_parser.Param{{Val: dst.Addr().String()}}}},
				Outbound:     config_parser.Function{Name: "block"},
			}}, "direct")}
			prepared.destinations = rules
			matcher, _ := routingMatcherForTest(t, prepared)
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
	unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	global := &dialer.GlobalOption{}
	unavailable := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: unused}), global, &dialer.Property{Name: "unavailable"}, true, "")
	group := outbound.NewDialerGroup(global, "proxy", outbound.GroupKindSelector, []*dialer.Dialer{unavailable}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, nil)
	t.Cleanup(func() { group.Close() })
	dst := netip.MustParseAddrPort("192.0.2.1:443")
	matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "dip(192.0.2.1) -> dnat('2001:db8::1')", "ipversion(6) -> proxy"))
	plane := &ControlPlane{routingMatcher: matcher, outbounds: []*outbound.DialerGroup{downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), group}}

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
	matcher, _ := routingMatcherForTest(t, prepared)
	unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	plane := &ControlPlane{routingMatcher: matcher, outbounds: []*outbound.DialerGroup{
		downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), downloadTestGroup(t, "proxy", unused),
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
		if ((builder.rules[i].Flags >> 3) & 3) != 0 {
			builder.rules[i].Outbound = uint8(consts.OutboundUserDefinedMin)
			builder.rules[i].Flags &^= 3 << 3 // Expose the capture predicate as a test terminal.
			builder.rules[i].Action = uint8(consts.MatchActionRoute)
		}
	}
	for _, address := range []string{"91.108.56.100", "91.108.56.101", "2001:db8::100", "2001:db8::101"} {
		for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
			ip := netip.MustParseAddr(address)
			got, _, _, err := matcher.match(routingInput{
				src:     netip.AddrPortFrom(ip, 1234),
				dst:     netip.AddrPortFrom(ip, 443),
				l4proto: proto,
			})
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

type destinationTestDialer struct{ netproxy.Dialer }

func (destinationTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return net.ListenPacket("udp4", "127.0.0.1:0")
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
	target := addrPortOf(server.LocalAddr())
	destinations := []netip.AddrPort{
		netip.AddrPortFrom(netip.MustParseAddr("91.108.56.100"), target.Port()),
		netip.AddrPortFrom(netip.MustParseAddr("91.108.56.101"), target.Port()),
	}
	type reply struct {
		data string
		from netip.AddrPort
	}
	replies := make(chan reply, 2)
	policy := netproxy.NewLease(netproxy.NewResourceRef())
	endpoint := &UdpEndpoint{
		NatTimeout: time.Hour, packetDialer: destinationTestDialer{},
		routeLease: policy, sockets: make(map[netip.AddrPort]net.PacketConn),
		traffic: stats.DefaultStore.OpenConnection(stats.Path{Outbound: t.Name()}, false),
		handler: func(data []byte, from netip.AddrPort) error { replies <- reply{string(data), from}; return nil },
	}
	matcher, _ := destinationTestMatcher(t, "dip(91.108.56.100, 91.108.56.101) -> dnat("+target.Addr().String()+")")
	endpoint.destinationMatcher = matcher.snapshotDestinations()
	endpoint.destinationParam = RouteParam{Src: source, routingResult: &bpfRoutingResult{}, networkType: *common.NetworkUDP4.NetworkType()}
	endpoint.destinations = make(map[netip.AddrPort]netip.AddrPort)

	pool.add(source, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	buf := make([]byte, 128)
	var previousPeer string
	for _, original := range destinations {
		lock, _ := pool.UdpEndpointKeyLocker.Lock(source)
		conn, err := endpoint.socket(ctx, &pool, source, original)
		if err == nil {
			_, err = writePacket(ctx, conn, []byte(original.String()), net.UDPAddrFromAddrPort(original))
		}
		pool.UdpEndpointKeyLocker.Unlock(source, lock)
		if err != nil {
			t.Fatal(err)
		}
		n, from, err := server.ReadFrom(buf)
		if err != nil || string(buf[:n]) != original.String() {
			t.Fatalf("wrong rewritten request: %q, %v", buf[:n], err)
		}
		if from.String() == previousPeer {
			t.Fatal("rewrites to the same server shared a socket")
		}
		previousPeer = from.String()
		if _, err := server.WriteTo(buf[:n], from); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-replies:
			if got.from != original || got.data != original.String() {
				t.Fatalf("reply lost original source: %+v", got)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if current, ok := pool.Get(source); !ok || current != endpoint {
		t.Fatal("destination rewrite replaced the source lifetime")
	}
	policy.Abort(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Origin: netproxy.OriginLocalCleanup}))
	deadline := time.After(5 * time.Second)
	for !endpoint.IsClosed() {
		select {
		case <-deadline:
			t.Fatal("policy did not release the source lifetime")
		case <-time.After(time.Millisecond):
		}
	}
}
