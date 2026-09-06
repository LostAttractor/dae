package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/mitmca"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/surgemodule"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/outbound/netproxy"
)

// Routing tests only inspect the engine's allowlist; no CA operations or JS run.
func surgeRoutingEngine(t *testing.T, hostnames ...string) *surgemodule.Engine {
	t.Helper()
	engine, err := surgemodule.NewEngine(surgemodule.EngineOptions{
		Modules:   []*surgemodule.Module{{Hostnames: hostnames}},
		Authority: &mitmca.Authority{}, Runtime: &surgemodule.Runtime{},
		MaxBodySize: 1 << 20, MaxConcurrentScripts: 1, ScriptTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestSurgeKernelRoutingReconstruction(t *testing.T) {
	for _, test := range []struct {
		name, rules       string
		want              consts.OutboundIndex
		must, unavailable bool
	}{
		{"uncertain domain", "domain(full: one.example) -> block", consts.OutboundControlPlaneRouting, false, false},
		{"uncertain negation", "!domain(full: one.example) -> block", consts.OutboundControlPlaneRouting, false, false},
		{"later AND misses", "domain(full: one.example) && dport(80) -> block", consts.OutboundDirect, false, false},
		{"earlier block wins", "dport(443) -> block\ndomain(full: one.example) -> proxy", consts.OutboundBlock, false, false},
		{"definite OR overrides uncertainty", "domain(full: one.example, suffix: example) -> proxy", consts.OutboundUserDefinedMin, false, false},
		{"negated definite OR", "!domain(full: one.example, suffix: example) -> block", consts.OutboundDirect, false, false},
		{"unavailable rule drops uncertainty", "domain(full: one.example) -> proxy(skip_while_noalive)\ndport(443) -> block", consts.OutboundBlock, false, true},
		{"uncertain must does not commit", "domain(full: one.example) -> must_rules", consts.OutboundControlPlaneRouting, false, false},
		{"earlier definite must survives", "dport(443) -> must_rules\ndomain(full: one.example) -> block(mark:37,must)", consts.OutboundControlPlaneRouting, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			sections, err := config_parser.Parse("global {}\nrouting {\n" + test.rules + "\nfallback: direct\n}")
			if err != nil {
				t.Fatal(err)
			}
			configuration, err := config.New(sections)
			if err != nil {
				t.Fatal(err)
			}
			preparation := &ControlPlanePreparation{rules: preparedRules{routing: configuration.Routing.Rules}}
			// Only one of the IP's hostnames belongs to the module: uncertainty
			// in the injected capture rule itself must be skipped in simulation.
			preparation.rules.enableSurgeRouting(surgeRoutingEngine(t, "one.example"))
			matcher, _ := surgeRoutingMatcher(t, preparation.rules)
			matcher.outboundUsable = func(uint8, consts.L4ProtoType, consts.IpVersionType) bool { return !test.unavailable }
			first := matcher.domainMatcher.MatchDomainBitmap("one.example")
			second := matcher.domainMatcher.MatchDomainBitmap("two.example")
			bump, routing := make([]uint32, len(first)), make([]uint32, len(first))
			for i := range first {
				bump[i] = first[i] | second[i]
				routing[i] = first[i] & second[i]
			}
			address := make([]byte, 16)
			got, mark, must, err := matcher.Match(address, address, 12345, 443, consts.IpVersion_4, consts.L4ProtoType_TCP, "", [16]uint8{}, 0, 0, address, routing, bump)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want || must != test.must || mark != 0 {
				t.Fatalf("reconstructed (%v,%d,%v), want (%v,0,%v)", got, mark, must, test.want, test.must)
			}
		})
	}
}

func surgeRoutingMatcher(t *testing.T, rules preparedRules) (*RoutingMatcher, *RoutingMatcherBuilder) {
	t.Helper()
	builder, err := NewRoutingMatcherBuilder(rules.routing, map[string]uint8{
		"direct": uint8(consts.OutboundDirect), "block": uint8(consts.OutboundBlock),
		"proxy": uint8(consts.OutboundUserDefinedMin),
	}, nil, "direct", nil, rules.capture)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	return matcher, builder
}

func surgeMatchRoute(t *testing.T, matcher *RoutingMatcher, host string, proto consts.L4ProtoType) (consts.OutboundIndex, uint32, bool) {
	t.Helper()
	address := make([]byte, 16)
	result, mark, must, err := matcher.Match(address, address, 12345, 443, consts.IpVersion_4, proto, host, [16]uint8{}, 0, 0, address)
	if err != nil {
		t.Fatal(err)
	}
	return result, mark, must
}

func TestSurgeCapturePreservesUserspaceRoute(t *testing.T) {
	engine := surgeRoutingEngine(t, "*.example")
	for _, test := range []struct {
		name     string
		outbound config_parser.Function
		want     consts.OutboundIndex
		mark     uint32
		must     bool
	}{
		{"direct", config_parser.Function{Name: "direct"}, consts.OutboundDirect, 0, false},
		{"block", config_parser.Function{Name: "block"}, consts.OutboundBlock, 0, false},
		{"proxy", config_parser.Function{Name: "proxy"}, consts.OutboundUserDefinedMin, 0, false},
		{"must_direct", config_parser.Function{Name: "direct", Params: []*config_parser.Param{{Val: "must"}, {Key: "mark", Val: "37"}}}, consts.OutboundDirect, 37, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := &config_parser.RoutingRule{AndFunctions: []*config_parser.Function{{Name: "domain", Params: []*config_parser.Param{{Key: "full", Val: "service.example"}}}}, Outbound: test.outbound}
			preparation := &ControlPlanePreparation{rules: preparedRules{routing: []*config_parser.RoutingRule{original}}}
			preparation.rules.enableSurgeRouting(engine)
			if len(preparation.rules.routing) != 1 || preparation.rules.routing[0] != original || preparation.rules.capture == nil {
				t.Fatalf("overlay replaced original routing: %+v", preparation.rules.routing)
			}
			matcher, _ := surgeRoutingMatcher(t, preparation.rules)
			got, mark, must := surgeMatchRoute(t, matcher, "service.example", consts.L4ProtoType_TCP)
			if got != test.want || mark != test.mark || must != test.must {
				t.Fatalf("route=(%v,%d,%v), want (%v,%d,%v)", got, mark, must, test.want, test.mark, test.must)
			}
		})
	}
}

func TestSurgeCaptureSelectsOnlyTCPModuleHostnames(t *testing.T) {
	engine := surgeRoutingEngine(t, "-excluded.example", "*.example", "node?.test:8443", "UPPER.EXAMPLE.")
	preparation := &ControlPlanePreparation{}
	preparation.rules.enableSurgeRouting(engine)
	matcher, builder := surgeRoutingMatcher(t, preparation.rules)
	// Change only the marker action to observe whether the preceding conditions
	// select capture, without loading BPF maps or altering userspace skip logic.
	for i := range builder.rules {
		if builder.rules[i].Outbound == uint8(consts.OutboundControlPlaneRouting) {
			builder.rules[i].Outbound = uint8(consts.OutboundUserDefinedMin)
		}
	}
	for _, test := range []struct {
		host    string
		proto   consts.L4ProtoType
		capture bool
	}{
		{"service.example", consts.L4ProtoType_TCP, true},
		{"service.example", consts.L4ProtoType_UDP, false},
		{"outside.test", consts.L4ProtoType_TCP, false},
		{"node1.test", consts.L4ProtoType_TCP, true},
		{"node12.test", consts.L4ProtoType_TCP, false},
		{"upper.example", consts.L4ProtoType_TCP, true},
		{"excluded.example", consts.L4ProtoType_TCP, true},
	} {
		got, _, _ := surgeMatchRoute(t, matcher, test.host, test.proto)
		if (got == consts.OutboundUserDefinedMin) != test.capture {
			t.Errorf("capture(%q,%v)=%v", test.host, test.proto, got)
		}
	}
	if engine.Match("excluded.example", 443) {
		t.Fatal("capturing an excluded hostname must not enable its MITM")
	}
	if !engine.Match("node1.test", 8443) || engine.Match("node1.test", 443) {
		t.Fatal("MITM lost hostname port constraint")
	}
}

func TestSurgeAPIRoutingPreservesDirectLANConnection(t *testing.T) {
	addresses := []net.Addr{
		&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(64, 128)},
	}
	for _, port := range []uint16{8081, 0} {
		prepared := preparedRules{}
		prepared.enableSurgeRouting(surgeRoutingEngine(t, "service.example"))
		prepared.bypassAPI(port, addresses)
		builder, err := NewRoutingMatcherBuilder(prepared.routing, map[string]uint8{
			"direct": uint8(consts.OutboundDirect), "proxy": uint8(consts.OutboundUserDefinedMin),
		}, nil, "proxy", nil, prepared.capture)
		if err != nil {
			t.Fatal(err)
		}
		// Treat the capture action as proxy to observe the kernel's first
		// matching route; the local portal must win even for a captured IP.
		for i := range builder.rules {
			if builder.rules[i].Outbound == uint8(consts.OutboundControlPlaneRouting) {
				builder.rules[i].Outbound = uint8(consts.OutboundUserDefinedMin)
			}
		}
		matcher, err := builder.BuildUserspace()
		if err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct {
			destination string
			port        uint16
			proto       consts.L4ProtoType
			direct      bool
		}{
			{"10.0.0.1", 8081, consts.L4ProtoType_TCP, true},
			{"fd00::1", 8081, consts.L4ProtoType_TCP, true},
			{"10.0.0.2", 8081, consts.L4ProtoType_TCP, false},
			{"fd00::2", 8081, consts.L4ProtoType_TCP, false},
			{"203.0.113.1", 8081, consts.L4ProtoType_TCP, false},
			{"10.0.0.1", 443, consts.L4ProtoType_TCP, false},
			{"10.0.0.1", 8081, consts.L4ProtoType_UDP, false},
		} {
			ip := netip.MustParseAddr(test.destination)
			destination := ip.As16()
			ipVersion := consts.IpVersion_6
			if ip.Is4() {
				ipVersion = consts.IpVersion_4
			}
			zero := make([]byte, 16)
			got, mark, must, err := matcher.Match(zero, destination[:], 12345, test.port, ipVersion, test.proto, "service.example", [16]uint8{}, 0, 0, zero)
			if err != nil {
				t.Fatal(err)
			}
			want := consts.OutboundUserDefinedMin
			if port != 0 && test.direct {
				want = consts.OutboundDirect
			}
			if got != want || mark != 0 || must {
				t.Errorf("api_port=%d route(%s:%d,%v)=(%v,%d,%v), want (%v,0,false)", port, test.destination, test.port, test.proto, got, mark, must, want)
			}
		}
	}
}

func TestSurgeCaptureReconstructionAfterAPIRoute(t *testing.T) {
	engine := surgeRoutingEngine(t, "one.example")
	prepared := preparedRules{routing: []*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{Name: "dport", Params: []*config_parser.Param{{Val: "443"}}}},
		Outbound:     config_parser.Function{Name: "block"},
	}}}
	prepared.enableSurgeRouting(engine)
	prepared.enableDestinationRewrites(routing.DestinationRewrites{{From: netip.MustParseAddr("192.0.2.2")}})
	prepared.bypassAPI(8081, []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}})
	matcher, _ := surgeRoutingMatcher(t, prepared)
	registry, _ := newTestRegistry(10, 10, time.Minute)
	defer registry.Close()
	ip := netip.MustParseAddr("192.0.2.1")
	// Only one of the shared IP's names matches the capture rule. Kernel
	// reconstruction must skip that uncertain marker and retain the block.
	for _, host := range []string{"one.example", "two.example"} {
		registry.UpsertNoExpiry(queryInfo{qname: host + ".", qtype: common.AddrToDnsType(ip)}, ip, matcher.domainMatcher.MatchDomainBitmap(host), time.Now())
	}
	c := &ControlPlane{surge: engine, core: &controlPlaneCore{domainRegistry: registry}, routingMatcher: matcher}
	bump, routing, err := c.capturedRoutingBitmaps(ip, consts.L4ProtoType_TCP)
	if err != nil || len(bump) == 0 || len(routing) == 0 {
		t.Fatalf("capture bitmaps after API prefix: bump=%v routing=%v err=%v", bump, routing, err)
	}
	address, zero := ip.As16(), make([]byte, 16)
	got, _, _, err := matcher.Match(zero, address[:], 12345, 443, consts.IpVersion_4, consts.L4ProtoType_TCP, "", [16]uint8{}, 0, 0, zero, routing, bump)
	if err != nil || got != consts.OutboundBlock {
		t.Fatalf("reconstructed route=%v err=%v, want block", got, err)
	}
}

func TestSurgeCaptureRetainsDNSRouteWithoutTrustedSNI(t *testing.T) {
	engine := surgeRoutingEngine(t, "blocked.example")
	preparation := &ControlPlanePreparation{rules: preparedRules{routing: []*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{Name: "domain", Params: []*config_parser.Param{{Key: "full", Val: "blocked.example"}}}},
		Outbound:     config_parser.Function{Name: "block"},
	}}}}
	preparation.rules.enableSurgeRouting(engine)
	matcher, _ := surgeRoutingMatcher(t, preparation.rules)
	registry, _ := newTestRegistry(10, 10, time.Minute)
	defer registry.Close()
	destination := netip.MustParseAddrPort("192.0.2.1:443")
	registry.UpsertNoExpiry(queryInfo{qname: "blocked.example.", qtype: common.AddrToDnsType(destination.Addr())}, destination.Addr(), matcher.domainMatcher.MatchDomainBitmap("blocked.example"), time.Now())
	option := &dialer.GlobalOption{}
	var groups []*outbound.DialerGroup
	for _, name := range []string{"direct", "block", "proxy"} {
		d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: dnsPathDialer{}}), option, &dialer.Property{Name: name, Link: "test://" + name}, false, name)
		group := outbound.NewDialerGroup(option, name, outbound.GroupKindSingleAlwaysAlive, []*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, func(bool, *common.NetworkType) error { return nil })
		groups = append(groups, group)
		defer group.Close()
	}
	c := &ControlPlane{core: &controlPlaneCore{domainRegistry: registry}, outbounds: groups, routingMatcher: matcher, sniffVerifyMode: consts.SniffVerifyMode_Strict, surge: engine}
	for _, host := range []string{"blocked.example", "", "unverified.example"} {
		t.Run(host, func(t *testing.T) {
			result, err := c.RouteDialOption(context.Background(), &RouteParam{
				routingResult: &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting)},
				networkType:   common.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4},
				Domain:        host, Src: netip.MustParseAddrPort("192.0.2.2:12345"), Dest: destination,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Outbound.Name != "block" {
				t.Fatalf("capture changed DNS-derived block route to %q when SNI=%q", result.Outbound.Name, host)
			}
		})
	}
	// A different SNI accepted by sniff_verify_mode=none must not replace a
	// definite kernel direct/block decision, even under reroute_mode=force.
	originalRule := matcher.matches[matcher.captureIndex+1]
	c.sniffVerifyMode = consts.SniffVerifyMode_None
	c.rerouteMode = consts.RerouteMode_Force
	c.dialTargetOverride = true
	for _, target := range []consts.OutboundIndex{consts.OutboundDirect, consts.OutboundBlock} {
		matcher.matches[matcher.captureIndex+1].Outbound = uint8(target)
		matcher.matches[matcher.captureIndex+1].Mark = 37
		matcher.matches[matcher.captureIndex+1].Must = true
		param := &RouteParam{
			routingResult: &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting)},
			networkType:   common.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4},
			Domain:        "different.test", Src: netip.MustParseAddrPort("192.0.2.2:12345"), Dest: destination,
		}
		result, err := c.RouteDialOption(context.Background(), param)
		if err != nil {
			t.Fatal(err)
		}
		if result.Outbound != groups[target] || result.DialTarget != destination.String() || param.routingResult.Mark != 37 || param.routingResult.Must != 1 {
			t.Fatalf("different trusted SNI changed original %s route/target: %+v, routing=%+v", target, result, param.routingResult)
		}
	}
	// A user proxy still follows the configured reroute policy, as it already
	// entered userspace before Surge support.
	matcher.matches[matcher.captureIndex+1] = originalRule
	matcher.matches[matcher.captureIndex+1].Outbound = uint8(consts.OutboundUserDefinedMin)
	for _, test := range []struct {
		mode consts.RerouteMode
		want string
	}{{consts.RerouteMode_None, "proxy"}, {consts.RerouteMode_Force, "direct"}} {
		c.rerouteMode = test.mode
		result, err := c.RouteDialOption(context.Background(), &RouteParam{
			routingResult: &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting)},
			networkType:   common.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4},
			Domain:        "different.test", Src: netip.MustParseAddrPort("192.0.2.2:12345"), Dest: destination,
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Outbound.Name != test.want {
			t.Fatalf("proxy reroute %v selected %q, want %q", test.mode, result.Outbound.Name, test.want)
		}
	}
	matcher.matches[matcher.captureIndex+1] = originalRule
	c.sniffVerifyMode = consts.SniffVerifyMode_Strict
	c.rerouteMode = consts.RerouteMode_None
	c.dialTargetOverride = false
	// Existing control-plane behavior stays unchanged when modules are disabled.
	c.surge = nil
	if _, bitmap, err := c.capturedRoutingBitmaps(destination.Addr(), consts.L4ProtoType_TCP); err != nil || bitmap != nil {
		t.Fatalf("disabled module routing changed: bitmap=%v, err=%v", bitmap, err)
	}
	c.surge = engine
	// A shared IP with contradictory domain rules cannot be reconstructed from
	// the intersection alone: skipping the block would create a policy bypass.
	registry.UpsertNoExpiry(queryInfo{qname: "allowed.example.", qtype: common.AddrToDnsType(destination.Addr())}, destination.Addr(), matcher.domainMatcher.MatchDomainBitmap("allowed.example"), time.Now())
	for _, host := range []string{"", "blocked.example", "allowed.example"} {
		result, err := c.RouteDialOption(context.Background(), &RouteParam{
			routingResult: &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting)},
			networkType:   common.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4},
			Domain:        host, Src: netip.MustParseAddrPort("192.0.2.2:12345"), Dest: destination,
		})
		if host == "" {
			if err == nil {
				t.Fatal("ambiguous shared-IP routing did not fail closed without SNI")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		want := "direct"
		if host == "blocked.example" {
			want = "block"
		}
		if result.Outbound.Name != want {
			t.Fatalf("ambiguous IP with trusted %s selected %s, want %s", host, result.Outbound.Name, want)
		}
	}
	// The record may expire or be evicted after kernel capture and before SNI
	// inspection. Missing DNS state must not silently become fallback direct.
	if _, _, err := c.capturedRoutingBitmaps(netip.MustParseAddr("192.0.2.99"), consts.L4ProtoType_TCP); err == nil {
		t.Fatal("missing DNS routing state did not fail closed")
	}
}

func TestSurgeDialReportsConnectivityFailures(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	for _, test := range []struct {
		name                string
		err                 error
		unchecked, canceled bool
		wantReport          bool
	}{
		{name: "connection refused", err: refused, wantReport: true},
		{name: "wrapped connection reset", err: fmt.Errorf("proxy: %w", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNRESET}), wantReport: true},
		{name: "timeout", err: &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}},
		{name: "non-network error", err: errors.New("invalid proxy response")},
		{name: "canceled request", err: refused, canceled: true},
		{name: "unchecked node", err: refused, unchecked: true},
		{name: "successful dial"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			transport := surgeDownloadTestDialer(func(context.Context, string, string) (net.Conn, error) {
				if test.canceled {
					cancel()
				}
				if test.err != nil {
					return nil, test.err
				}
				return newCloseTrackingConn(), nil
			})
			d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: transport}), &dialer.GlobalOption{},
				&dialer.Property{Name: t.Name()}, !test.unchecked, "")
			t.Cleanup(func() { _ = d.Close() })
			stats.DefaultStore.Reconcile(map[string]stats.NodeIdentity{d.StatsKey(): {Name: d.Name}}, nil)
			stats.DefaultStore.RecordNodeState(d.StatsKey(), false, time.Time{})
			t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })
			option := &DialOption{Dialer: d, DialTarget: "198.51.100.1:443"}
			path := d.StatsPath("proxy", common.NetworkTCP4.NetworkType())
			conn, err := (&ControlPlane{}).surgeDialContext(option, "api.example", netip.MustParseAddrPort(option.DialTarget), path)(ctx, "tcp", "api.example:443")
			if conn != nil {
				_ = conn.Close()
			}
			if !errors.Is(err, test.err) {
				t.Fatalf("dial error = %v, want %v", err, test.err)
			}
			// ReportDataPlaneFailure records this observation even before a node
			// becomes healthy; no background probe is needed to observe the call.
			reported := !stats.DefaultStore.GetNode(d.StatsKey()).LastConnFailAt.IsZero()
			if reported != test.wantReport {
				t.Fatalf("connectivity failure reported = %v, want %v", reported, test.wantReport)
			}
		})
	}
}
