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
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/surgemodule"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/outbound/netproxy"
)

// Routing tests only inspect the engine's allowlist; no CA operations or JS run.
func surgeRoutingEngine(t *testing.T, hostnames ...string) *surgemodule.Engine {
	t.Helper()
	engine, err := surgemodule.NewEngine(surgemodule.EngineOptions{
		Modules:     []*surgemodule.Module{{Hostnames: hostnames}},
		Runtime:     &surgemodule.Runtime{},
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
			preparation.rules.enableMITMPlan(surgeRoutingEngine(t, "one.example").Plan())
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
	}, nil, "direct", nil, rules.capture, rules.destinations)
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
			preparation.rules.enableMITMPlan(engine.Plan())
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

func TestMITMCaptureSniffsTCPWithoutDNS(t *testing.T) {
	engine := surgeRoutingEngine(t, "-excluded.example", "*.example", "node?.test:8443", "UPPER.EXAMPLE.")
	preparation := &ControlPlanePreparation{}
	preparation.rules.enableMITMPlan(engine.Plan())
	matcher, builder := surgeRoutingMatcher(t, preparation.rules)
	// Change only the marker action to observe whether the preceding conditions
	// select capture, without loading BPF maps or altering userspace skip logic.
	for i := range builder.rules {
		if builder.rules[i].CaptureFlags != 0 {
			builder.rules[i].Outbound = uint8(consts.OutboundUserDefinedMin)
			builder.rules[i].CaptureFlags = 0 // Expose the capture predicate as a test terminal.
		}
	}
	for _, test := range []struct {
		host    string
		proto   consts.L4ProtoType
		capture bool
	}{
		{"service.example", consts.L4ProtoType_TCP, true},
		{"service.example", consts.L4ProtoType_UDP, false},
		{"outside.test", consts.L4ProtoType_TCP, true},
		{"node1.test", consts.L4ProtoType_TCP, true},
		{"node12.test", consts.L4ProtoType_TCP, true},
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
		prepared.enableMITMPlan(surgeRoutingEngine(t, "service.example").Plan())
		prepared.bypassAPI(port, addresses)
		builder, err := NewRoutingMatcherBuilder(prepared.routing, map[string]uint8{
			"direct": uint8(consts.OutboundDirect), "proxy": uint8(consts.OutboundUserDefinedMin),
		}, nil, "proxy", nil, prepared.capture, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Treat the capture action as proxy to observe the kernel's first
		// matching route; the local portal must win even for a captured IP.
		for i := range builder.rules {
			if builder.rules[i].CaptureFlags != 0 {
				builder.rules[i].Outbound = uint8(consts.OutboundUserDefinedMin)
				builder.rules[i].CaptureFlags = 0 // Expose the capture predicate as a test terminal.
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

// Kernel terminal decisions carry capture separately; SNI does not replace them.
func TestMITMCaptureRetainsKernelRoute(t *testing.T) {
	unused := surgeDownloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	groups := []*outbound.DialerGroup{surgeDownloadTestGroup(t, "direct", unused), surgeDownloadTestGroup(t, "block", unused), surgeDownloadTestGroup(t, "proxy", unused)}
	matcher, _ := surgeRoutingMatcher(t, preparedRules{})
	plane := &ControlPlane{outbounds: groups, routingMatcher: matcher, sniffVerifyMode: consts.SniffVerifyMode_None, rerouteMode: consts.RerouteMode_Force, dialTargetOverride: true}
	plane.markedDirectDialers.Store(uint32(37), unused)
	for _, out := range []consts.OutboundIndex{consts.OutboundDirect, consts.OutboundBlock} {
		for _, host := range []string{"", "different.example"} {
			p := &RouteParam{Src: netip.MustParseAddrPort("192.0.2.1:12345"), Dest: netip.MustParseAddrPort("192.0.2.2:443"), Domain: host, networkType: *common.NetworkTCP4.NetworkType(), routingResult: &bpfRoutingResult{Outbound: uint8(out), Mark: 37, Must: 1, CaptureFlags: captureHTTP}}
			got, err := plane.RouteDialOption(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			if got.Outbound != groups[out] || got.DialTarget != p.Dest.String() || p.routingResult.Mark != 37 || p.routingResult.Must != 1 {
				t.Fatalf("capture changed route: %+v, %+v", got, p.routingResult)
			}
		}
	}
	plane.sniffVerifyMode = consts.SniffVerifyMode_Strict
	p := &RouteParam{Src: netip.MustParseAddrPort("192.0.2.1:12345"), Dest: netip.MustParseAddrPort("192.0.2.2:443"), networkType: *common.NetworkTCP4.NetworkType(), routingResult: &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting), CaptureFlags: captureHTTP}}
	if _, err := plane.RouteDialOption(context.Background(), p); err == nil {
		t.Fatal("ambiguous kernel route accepted without a trusted domain")
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
			conn, err := (&ControlPlane{}).mitmDialContext(option, "api.example", netip.MustParseAddrPort(option.DialTarget), path)(ctx, "tcp", "api.example:443")
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
