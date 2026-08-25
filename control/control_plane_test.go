/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/vishvananda/netlink"
)

func TestSplitWanInterfacesPreservesAutoIntent(t *testing.T) {
	manual, auto := splitWanInterfaces([]string{"eth0", "auto", "eth0", "ppp.*", "auto"})
	if !auto {
		t.Fatal("auto WAN discovery is disabled")
	}
	if want := []string{"eth0", "ppp.*"}; !reflect.DeepEqual(manual, want) {
		t.Fatalf("manual interfaces = %v, want %v", manual, want)
	}
}

func TestValidateReusableBpfStateRejectsChangedSoMark(t *testing.T) {
	state := &bpfState{soMarkFromDae: 0x100}
	if _, err := validateReusableBpfState(state, 0x101); err == nil {
		t.Fatal("changed so_mark_from_dae was accepted")
	}
	if got, err := validateReusableBpfState(state, state.soMarkFromDae); err != nil || got != state {
		t.Fatalf("matching reusable BPF state = %p, %v; want %p", got, err, state)
	}
}

func TestAutoWanTargetsUseOneOwnerPerInterface(t *testing.T) {
	got := autoWanTargets(component.HostNetworkSnapshot{Interfaces: []component.DefaultRouteInterface{
		{Index: consts.LoopbackIfIndex, Name: "lo", IPv4Default: true},
		{Index: 2, Name: "eth0", IPv4Default: true},
		{Index: 3, Name: "eth1", IPv6Default: true},
		{Index: 4, Name: "ppp0", IPv4Default: true, IPv6Default: true},
	}})
	want := map[int]string{2: "eth0", 3: "eth1", 4: "ppp0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("auto WAN targets = %v, want %v", got, want)
	}
}

func TestManualWanRejectsLoopback(t *testing.T) {
	closed, cancel := context.WithCancel(context.Background())
	defer cancel()
	core := &controlPlaneCore{closed: closed, wanBindings: make(map[int]*wanBinding)}
	core.setManualWan(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Index: consts.LoopbackIfIndex,
		Name:  "lo",
	}}, "*", true)
	if len(core.wanBindings) != 0 {
		t.Fatalf("loopback WAN binding = %+v", core.wanBindings)
	}
}

func TestManualWanRenamePreservesAttachment(t *testing.T) {
	closed, cancel := context.WithCancel(context.Background())
	defer cancel()
	const index = 2
	core := &controlPlaneCore{
		closed: closed,
		wanBindings: map[int]*wanBinding{index: {
			ifname:         "eth0",
			manualPatterns: map[string]struct{}{"eth*": {}},
		}},
	}
	core.setManualWan(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: index, Name: "wan0"}}, "wan*", true)
	binding := core.wanBindings[index]
	if binding.ifname != "wan0" {
		t.Fatalf("renamed binding = %+v", binding)
	}
	if _, exists := binding.manualPatterns["eth*"]; exists {
		t.Fatal("rename retained ownership from the old interface name")
	}
}

func TestRemoveWanOwnerPreservesTCXForOtherOwners(t *testing.T) {
	closed, cancel := context.WithCancel(context.Background())
	defer cancel()
	const index = 2
	var closes int
	core := &controlPlaneCore{
		closed: closed,
		wanBindings: map[int]*wanBinding{index: {
			ifname:         "eth0",
			automatic:      true,
			manualPatterns: map[string]struct{}{"eth*": {}, "*0": {}},
		}},
		hostTCXLinks: []hostTCXLink{
			{linkIndex: index, role: hostTCXWanIngress, close: func() error { closes++; return nil }},
			{linkIndex: index, role: hostTCXWanEgress, close: func() error { closes++; return nil }},
		},
	}

	core.removeWanLink(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: index, Name: "eth0"}}, "eth*")
	if closes != 0 || len(core.hostTCXLinks) != 2 {
		t.Fatalf("removing one owner detached WAN TCX: closes=%d links=%v", closes, core.hostTCXLinks)
	}
	binding := core.wanBindings[index]
	if _, exists := binding.manualPatterns["eth*"]; exists {
		t.Fatal("manual WAN ownership retained after delete")
	}
	if _, exists := binding.manualPatterns["*0"]; !exists || !binding.automatic {
		t.Fatalf("remaining WAN ownership was lost: %+v", binding)
	}
}

func TestInvalidateAutoWanLinkClearsTCXOwnership(t *testing.T) {
	closed, cancel := context.WithCancel(context.Background())
	defer cancel()
	const index = 2
	var closes int
	core := &controlPlaneCore{
		closed: closed,
		wanBindings: map[int]*wanBinding{index: {
			ifname:         "eth0",
			automatic:      true,
			manualPatterns: make(map[string]struct{}),
		}},
		hostTCXLinks: []hostTCXLink{
			{linkIndex: index, role: hostTCXWanIngress, close: func() error { closes++; return nil }},
			{linkIndex: index, role: hostTCXWanEgress, close: func() error { closes++; return nil }},
		},
	}

	core.invalidateWanLink(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: index, Name: "eth0"}})
	if closes != 2 || len(core.hostTCXLinks) != 0 {
		t.Fatalf("auto-WAN TCX ownership retained after delete: closes=%d links=%v", closes, core.hostTCXLinks)
	}
	if !core.wanBindings[index].automatic {
		t.Fatal("link deletion discarded automatic intent before reconciliation")
	}
}

func TestReconcileLanLinksRetriesAndDeduplicatesPatterns(t *testing.T) {
	links := []netlink.Link{
		&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "eth0"}},
		&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 3, Name: "eth1"}},
		&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 4, Name: hostLinkName}},
	}
	attempts := make(map[string]int)
	bind := func(link netlink.Link) error {
		name := link.Attrs().Name
		attempts[name]++
		if name == "eth1" && attempts[name] == 1 {
			return errors.New("temporary attach failure")
		}
		return nil
	}

	if !reconcileLanLinks(links, []string{"eth*", "*0"}, bind) {
		t.Fatal("failed LAN attachment did not request retry")
	}
	if reconcileLanLinks(links, []string{"eth*", "*0"}, bind) {
		t.Fatal("successful LAN reconciliation requested retry")
	}
	if attempts["eth0"] != 2 || attempts["eth1"] != 2 {
		t.Fatalf("bind attempts = %v, want each LAN once per pass", attempts)
	}
	if attempts[hostLinkName] != 0 {
		t.Fatal("host link was treated as LAN")
	}
}

func TestGroupOverrideOptionCheckIntervals(t *testing.T) {
	global := config.Global{
		CheckInterval:    30 * time.Second,
		CheckIntervalMax: time.Hour,
	}
	option := parseGroupOverrideOption(config.Group{
		CheckInterval:    45 * time.Second,
		CheckIntervalMax: 10 * time.Minute,
	}, global)
	if option.CheckInterval != 45*time.Second || option.CheckIntervalMax != 10*time.Minute {
		t.Fatalf("unexpected check intervals: %v, %v", option.CheckInterval, option.CheckIntervalMax)
	}
}

func TestGroupOverrideOptionExplicitZeroTolerance(t *testing.T) {
	option := parseGroupOverrideOption(config.Group{
		Present:        map[string]bool{"check_tolerance": true},
		CheckTolerance: 0,
	}, config.Global{CheckTolerance: time.Second})
	if option == nil || option.CheckTolerance != 0 {
		t.Fatalf("explicit zero tolerance option = %#v", option)
	}
}

func TestCollectRoutingTargetNamesPreservesFirstReferenceOrder(t *testing.T) {
	routingConfig := &config.Routing{
		Rules: []*config_parser.RoutingRule{
			{Outbound: config_parser.Function{Name: "selector"}},
			{Outbound: config_parser.Function{Name: "direct node"}},
			{Outbound: config_parser.Function{Name: "selector"}},
		},
		Fallback: &config_parser.Function{Name: "fallback group"},
	}
	want := []string{"selector", "direct node", "fallback group"}
	if got := collectRoutingTargetNames(routingConfig); !reflect.DeepEqual(got, want) {
		t.Fatalf("routing targets = %v, want %v", got, want)
	}
}

func TestCandidateStatsScopeSeparatesIdenticalPaths(t *testing.T) {
	set, err := outbound.NewDialerSet([]outbound.NodeDescriptor{{
		Name:     "node",
		Link:     "socks5://127.0.0.1:1080",
		Required: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	path := outbound.NodePath(set.NodesNamed("node")[0])
	occurrences := make(map[string]int)
	first, err := set.BuildPath(path, new(dialer.GlobalOption), candidateStatsScope("target", path, occurrences))
	if err != nil {
		t.Fatal(err)
	}
	second, err := set.BuildPath(path, new(dialer.GlobalOption), candidateStatsScope("target", path, occurrences))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = first.Close()
		first.RetireTransport()
		_ = second.Close()
		second.RetireTransport()
	})
	if first.StatsKey() == second.StatsKey() || first.StatsID() == second.StatsID() {
		t.Fatal("identical path occurrences share stats identity")
	}
}

func TestCandidateStatsScopeIgnoresUnrelatedPaths(t *testing.T) {
	first := &outbound.PathSpec{Nodes: []*outbound.NodeInfo{{
		Property: &dialer.Property{Property: D.Property{Name: "first", Link: "first"}},
	}}}
	second := &outbound.PathSpec{Nodes: []*outbound.NodeInfo{{
		Property: &dialer.Property{Property: D.Property{Name: "second", Link: "second"}},
	}}}

	withoutInsertion := make(map[string]int)
	_ = candidateStatsScope("target", first, withoutInsertion)
	want := candidateStatsScope("target", second, withoutInsertion)

	withInsertion := make(map[string]int)
	_ = candidateStatsScope("target", &outbound.PathSpec{Nodes: []*outbound.NodeInfo{{
		Property: &dialer.Property{Property: D.Property{Name: "inserted", Link: "inserted"}},
	}}}, withInsertion)
	if got := candidateStatsScope("target", second, withInsertion); got != want {
		t.Fatalf("scope after unrelated insertion = %q, want %q", got, want)
	}
}

type dnsPathDialer struct{}

func (dnsPathDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}
func (dnsPathDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, fmt.Errorf("not implemented")
}

func TestChooseBestDnsDialerReturnsSuccessfulNetworkType(t *testing.T) {
	option := &dialer.GlobalOption{}
	d := dialer.NewDialer(netproxy.NewRuntime(dnsPathDialer{}), option, &dialer.Property{Property: D.Property{
		Name: "dns-path",
		Link: "test://dns-path",
	}}, dialer.InitialCheckBlocking)
	group := outbound.NewDialerGroup(
		option,
		"dns-path",
		outbound.GroupKindSelector,
		[]*dialer.Dialer{d},
		[]*dialer.Annotation{{}},
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed},
		func(bool, *common.NetworkType) error { return nil },
	)
	t.Cleanup(func() { _ = group.Close() })
	wantNetwork := common.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_4,
	}
	d.SetSupported(&wantNetwork, true)
	d.Update(true, 0, &wantNetwork, nil)

	c := &ControlPlane{
		outbounds: []*outbound.DialerGroup{group},
		routingMatcher: &RoutingMatcher{
			rulesMu: new(sync.RWMutex),
			matches: []bpfMatchSet{{
				Type:     uint8(consts.MatchType_Fallback),
				Outbound: uint8(consts.OutboundDirect),
				Mark:     42,
			}},
		},
	}
	upstream := &dns.Upstream{
		Scheme: dns.UpstreamScheme_TCP_UDP,
		Port:   53,
		Ip46: &netutils.Ip46{
			Ip4: netip.MustParseAddr("192.0.2.1"),
			Ip6: netip.MustParseAddr("2001:db8::1"),
		},
	}
	req := &udpRequest{
		src:           netip.MustParseAddrPort("192.0.2.2:12345"),
		routingResult: &bpfRoutingResult{},
	}

	got, err := c.chooseBestDnsDialer(req, upstream)
	if err != nil {
		t.Fatalf("chooseBestDnsDialer: %v", err)
	}
	if got.networkType != wantNetwork {
		t.Fatalf("network type = %+v, want %+v", got.networkType, wantNetwork)
	}
	if want := netip.MustParseAddrPort("192.0.2.1:53"); got.Target != want {
		t.Fatalf("target = %v, want %v", got.Target, want)
	}
	if got.Mark != 42 || got.connectionDialer == nil {
		t.Fatalf("marked DNS path = mark %d, dialer %v", got.Mark, got.connectionDialer)
	}
}

func newLifecycleTestControlPlane(udpEndpoints *UdpEndpointPool) *ControlPlane {
	ctx, cancel := context.WithCancel(context.Background())
	tcpSetupCtx, cancelTCPSetups := context.WithCancel(ctx)
	return &ControlPlane{
		tcpConnections:  new(tcpConnectionTracker),
		udpTaskPool:     newUdpTaskPool[netip.AddrPort](time.Hour),
		udpEndpoints:    udpEndpoints,
		ctx:             ctx,
		cancel:          cancel,
		tcpSetupCtx:     tcpSetupCtx,
		cancelTCPSetups: cancelTCPSetups,
	}
}

func TestControlPlaneRetireClosesIngressBeforeWaitAndDrainsUDPWithLiveContext(t *testing.T) {
	plane := newLifecycleTestControlPlane(new(UdpEndpointPool))
	tcpIngressClosed := make(chan struct{})
	udpIngressClosed := make(chan struct{})
	plane.ingress = &controlPlaneIngress{closeFuncs: []func() error{
		func() error {
			close(tcpIngressClosed)
			return nil
		},
		func() error {
			close(udpIngressClosed)
			return nil
		},
	}}

	conn := newCloseTrackingConn()
	if !plane.tcpConnections.beginSetup(conn) {
		t.Fatal("failed to register TCP setup")
	}
	t.Cleanup(func() { _ = conn.Close() })

	taskStarted := make(chan struct{})
	releaseTask := make(chan struct{})
	var releaseTaskOnce sync.Once
	release := func() { releaseTaskOnce.Do(func() { close(releaseTask) }) }
	t.Cleanup(release)
	var finishSetupOnce sync.Once
	finishSetup := func() { finishSetupOnce.Do(plane.tcpConnections.finishSetup) }
	t.Cleanup(finishSetup)
	taskContextErrors := make(chan error, 2)
	if !plane.udpTaskPool.emit(testUdpKey(11001), func() {
		taskContextErrors <- plane.ctx.Err()
		close(taskStarted)
		<-releaseTask
		taskContextErrors <- plane.ctx.Err()
	}) {
		t.Fatal("failed to enqueue UDP task")
	}
	<-taskStarted

	retireDone := make(chan error, 1)
	go func() { retireDone <- plane.retireTraffic() }()
	for name, closed := range map[string]<-chan struct{}{
		"TCP": tcpIngressClosed,
		"UDP": udpIngressClosed,
	} {
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatalf("%s ingress was not closed before retirement wait", name)
		}
	}
	select {
	case <-plane.tcpSetupCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("TCP setup context was not canceled")
	}
	if err := <-taskContextErrors; err != nil {
		t.Fatalf("accepted UDP task started with canceled context: %v", err)
	}
	if err := plane.ctx.Err(); err != nil {
		t.Fatalf("control-plane context canceled before UDP drain: %v", err)
	}
	select {
	case err := <-retireDone:
		t.Fatalf("retirement returned before accepted work completed: %v", err)
	default:
	}

	release()
	if err := <-taskContextErrors; err != nil {
		t.Fatalf("control-plane context canceled during UDP drain: %v", err)
	}
	select {
	case err := <-retireDone:
		t.Fatalf("retirement returned before TCP setup handoff: %v", err)
	default:
	}

	finishSetup()
	select {
	case err := <-retireDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("retirement did not finish after setup and UDP drain")
	}
	if plane.ctx.Err() == nil {
		t.Fatal("control-plane context remained live after retirement")
	}
}

func TestControlPlaneNormalRetirePreservesEstablishedUDPEndpoint(t *testing.T) {
	udpEndpoints := new(UdpEndpointPool)
	plane := newLifecycleTestControlPlane(udpEndpoints)
	key := testUdpKey(11002)
	conn := newTestPacketConn(false)
	endpoint := newUdpEndpoint(&UdpEndpointOptions{
		PacketConn: conn,
		NatTimeout: time.Hour,
	})
	udpEndpoints.add(key, endpoint)
	t.Cleanup(func() { udpEndpoints.remove(key, endpoint) })

	if err := plane.retireTraffic(); err != nil {
		t.Fatal(err)
	}
	got, ok := udpEndpoints.Get(key)
	if !ok || got != endpoint {
		t.Fatal("normal retirement removed the established UDP endpoint")
	}
	select {
	case <-conn.closed:
		t.Fatal("normal retirement closed the established UDP endpoint")
	default:
	}
}

func TestControlPlaneAbortClosesUDPEndpointsCreatedDuringDrain(t *testing.T) {
	udpEndpoints := new(UdpEndpointPool)
	t.Cleanup(udpEndpoints.closeAll)
	plane := newLifecycleTestControlPlane(udpEndpoints)
	key := testUdpKey(11003)
	oldConn := newTestPacketConn(false)
	oldEndpoint := newUdpEndpoint(&UdpEndpointOptions{
		PacketConn: oldConn,
		NatTimeout: time.Hour,
	})
	udpEndpoints.add(key, oldEndpoint)

	taskStarted := make(chan struct{})
	releaseTask := make(chan struct{})
	var releaseTaskOnce sync.Once
	release := func() { releaseTaskOnce.Do(func() { close(releaseTask) }) }
	t.Cleanup(release)
	replacementPublished := make(chan *testPacketConn, 1)
	if !plane.udpTaskPool.emit(key, func() {
		close(taskStarted)
		<-releaseTask
		if err := plane.ctx.Err(); err != nil {
			replacementPublished <- nil
			return
		}
		conn := newTestPacketConn(false)
		udpEndpoints.add(key, newUdpEndpoint(&UdpEndpointOptions{
			PacketConn: conn,
			NatTimeout: time.Hour,
		}))
		replacementPublished <- conn
	}) {
		t.Fatal("failed to enqueue UDP task")
	}
	<-taskStarted

	if err := plane.StopAndAbortConnections(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-oldConn.closed:
	case <-time.After(time.Second):
		t.Fatal("abort did not close the established UDP endpoint")
	}

	retireDone := make(chan error, 1)
	go func() { retireDone <- plane.retireTraffic() }()
	release()
	replacementConn := <-replacementPublished
	if replacementConn == nil {
		t.Fatal("accepted UDP task ran with a canceled control-plane context")
	}
	select {
	case err := <-retireDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("abort retirement did not finish")
	}
	select {
	case <-replacementConn.closed:
	case <-time.After(time.Second):
		t.Fatal("abort did not close endpoint published by an accepted UDP task")
	}
	if _, ok := udpEndpoints.Get(key); ok {
		t.Fatal("abort left an established UDP endpoint in the global pool")
	}
}
