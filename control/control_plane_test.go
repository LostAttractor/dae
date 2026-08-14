/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	D "github.com/daeuniverse/outbound/dialer"
)

func TestParseGroupOverrideOptionCheckIntervals(t *testing.T) {
	global := config.Global{
		CheckInterval:    30 * time.Second,
		CheckIntervalMax: time.Hour,
	}
	option, err := ParseGroupOverrideOption(config.Group{
		CheckInterval:    45 * time.Second,
		CheckIntervalMax: 10 * time.Minute,
	}, global)
	if err != nil {
		t.Fatal(err)
	}
	if option.CheckInterval != 45*time.Second || option.CheckIntervalMax != 10*time.Minute {
		t.Fatalf("unexpected check intervals: %v, %v", option.CheckInterval, option.CheckIntervalMax)
	}
}

type dnsPathDialer struct{}

func (dnsPathDialer) Alive() bool    { return true }
func (dnsPathDialer) Connect() error { return nil }
func (dnsPathDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}
func (dnsPathDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, fmt.Errorf("not implemented")
}

func TestChooseBestDnsDialerReturnsSuccessfulNetworkType(t *testing.T) {
	option := &dialer.GlobalOption{}
	d := dialer.NewDialer(dnsPathDialer{}, option, &dialer.Property{Property: D.Property{
		Name: "dns-path",
		Link: "test://dns-path",
	}}, true)
	group := outbound.NewDialerGroup(
		option,
		"dns-path",
		outbound.GroupKindNormal,
		[]*dialer.Dialer{d},
		[]*dialer.Annotation{{}},
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed},
		func(bool, *common.NetworkType) {},
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
