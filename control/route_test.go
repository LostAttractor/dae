/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

// Only a proxy receives the sniffed name. A direct connection, including the
// no-connectivity fallback of a proxy group, dials the client's address.
func TestDialTargetOverrideAppliesOnlyToProxies(t *testing.T) {
	unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	global := &dialer.GlobalOption{}
	unavailable := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: unused}), global, &dialer.Property{Name: "unavailable"}, true, "")
	dead := outbound.NewDialerGroup(global, "dead", outbound.GroupKindSelector, []*dialer.Dialer{unavailable}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{})
	t.Cleanup(func() { dead.Close() })
	plane := &ControlPlane{noConnectivityOutbound: consts.OutboundDirect, outbounds: []*outbound.DialerGroup{
		downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), downloadTestGroup(t, "proxy", unused), dead,
	}}
	destination := netip.MustParseAddrPort("192.0.2.2:443")
	for _, test := range []struct {
		outbound consts.OutboundIndex
		network  *common.NetworkType
		want     string
	}{
		{consts.OutboundDirect, common.NetworkTCP4.NetworkType(), destination.String()},
		{2, common.NetworkTCP4.NetworkType(), "example.com:443"},
		{2, common.NetworkUDP4.NetworkType(), destination.String()},
		{3, common.NetworkTCP4.NetworkType(), destination.String()},
	} {
		p := &RouteParam{Src: netip.MustParseAddrPort("192.0.2.1:12345"), Dest: destination, Domain: "example.com", networkType: *test.network, routingResult: &routingResult{}}
		option, err := plane.selectDialOption(p, test.outbound, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		if option.DialTarget != test.want || (test.outbound == 3) != (option.OriginalOutbound == dead) {
			t.Fatalf("%s via %s: dial target %s, want %s", test.network, plane.outbounds[test.outbound].Name, option.DialTarget, test.want)
		}
	}
}

func TestDirectDialerForMarkCachesOverrides(t *testing.T) {
	c := &ControlPlane{soMarkFromDae: 7}
	if got := c.directDialerForMark(consts.OutboundUserDefinedMin, 8); got != nil {
		t.Fatal("non-direct outbound received a marked direct dialer")
	}
	if got := c.directDialerForMark(consts.OutboundDirect, 7); got != nil {
		t.Fatal("global mark unnecessarily replaced the configured direct dialer")
	}
	first := c.directDialerForMark(consts.OutboundDirect, 8)
	second := c.directDialerForMark(consts.OutboundDirect, 8)
	if first == nil || first != second {
		t.Fatal("marked direct dialer was not cached")
	}
}

func TestRoutingLogFieldsOmitUnavailableMetadata(t *testing.T) {
	if fields := routingLogFields(new(routingResult), ""); len(fields) != 0 {
		t.Fatalf("zero routing metadata = %#v, want empty", fields)
	}

	result := &routingResult{
		Pid:  42,
		Dscp: 4,
		Mac:  [6]uint8{0x02, 0x42, 0xac, 0x11, 0x00, 0x02},
	}
	copy(result.Pname[:], "curl")
	fields := routeLogFields(result, "lan0", "tcp4", "192.0.2.1:1234", "example.com:443")
	if len(fields) != 9 || fields["pid"] != uint32(42) || fields["pname"] != "curl" ||
		fields["interface"] != "lan0" || fields["dscp"] != uint8(4) || fields["mac"] != "02:42:ac:11:00:02" {
		t.Fatalf("routing metadata = %#v", fields)
	}
	if fields["action"] != "forward" || fields["network"] != "tcp4" ||
		fields["source"] != "192.0.2.1:1234" || fields["destination"] != "example.com:443" {
		t.Fatalf("route fields = %#v", fields)
	}
	if _, ok := fields["ifindex"]; ok {
		t.Fatal("routing metadata exposed a numeric ifindex")
	}
}
