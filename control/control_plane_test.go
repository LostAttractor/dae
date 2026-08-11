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

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
)

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
