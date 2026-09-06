// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	protocolDirect "github.com/daeuniverse/outbound/protocol/direct"
	"github.com/samber/oops"
)

type DialOption struct {
	Mark              uint32
	DialTarget        string
	Dialer            *dialer.Dialer
	connectionDialer  netproxy.Dialer
	Outbound          *outbound.DialerGroup
	OriginalOutbound  *outbound.DialerGroup
	NetworkType       common.NetworkType
	Direct            bool
	FallbackIpVersion bool
	PolicyLease       *netproxy.Lease
}

func (o *DialOption) dialerForConnection() netproxy.Dialer {
	if o.connectionDialer != nil {
		return o.connectionDialer
	}
	return o.Dialer
}

func (o *DialOption) trafficAttribution() (stats.Path, bool) {
	return o.Dialer.StatsPath(o.Outbound.Name, &o.NetworkType), o.OriginalOutbound != nil
}

// selectDialOption applies the configured node policy and no-connectivity
// fallback after routing has selected an outbound.
func (c *ControlPlane) selectDialOption(p *RouteParam, outboundIndex consts.OutboundIndex, mark uint32, override bool) (*DialOption, error) {
	if int(outboundIndex) >= len(c.outbounds) {
		if len(c.outbounds) == int(consts.OutboundUserDefinedMin) {
			return nil, oops.Errorf("traffic was dropped due to no-load configuration")
		}
		return nil, oops.Errorf("outbound id from bpf is out of range: %v not in [0, %v]", outboundIndex, len(c.outbounds)-1)
	}
	selectedOutbound := c.outbounds[outboundIndex]
	// UDP relays use IPs; replacing them with sniffed QUIC hostnames breaks
	// full-cone reply addressing. Explicit destination IP rewrites remain applicable.
	override = override && p.networkType.L4Proto != consts.L4ProtoStr_UDP
	dialTarget := p.dialTarget(override)
	target, ipErr := netip.ParseAddrPort(dialTarget)
	networkType := p.networkType
	if ipErr == nil {
		networkType.IpVersion = consts.IpVersionStrFromAddr(target.Addr())
	}
	dialer, selectedNetwork, fallback, policyLease, err := selectedOutbound.SelectConnection(
		networkType,
		ipErr == nil,
	)
	selectedOutboundIndex := outboundIndex
	var originalOutbound *outbound.DialerGroup
	if err != nil {
		if !errors.Is(err, outbound.ErrNoAliveDialer) {
			return nil, err
		}
		originalOutbound = selectedOutbound
		selectedOutboundIndex = c.noConnectivityOutbound
		selectedOutbound = c.outbounds[selectedOutboundIndex]
		selectedNetwork = networkType
		fallback = false
		dialer, err = selectedOutbound.Select(&selectedNetwork)
		if err != nil {
			return nil, fmt.Errorf("select fallback outbound %q: %w", selectedOutbound.Name, err)
		}
	}
	return &DialOption{
		Mark:              mark,
		DialTarget:        dialTarget,
		Dialer:            dialer,
		connectionDialer:  c.directDialerForMark(selectedOutboundIndex, mark),
		Outbound:          selectedOutbound,
		OriginalOutbound:  originalOutbound,
		NetworkType:       selectedNetwork,
		Direct:            selectedOutboundIndex == consts.OutboundDirect,
		FallbackIpVersion: fallback,
		PolicyLease:       policyLease,
	}, nil
}

func (c *ControlPlane) directDialerForMark(outboundIndex consts.OutboundIndex, mark uint32) netproxy.Dialer {
	if outboundIndex != consts.OutboundDirect || mark == 0 || mark == c.soMarkFromDae {
		return nil
	}
	if cached, ok := c.markedDirectDialers.Load(mark); ok {
		return cached.(netproxy.Dialer)
	}
	d := protocolDirect.NewDirectDialer(protocolDirect.Option{
		FallbackDNS: c.fallbackResolver,
		Mptcp:       c.mptcp,
		Mark:        int(mark),
	})
	actual, _ := c.markedDirectDialers.LoadOrStore(mark, d)
	return actual.(netproxy.Dialer)
}
