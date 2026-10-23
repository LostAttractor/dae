// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	protocolDirect "github.com/daeuniverse/dae/pkg/outbound/protocol/direct"
)

type DialOption struct {
	DeviceMAC         [6]byte
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

// selectRoutedAddress is shared by HTTP targets and internal DNS transports.
// Match destination transformations once, then flow/routing with the caller's
// original identity. Daemon requests supply an unspecified source address.
func (c *ControlPlane) selectRoutedAddress(ctx context.Context, network string, source netip.AddrPort, identity routingResult, domain string, address netip.AddrPort) (*DialOption, error) {
	return c.selectAddress(ctx, network, source, identity, domain, address, nil)
}

func (c *ControlPlane) selectAddress(ctx context.Context, network string, source netip.AddrPort, identity routingResult, domain string, address netip.AddrPort, outboundOverride *consts.OutboundIndex) (*DialOption, error) {
	if !source.IsValid() {
		ip := netip.IPv6Unspecified()
		if address.Addr().Is4() {
			ip = netip.IPv4Unspecified()
		}
		source = netip.AddrPortFrom(ip, 0)
	}
	proto := consts.L4ProtoStr_TCP
	if network == "udp" {
		proto = consts.L4ProtoStr_UDP
	}
	param := &RouteParam{Src: source, Dest: address, Domain: domain, explicitTarget: true, routingResult: &identity, networkType: common.NetworkType{L4Proto: proto, IpVersion: consts.IpVersionStrFromAddr(address.Addr())}}
	param.outboundOverride = outboundOverride
	var err error
	param.destination, err = c.routingMatcher.matchDestination(param)
	if err != nil {
		return nil, err
	}
	return c.routeDestination(ctx, param, domain)
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

// routeBlocked is a decision to drop a flow, by a block rule or by the
// no-connectivity behavior of the unavailable original group.
type routeBlocked struct{ original *outbound.DialerGroup }

func (e *routeBlocked) Error() string {
	if e.original != nil {
		return fmt.Sprintf("outbound %q has no usable node; no_connectivity_behavior blocks the flow", e.original.Name)
	}
	return "blocked by routing"
}

// servingOutbound applies no_connectivity_behavior to a decision using the
// connectivity the groups publish to the kernel, which diagnostics and
// skip_while_noalive share. A name target can use either address family.
func servingOutbound(outbound consts.OutboundIndex, network common.NetworkType, name bool, behavior consts.OutboundIndex, usable func(uint8, consts.L4ProtoType, consts.IpVersionType) bool) consts.OutboundIndex {
	if outbound < consts.OutboundUserDefinedMin || outbound > consts.OutboundUserDefinedMax {
		return outbound
	}
	proto, family := network.L4Proto.ToL4ProtoType(), network.IpVersion.ToIpVersionType()
	if usable(uint8(outbound), proto, family) || name && usable(uint8(outbound), proto, consts.IpVersion_X-family) {
		return outbound
	}
	return behavior
}

// dialsName reports whether a connection allowed to override its dial target
// dials its sniffed name. Only a proxy receives the name, to resolve it
// remotely. A direct connection dials the address the client chose, so the
// client selects its address family and every address it tries is routed. UDP
// relays keep IPs: sniffed QUIC hostnames break full-cone reply addressing. An
// explicit destination always applies.
func (c *ControlPlane) dialsName(override bool, outbound consts.OutboundIndex, l4proto consts.L4ProtoType, name string, explicit bool) bool {
	return override && !explicit && outbound != consts.OutboundDirect && l4proto != consts.L4ProtoType_UDP && !c.useDNSAddress(name)
}

// selectDialOption selects a node of the routed group for the dial target's
// family, waiting within ctx while the group elects one. A group with no
// usable node degrades by no_connectivity_behavior; an explicit HTTP policy
// never degrades. A request whose context ended fails instead.
func (c *ControlPlane) selectDialOption(ctx context.Context, p *RouteParam, outboundIndex consts.OutboundIndex, mark uint32, override bool) (*DialOption, error) {
	if int(outboundIndex) >= len(c.outbounds) {
		if len(c.outbounds) == int(consts.OutboundUserDefinedMin) {
			return nil, fmt.Errorf("traffic was dropped due to no-load configuration")
		}
		return nil, fmt.Errorf("outbound id from bpf is out of range: %v not in [0, %v]", outboundIndex, len(c.outbounds)-1)
	}
	if outboundIndex == consts.OutboundBlock {
		return nil, &routeBlocked{}
	}
	override = c.dialsName(override, outboundIndex, p.networkType.L4Proto.ToL4ProtoType(), p.Domain, p.destination.IsValid())
	target := func(override bool) (string, common.NetworkType, bool) {
		dialTarget := p.dialTarget(override)
		networkType := p.networkType
		address, err := netip.ParseAddrPort(dialTarget)
		if err == nil {
			networkType.IpVersion = consts.IpVersionStrFromAddr(address.Addr())
		}
		return dialTarget, networkType, err == nil
	}
	dialTarget, networkType, ip := target(override)
	group := c.outbounds[outboundIndex]
	selection, err := group.SelectConnection(ctx, networkType, ip)
	var original *outbound.DialerGroup
	if errors.Is(err, outbound.ErrNoAliveDialer) && p.outboundOverride == nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Fallback connections belong to the original group's policies.
		original, outboundIndex = group, c.noConnectivityOutbound
		if outboundIndex == consts.OutboundBlock {
			return nil, &routeBlocked{original: original}
		}
		dialTarget, networkType, _ = target(false)
		group = c.outbounds[outboundIndex]
		selection.Network, selection.Lease = networkType, original.FallbackLease(networkType)
		selection.Dialer, err = group.Select(ctx, &selection.Network)
	}
	if err != nil {
		if p.outboundOverride != nil {
			return nil, fmt.Errorf("select HTTP policy %q: %w", group.Name, err)
		}
		return nil, fmt.Errorf("select outbound %q: %w", group.Name, err)
	}
	return &DialOption{
		DeviceMAC:         p.routingResult.Mac,
		Mark:              mark,
		DialTarget:        dialTarget,
		Dialer:            selection.Dialer,
		connectionDialer:  c.directDialerForMark(outboundIndex, mark),
		Outbound:          group,
		OriginalOutbound:  original,
		NetworkType:       selection.Network,
		Direct:            outboundIndex == consts.OutboundDirect,
		FallbackIpVersion: selection.Network.IpVersion != networkType.IpVersion,
		PolicyLease:       selection.Lease,
	}, nil
}

// outboundAvailable reports the connectivity the group last published to
// every routing projection, including the kernel's. Unknown network masks
// conservatively remain usable.
func (c *ControlPlane) outboundAvailable(id uint8, l4proto consts.L4ProtoType, ipVersion consts.IpVersionType) bool {
	if int(id) >= len(c.outbounds) {
		return true
	}
	var network common.NetworkType
	switch {
	case l4proto&consts.L4ProtoType_TCP != 0:
		network.L4Proto = consts.L4ProtoStr_TCP
	case l4proto&consts.L4ProtoType_UDP != 0:
		network.L4Proto = consts.L4ProtoStr_UDP
	default:
		return true
	}
	switch {
	case ipVersion&consts.IpVersion_4 != 0:
		network.IpVersion = consts.IpVersionStr_4
	case ipVersion&consts.IpVersion_6 != 0:
		network.IpVersion = consts.IpVersionStr_6
	default:
		return true
	}
	return c.outbounds[id].Available(network)
}

func (c *ControlPlane) directDialerForMark(outboundIndex consts.OutboundIndex, mark uint32) netproxy.Dialer {
	if outboundIndex != consts.OutboundDirect || mark == 0 || mark == c.soMarkFromDae {
		return nil
	}
	if cached, ok := c.markedDirectDialers.Load(mark); ok {
		return cached.(netproxy.Dialer)
	}
	d := protocolDirect.NewDirectDialer(protocolDirect.Option{
		Resolver: net.DefaultResolver,
		Mptcp:    c.mptcp,
		Mark:     int(mark),
	})
	actual, _ := c.markedDirectDialers.LoadOrStore(mark, d)
	return actual.(netproxy.Dialer)
}
