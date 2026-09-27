// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"net"
	"net/netip"
	"strconv"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func (p *PathSpec) availableEntryFamilies(ctx context.Context, option *dialer.GlobalOption, usable func(netip.Addr, uint32, string) bool) (uint8, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	host := entryHostname(p.Nodes[0].Property.Address)
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{ip}
	} else {
		resolver, err := p.entryResolver(option)
		if err != nil {
			return 0, err
		}
		ctx, cancel := netproxy.NewDialTimeoutContextFrom(ctx)
		defer cancel()
		addresses, err = resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return 0, err
		}
	}
	var families uint8
	for _, address := range addresses {
		address = address.Unmap()
		family := family6
		if address.Is4() {
			family = family4
		}
		if families&family == 0 && usable(address, p.effectiveMark(option), p.Entry.Interface) {
			families |= family
		}
	}
	return families, nil
}

// Query the kernel with the same mark and bound interface as the entry socket.
// A default IPv6 route or ::1 alone does not establish usable IPv6 on a WAN.
// This performs no remote connection attempt; health checks test the proxy later.
func entryAddressUsable(address netip.Addr, mark uint32, iface string) bool {
	options := &netlink.RouteGetOptions{Mark: mark, Oif: iface}
	if address.Zone() != "" {
		// Go accepts either an interface name or a numeric scope ID in a zone.
		index := 0
		if link, err := netlink.LinkByName(address.Zone()); err == nil {
			index = link.Attrs().Index
		} else {
			index, _ = strconv.Atoi(address.Zone())
		}
		if index <= 0 {
			return false
		}
		if iface != "" {
			link, err := netlink.LinkByName(iface)
			if err != nil || link.Attrs().Index != index {
				return false
			}
		}
		options.Oif, options.OifIndex = "", index
	}
	routes, err := netlink.RouteGetWithOptions(net.IP(address.AsSlice()), options)
	if err != nil {
		return false
	}
	for _, route := range routes {
		if route.Type != unix.RTN_UNICAST && route.Type != unix.RTN_LOCAL {
			continue
		}
		source, ok := netip.AddrFromSlice(route.Src)
		source = source.Unmap()
		if !ok || source.IsUnspecified() || source.Is4() != address.Is4() || address.IsGlobalUnicast() && !source.IsGlobalUnicast() {
			continue
		}
		link, err := netlink.LinkByIndex(route.LinkIndex)
		if err != nil || link.Attrs().Flags&net.FlagUp == 0 {
			continue
		}
		if options.Oif != "" && link.Attrs().Name != options.Oif || options.OifIndex != 0 && link.Attrs().Index != options.OifIndex {
			continue
		}
		if route.Type == unix.RTN_LOCAL && options.Oif == "" && options.OifIndex == 0 {
			return true
		}
		family := netlink.FAMILY_V6
		if address.Is4() {
			family = netlink.FAMILY_V4
		}
		assigned, err := netlink.AddrList(link, family)
		if err != nil {
			continue
		}
		for _, addr := range assigned {
			if addr.IP.Equal(route.Src) && addr.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) == 0 {
				return true
			}
		}
	}
	return false
}
