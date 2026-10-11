// SPDX-License-Identifier: AGPL-3.0-only

package netutils

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ValidateClientScope binds scoped TCP endpoints to the observed LAN ingress.
// A tuple's numeric IPv6 addresses alone cannot distinguish different links.
func ValidateClientScope(source, destination netip.Addr, ingress int) error {
	for _, address := range []netip.Addr{source, destination} {
		if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
			return fmt.Errorf("invalid LAN connection address")
		}
		if !address.Is6() || !address.IsLinkLocalUnicast() {
			continue
		}
		scope, err := clientZone(address.Zone())
		if err != nil || scope == 0 {
			return fmt.Errorf("link-local connection requires a valid interface zone")
		}
		links, err := netlink.LinkList()
		if err != nil {
			return fmt.Errorf("resolve LAN scope topology: %w", err)
		}
		if !clientScopeReachable(links, ingress, scope) {
			return fmt.Errorf("connection scope does not belong to the observed LAN ingress")
		}
	}
	return nil
}

// Traverse only the receive direction: port -> master and lower -> VLAN.
// Walking back down to a common parent would incorrectly trust sibling links.
func clientScopeReachable(links []netlink.Link, ingress, scope int) bool {
	byIndex := make(map[int]netlink.Link, len(links))
	for _, link := range links {
		byIndex[link.Attrs().Index] = link
	}
	pending := []int{ingress}
	seen := make(map[int]bool)
	for len(pending) > 0 {
		index := pending[0]
		pending = pending[1:]
		link := byIndex[index]
		if link == nil || seen[index] {
			continue
		}
		if index == scope {
			return true
		}
		seen[index] = true
		if master := link.Attrs().MasterIndex; master != 0 {
			pending = append(pending, master)
		}
		for _, upper := range links {
			if vlan, ok := upper.(*netlink.Vlan); ok && vlan.ParentIndex == index {
				pending = append(pending, vlan.Index)
			}
		}
	}
	return false
}

func clientZone(zone string) (int, error) {
	if zone == "" {
		return 0, nil
	}
	if iface, err := net.InterfaceByName(zone); err == nil {
		return iface.Index, nil
	}
	if scope, err := strconv.Atoi(zone); err == nil && scope > 0 {
		return scope, nil
	}
	return 0, fmt.Errorf("unknown client interface zone %q", zone)
}

// ValidateClientMAC checks a connection's observed source MAC against its direct
// L3 neighbor. LAN authorization belongs to the ingress hook; the route device
// may instead be a bridge or bond. Other interfaces' neighbors are irrelevant.
func ValidateClientMAC(source netip.Addr, mac [6]byte) error {
	source = source.Unmap()
	if !source.IsValid() || source.IsLoopback() ||
		(!source.IsGlobalUnicast() && !source.IsLinkLocalUnicast()) ||
		mac == [6]byte{} || mac[0]&1 != 0 {
		return fmt.Errorf("client is not a unicast Ethernet peer")
	}
	if source.Is6() && source.IsLinkLocalUnicast() && source.Zone() == "" {
		return fmt.Errorf("link-local client address requires an interface zone")
	}
	scope, err := clientZone(source.Zone())
	if err != nil {
		return err
	}
	routes, err := netlink.RouteGetWithOptions(source.AsSlice(), &netlink.RouteGetOptions{OifIndex: scope})
	if err != nil {
		return fmt.Errorf("resolve client route: %w", err)
	}
	linkIndex, err := directClientLink(routes, scope)
	if err != nil {
		return err
	}
	family := netlink.FAMILY_V6
	if source.Is4() {
		family = netlink.FAMILY_V4
	}
	neighbors, err := netlink.NeighList(linkIndex, family)
	if err != nil {
		return fmt.Errorf("read client neighbors: %w", err)
	}
	return validateClientNeighbor(source, mac, neighbors)
}

func directClientLink(routes []netlink.Route, scope int) (int, error) {
	if len(routes) != 1 {
		return 0, fmt.Errorf("client has no unique direct route")
	}
	route := routes[0]
	// RTN_LOCAL also rejects this router's addresses without an address dump.
	if route.Type != unix.RTN_UNICAST || route.LinkIndex <= 0 ||
		(scope != 0 && route.LinkIndex != scope) ||
		(len(route.Gw) != 0 && !route.Gw.IsUnspecified()) || route.Via != nil ||
		len(route.MultiPath) != 0 || route.Encap != nil || route.NewDst != nil {
		return 0, fmt.Errorf("client is not directly connected")
	}
	return route.LinkIndex, nil
}

// Neighbors have already been scoped to the direct route's device and family.
func validateClientNeighbor(source netip.Addr, mac [6]byte, neighbors []netlink.Neigh) error {
	for _, neighbor := range neighbors {
		if !neighbor.IP.Equal(source.AsSlice()) {
			continue
		}
		const resolved = netlink.NUD_REACHABLE | netlink.NUD_STALE | netlink.NUD_DELAY | netlink.NUD_PROBE | netlink.NUD_PERMANENT
		if neighbor.State&resolved == 0 || neighbor.State&(netlink.NUD_FAILED|netlink.NUD_INCOMPLETE) != 0 ||
			neighbor.Flags&netlink.NTF_PROXY != 0 || !bytes.Equal(neighbor.HardwareAddr, mac[:]) {
			return fmt.Errorf("client neighbor does not match the connection's unicast MAC")
		}
		return nil
	}
	return fmt.Errorf("client has no neighbor on its direct route")
}
