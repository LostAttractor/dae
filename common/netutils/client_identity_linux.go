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
	var scope int
	if zone := source.Zone(); zone != "" {
		iface, err := net.InterfaceByName(zone)
		if err == nil {
			scope = iface.Index
		} else if scope, err = strconv.Atoi(zone); err != nil || scope <= 0 {
			return fmt.Errorf("unknown client interface zone %q", zone)
		}
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
