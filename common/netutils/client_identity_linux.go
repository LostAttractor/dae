// SPDX-License-Identifier: AGPL-3.0-only

package netutils

import (
	"fmt"
	"net"
	"net/netip"
	"path"
	"strconv"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ResolveClientMAC identifies a directly connected peer on a configured LAN
// interface. It only reads kernel state; the TCP handshake has already resolved
// the peer's ARP/NDP entry. Interface patterns use the same syntax as lan_interface.
func ResolveClientMAC(source netip.Addr, lanInterfaces []string) ([6]byte, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return [6]byte{}, fmt.Errorf("read client interfaces: %w", err)
	}
	lan := make(map[int]bool)
	for _, iface := range interfaces {
		for _, pattern := range lanInterfaces {
			if matched, _ := path.Match(pattern, iface.Name); matched {
				lan[iface.Index] = true
				break
			}
		}
	}
	if len(lan) == 0 {
		return [6]byte{}, fmt.Errorf("device API requires a configured LAN interface (global.lan_interface)")
	}
	source = source.Unmap()
	if !source.IsValid() || source.IsLoopback() ||
		(!source.IsGlobalUnicast() && !source.IsLinkLocalUnicast()) {
		return [6]byte{}, fmt.Errorf("client address is not a unicast peer")
	}
	if source.Is6() && source.IsLinkLocalUnicast() && source.Zone() == "" {
		return [6]byte{}, fmt.Errorf("link-local client address requires an interface zone")
	}
	var scope int
	if zone := source.Zone(); zone != "" {
		iface, err := net.InterfaceByName(zone)
		if err != nil {
			index, parseErr := strconv.Atoi(zone)
			if parseErr != nil || index <= 0 {
				return [6]byte{}, fmt.Errorf("unknown client interface zone %q", zone)
			}
			iface, err = net.InterfaceByIndex(index)
			if err != nil {
				return [6]byte{}, fmt.Errorf("unknown client interface zone %q: %w", zone, err)
			}
		}
		scope = iface.Index
	}
	family := netlink.FAMILY_V6
	if source.Is4() {
		family = netlink.FAMILY_V4
	}
	addresses, err := netlink.AddrList(nil, family)
	if err != nil {
		return [6]byte{}, fmt.Errorf("read local addresses: %w", err)
	}
	routes, err := netlink.RouteGetWithOptions(source.AsSlice(), &netlink.RouteGetOptions{OifIndex: scope})
	if err != nil {
		return [6]byte{}, fmt.Errorf("resolve client route: %w", err)
	}
	// Read all L3 neighbors to detect duplicate global addresses. A link-local
	// address is meaningful only on its supplied interface. AF_BRIDGE entries
	// are forwarding records, not IP identities, and are intentionally excluded.
	neighbors, err := netlink.NeighList(scope, family)
	if err != nil {
		return [6]byte{}, fmt.Errorf("read client neighbors: %w", err)
	}
	return selectClientMAC(source, scope, addresses, routes, neighbors, lan)
}

func selectClientMAC(source netip.Addr, scope int, addresses []netlink.Addr, routes []netlink.Route, neighbors []netlink.Neigh, lan map[int]bool) ([6]byte, error) {
	source = source.Unmap().WithZone("")
	for _, address := range addresses {
		if scope != 0 && address.LinkIndex != scope {
			continue
		}
		if address.IPNet == nil {
			continue
		}
		if ip, ok := netip.AddrFromSlice(address.IP); ok && ip.Unmap() == source {
			return [6]byte{}, fmt.Errorf("client address belongs to this router")
		}
	}
	var linkIndex int
	for _, route := range routes {
		if route.Type != unix.RTN_UNICAST || route.LinkIndex <= 0 ||
			(len(route.Gw) != 0 && !route.Gw.IsUnspecified()) || route.Via != nil ||
			len(route.MultiPath) != 0 || route.Encap != nil || route.NewDst != nil {
			return [6]byte{}, fmt.Errorf("client is not directly connected")
		}
		if (scope != 0 && route.LinkIndex != scope) || (linkIndex != 0 && route.LinkIndex != linkIndex) {
			return [6]byte{}, fmt.Errorf("client route has an ambiguous interface")
		}
		linkIndex = route.LinkIndex
	}
	if linkIndex == 0 {
		return [6]byte{}, fmt.Errorf("client has no direct route")
	}
	if !lan[linkIndex] {
		return [6]byte{}, fmt.Errorf("device API is only available to directly connected clients on global.lan_interface")
	}
	var selected, observed [6]byte
	for _, neighbor := range neighbors {
		if scope != 0 && neighbor.LinkIndex != scope {
			continue
		}
		ip, ok := netip.AddrFromSlice(neighbor.IP)
		if !ok || ip.Unmap() != source {
			continue
		}
		const resolved = netlink.NUD_REACHABLE | netlink.NUD_STALE | netlink.NUD_DELAY | netlink.NUD_PROBE | netlink.NUD_PERMANENT
		if neighbor.LinkIndex <= 0 || neighbor.State&resolved == 0 ||
			neighbor.State&(netlink.NUD_FAILED|netlink.NUD_INCOMPLETE) != 0 ||
			neighbor.Flags&netlink.NTF_PROXY != 0 || len(neighbor.HardwareAddr) != 6 ||
			neighbor.HardwareAddr[0]&1 != 0 {
			if neighbor.LinkIndex == linkIndex {
				return [6]byte{}, fmt.Errorf("client neighbor has no resolved unicast MAC address")
			}
			continue
		}
		mac := [6]byte(neighbor.HardwareAddr)
		if mac == [6]byte{} {
			if neighbor.LinkIndex == linkIndex {
				return [6]byte{}, fmt.Errorf("client neighbor has an empty MAC address")
			}
			continue
		}
		if observed != [6]byte{} && observed != mac {
			return [6]byte{}, fmt.Errorf("client address has multiple MAC addresses")
		}
		observed = mac
		if neighbor.LinkIndex == linkIndex {
			selected = mac
		}
	}
	if selected == [6]byte{} {
		return [6]byte{}, fmt.Errorf("client has no neighbor on its direct route")
	}
	return selected, nil
}
