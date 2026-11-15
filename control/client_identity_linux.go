// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/daeuniverse/dae/common/macaddr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// validateLANClientScope binds scoped TCP endpoints to the observed LAN ingress.
// A tuple's numeric IPv6 addresses alone cannot distinguish different links.
func validateLANClientScope(source, destination netip.Addr, ingress int) error {
	return validateClientScope(source, destination, ingress, netlink.LinkList)
}

func validateClientScope(source, destination netip.Addr, ingress int, listLinks func() ([]netlink.Link, error)) error {
	var topology map[int]bool
	var links []netlink.Link
	for _, address := range []netip.Addr{source, destination} {
		if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
			return fmt.Errorf("invalid LAN connection address")
		}
		if !address.Is6() || !address.IsLinkLocalUnicast() {
			continue
		}
		if topology == nil {
			var err error
			links, err = listLinks()
			if err != nil {
				return fmt.Errorf("resolve LAN scope topology: %w", err)
			}
			topology = clientReceiveTopology(links, ingress)
		}
		// Both endpoints resolve names and reachability against one link snapshot.
		scope := clientScopeIndex(address.Zone(), links)
		if scope <= 0 {
			return fmt.Errorf("link-local connection requires a valid interface zone")
		}
		if !topology[scope] {
			return fmt.Errorf("connection scope does not belong to the observed LAN ingress")
		}
	}
	return nil
}

func clientScopeIndex(zone string, links []netlink.Link) int {
	for _, link := range links {
		if link.Attrs().Name == zone {
			return link.Attrs().Index
		}
	}
	scope, _ := strconv.Atoi(zone)
	return scope
}

func clientReceiveTopology(links []netlink.Link, ingress int) map[int]bool {
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
	return seen
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

// validateLANClientMAC checks a connection's observed source MAC against its direct
// L3 neighbor. LAN authorization belongs to the ingress hook; the route device
// may instead be a bridge or bond. Other interfaces' neighbors are irrelevant.
func validateLANClientMAC(source netip.Addr, mac [6]byte) error {
	scope, err := clientZone(source.Zone())
	if err != nil {
		return err
	}
	_, err = systemClientNetlink.validateMAC(context.Background(), source, mac, scope)
	return err
}

type clientNetlink struct {
	links     func() ([]netlink.Link, error)
	routes    func(net.IP, *netlink.RouteGetOptions) ([]netlink.Route, error)
	neighbors func(int, int) ([]netlink.Neigh, error)
	neighbor  func(context.Context, int, netip.Addr) (*netlink.Neigh, error)
}

var systemClientNetlink = clientNetlink{netlink.LinkList, netlink.RouteGetWithOptions, netlink.NeighList, lookupClientNeighbor}

func (n clientNetlink) validateMAC(ctx context.Context, source netip.Addr, mac [6]byte, scope int) (int, error) {
	source = source.Unmap()
	if !source.IsValid() || source.IsLoopback() ||
		(!source.IsGlobalUnicast() && !source.IsLinkLocalUnicast()) ||
		!macaddr.ValidClient(mac) {
		return 0, fmt.Errorf("client is not a unicast Ethernet peer")
	}
	if source.Is6() && source.IsLinkLocalUnicast() && scope <= 0 {
		return 0, fmt.Errorf("link-local client address requires an interface zone")
	}
	routes, err := n.routes(source.AsSlice(), &netlink.RouteGetOptions{OifIndex: scope})
	if err != nil {
		return 0, fmt.Errorf("resolve client route: %w", err)
	}
	linkIndex, err := directClientLink(routes, scope)
	if err != nil {
		return 0, err
	}
	neighbor, err := n.neighbor(ctx, linkIndex, source)
	if err != nil {
		return 0, fmt.Errorf("read client neighbor: %w", err)
	}
	if err := validateClientNeighbor(source, mac, neighbor); err != nil {
		return 0, err
	}
	return linkIndex, nil
}

// The high-level NeighList API requests a dump even when an interface is specified.
func lookupClientNeighbor(ctx context.Context, index int, source netip.Addr) (*netlink.Neigh, error) {
	socket, err := nl.GetNetlinkSocketAt(-1, -1, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	return queryClientNeighbor(ctx, socket, index, source)
}

func queryClientNeighbor(ctx context.Context, socket *nl.NetlinkSocket, index int, source netip.Addr) (*netlink.Neigh, error) {
	defer socket.Close()
	ctx, cancel := context.WithTimeout(ctx, netlink.GetSocketTimeout())
	defer cancel()
	stop := context.AfterFunc(ctx, socket.Close)
	defer stop()
	family := unix.AF_INET6
	if source.Is4() {
		family = unix.AF_INET
	}
	header := &netlink.Ndmsg{Family: uint8(family), Index: uint32(index)}
	req := nl.NewNetlinkRequest(unix.RTM_GETNEIGH, 0)
	req.Sockets = map[int]*nl.SocketHandle{unix.NETLINK_ROUTE: {Socket: socket}}
	req.AddData(header)
	req.AddData(nl.NewRtAttr(netlink.NDA_DST, source.AsSlice()))
	replies, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWNEIGH)
	if err != nil {
		return nil, err
	}
	if len(replies) != 1 || len(replies[0]) < header.Len() {
		return nil, fmt.Errorf("expected a single neighbor reply")
	}
	neighbor, err := netlink.NeighDeserialize(replies[0])
	if err == nil && (neighbor.LinkIndex != index || neighbor.Family != family) {
		return nil, fmt.Errorf("neighbor is not on the direct route")
	}
	return neighbor, err
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
func validateClientNeighbor(source netip.Addr, mac [6]byte, neighbor *netlink.Neigh) error {
	if neighbor == nil || !neighbor.IP.Equal(source.AsSlice()) {
		return fmt.Errorf("client has no neighbor on its direct route")
	}
	const resolved = netlink.NUD_REACHABLE | netlink.NUD_STALE | netlink.NUD_DELAY | netlink.NUD_PROBE | netlink.NUD_PERMANENT
	if neighbor.State&resolved == 0 || neighbor.State&(netlink.NUD_FAILED|netlink.NUD_INCOMPLETE) != 0 ||
		neighbor.Flags&netlink.NTF_PROXY != 0 || !bytes.Equal(neighbor.HardwareAddr, mac[:]) {
		return fmt.Errorf("client neighbor does not match the connection's unicast MAC")
	}
	return nil
}
