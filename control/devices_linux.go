// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/macaddr"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var _ plugin.DeviceService = (*Runtime)(nil)

func (r *Runtime) deviceNetlink(ctx context.Context) (clientNetlink, func(), error) {
	if err := ctx.Err(); err != nil {
		return clientNetlink{}, nil, err
	}
	if r.clientNetlink != nil {
		return *r.clientNetlink, func() {}, nil
	}
	owner, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return clientNetlink{}, nil, err
	}
	// Private handles do not inherit the global query timeout.
	if err := owner.SetSocketTimeout(netlink.GetSocketTimeout()); err != nil {
		owner.Close()
		return clientNetlink{}, nil, err
	}
	// Close clears owner.sockets; queries use a copy to avoid races and global-socket fallback.
	reader := *owner
	closeOnce := sync.OnceFunc(owner.Close)
	stop := context.AfterFunc(ctx, closeOnce)
	return clientNetlink{reader.LinkList, reader.RouteGetWithOptions, reader.NeighList, lookupClientNeighbor}, func() {
		stop()
		closeOnce()
	}, nil
}

// lanClientLinks uses attached LAN ingress links and their upper receive topology, not routes.
func (r *Runtime) lanClientLinks(n clientNetlink) ([]netlink.Link, map[int]bool, error) {
	r.kernelLinks.mu.Lock()
	var ingress []int
	for _, attached := range r.kernelLinks.hostTCXLinks {
		if attached.role == hostTCXLanIngress {
			ingress = append(ingress, attached.linkIndex)
		}
	}
	r.kernelLinks.mu.Unlock()
	if len(ingress) == 0 {
		return nil, nil, nil
	}
	links, err := n.links()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve LAN device topology: %w", err)
	}
	topology := make(map[int]bool)
	for _, index := range ingress {
		for upper := range clientReceiveTopology(links, index) {
			topology[upper] = true
		}
	}
	return links, topology, nil
}

// Identify validates peers without changing the routing MAC or trusting a downstream router as the client.
func (r *Runtime) Identify(ctx context.Context, source netip.Addr, mac [6]byte) [6]byte {
	if ctx.Err() != nil || !macaddr.ValidClient(mac) {
		return [6]byte{}
	}
	plane := r.admitWorkerPlane()
	if plane == nil {
		return [6]byte{}
	}
	defer plane.workerRoundTrips.Done()
	n, cleanup, err := r.deviceNetlink(ctx)
	if err != nil {
		return [6]byte{}
	}
	defer cleanup()
	links, topology, err := r.lanClientLinks(n)
	if err != nil || len(topology) == 0 || ctx.Err() != nil {
		return [6]byte{}
	}
	scope := 0
	if source.Zone() != "" {
		scope = clientScopeIndex(source.Zone(), links)
		if !topology[scope] {
			return [6]byte{}
		}
	}
	index, err := n.validateMAC(ctx, source, mac, scope)
	if err != nil || !topology[index] || ctx.Err() != nil {
		return [6]byte{}
	}
	return mac
}

// MITMEnabled reads the current generation and published policy.
// Netlink queries hold a retirement lease, not Runtime.mu.
func (r *Runtime) MITMEnabled(ctx context.Context) (enabled [][6]byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	defer func() {
		if ctxErr := ctx.Err(); ctxErr != nil {
			enabled, err = nil, ctxErr
		}
	}()
	plane := r.admitWorkerPlane()
	if plane == nil {
		return nil, net.ErrClosed
	}
	defer plane.workerRoundTrips.Done()
	if !plane.mitmEnabled || plane.mitmAuthority() == nil {
		return nil, nil
	}
	plane.httpClients.mu.RLock()
	policy := plane.httpClients.policy
	plane.httpClients.mu.RUnlock()
	if policy == nil {
		return nil, nil
	}
	candidates := make(map[[6]byte][]netip.Addr)
	for _, entry := range policy.Entries() {
		if macaddr.ValidClient(entry.MAC) {
			candidates[entry.MAC] = nil
		}
	}
	// Routing rules and published clientsets provide candidate identities, not authorization.
	if state := plane.routingState; state != nil {
		state.rulesMu.RLock()
		for _, match := range state.matches {
			if consts.MatchType(match.Type) != consts.MatchType_Mac {
				continue
			}
			index := binary.LittleEndian.Uint32(match.Value[:])
			for _, prefix := range state.simulatedLpmTries[index] {
				address := prefix.Addr().As16()
				mac := [6]byte(address[10:])
				if macaddr.ValidClient(mac) {
					candidates[mac] = nil
				}
			}
		}
		state.rulesMu.RUnlock()
	}
	n, cleanup, err := r.deviceNetlink(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	_, topology, err := r.lanClientLinks(n)
	if err != nil {
		return nil, err
	}
	for index := range topology {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		neighbors, err := n.neighbors(index, netlink.FAMILY_ALL)
		if err != nil {
			return nil, fmt.Errorf("read LAN device neighbors on interface %d: %w", index, err)
		}
		for _, neighbor := range neighbors {
			ip, ok := netip.AddrFromSlice(neighbor.IP)
			if !ok || ip.IsLoopback() || (!ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast()) || len(neighbor.HardwareAddr) != 6 {
				continue
			}
			mac := [6]byte(neighbor.HardwareAddr)
			if !macaddr.ValidClient(mac) || validateClientNeighbor(ip, mac, &neighbor) != nil {
				continue
			}
			ip = ip.Unmap()
			if ip.Is6() && ip.IsLinkLocalUnicast() {
				ip = ip.WithZone(strconv.Itoa(index))
			}
			candidates[mac] = append(candidates[mac], ip)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for mac, addresses := range candidates {
		allowed := len(addresses) == 0 && policy.AllowsMAC(mac)
		for _, ip := range addresses {
			if selected, _ := policy.Match(ip, mac); selected {
				allowed = true
				break
			}
		}
		if allowed {
			enabled = append(enabled, mac)
		}
	}
	slices.SortFunc(enabled, func(a, b [6]byte) int { return slices.Compare(a[:], b[:]) })
	return enabled, nil
}
