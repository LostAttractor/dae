// SPDX-License-Identifier: AGPL-3.0-only

package netutils

import (
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestValidateClientMACRejectsInvalidPeers(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	for _, source := range []string{"", "127.0.0.1", "::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1%lo", "255.255.255.255", "fe80::1", "fe80::1%missing-dae-test-interface", "fe80::1%0", "fe80::1%2147483647"} {
		t.Run(source, func(t *testing.T) {
			addr, _ := netip.ParseAddr(source)
			if err := ValidateClientMAC(addr, mac); err == nil {
				t.Fatal("accepted invalid client address")
			}
		})
	}
	for _, mac := range [][6]byte{{}, {1, 0, 0, 0, 0, 1}} {
		if err := ValidateClientMAC(netip.MustParseAddr("192.0.2.23"), mac); err == nil {
			t.Fatal("accepted a non-unicast MAC")
		}
	}
}

func TestDirectClientLink(t *testing.T) {
	const index = 9
	direct := netlink.Route{LinkIndex: index, Type: unix.RTN_UNICAST}
	changed := func(change func(*netlink.Route)) []netlink.Route {
		route := direct
		change(&route)
		return []netlink.Route{route}
	}
	for _, test := range []struct {
		name   string
		routes []netlink.Route
		scope  int
		want   bool
	}{
		{"bridge or bond L3 route", []netlink.Route{direct}, 0, true},
		{"IPv6 scoped route", []netlink.Route{direct}, index, true},
		{"wrong IPv6 scope", []netlink.Route{direct}, 10, false},
		{"router address", changed(func(r *netlink.Route) { r.Type = unix.RTN_LOCAL }), 0, false},
		{"broadcast", changed(func(r *netlink.Route) { r.Type = unix.RTN_BROADCAST }), 0, false},
		{"missing interface", changed(func(r *netlink.Route) { r.LinkIndex = 0 }), 0, false},
		{"gateway", changed(func(r *netlink.Route) { r.Gw = net.ParseIP("192.0.2.1") }), 0, false},
		{"via", changed(func(r *netlink.Route) { r.Via = &netlink.Via{Addr: net.ParseIP("192.0.2.1")} }), 0, false},
		{"multipath", changed(func(r *netlink.Route) { r.MultiPath = []*netlink.NexthopInfo{{LinkIndex: 10}} }), 0, false},
		{"encapsulation", changed(func(r *netlink.Route) { r.Encap = &netlink.MPLSEncap{Labels: []int{100}} }), 0, false},
		{"new destination", changed(func(r *netlink.Route) { r.NewDst = &netlink.MPLSDestination{Labels: []int{100}} }), 0, false},
		{"missing route", nil, 0, false},
		{"multiple routes", []netlink.Route{direct, {LinkIndex: 10, Type: unix.RTN_UNICAST}}, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := directClientLink(test.routes, test.scope)
			if (err == nil) != test.want || test.want && got != index {
				t.Fatalf("link = %d, error = %v, want accepted = %v", got, err, test.want)
			}
		})
	}
}

func TestValidateClientNeighbor(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	for _, text := range []string{"192.0.2.23", "::ffff:192.0.2.23", "2001:db8::23", "fe80::23%br-lan"} {
		t.Run(text, func(t *testing.T) {
			source := netip.MustParseAddr(text)
			good := netlink.Neigh{IP: source.Unmap().AsSlice(), State: netlink.NUD_REACHABLE, HardwareAddr: net.HardwareAddr(mac[:])}
			changed := func(change func(*netlink.Neigh)) netlink.Neigh {
				neighbor := good
				change(&neighbor)
				return neighbor
			}
			for _, test := range []struct {
				name     string
				neighbor netlink.Neigh
				want     bool
			}{
				{"reachable", good, true},
				{"stale after idle", changed(func(n *netlink.Neigh) { n.State = netlink.NUD_STALE }), true},
				{"delay", changed(func(n *netlink.Neigh) { n.State = netlink.NUD_DELAY }), true},
				{"probe", changed(func(n *netlink.Neigh) { n.State = netlink.NUD_PROBE }), true},
				{"static", changed(func(n *netlink.Neigh) { n.State = netlink.NUD_PERMANENT }), true},
				{"failed", changed(func(n *netlink.Neigh) { n.State = netlink.NUD_FAILED }), false},
				{"incomplete", changed(func(n *netlink.Neigh) { n.State = netlink.NUD_INCOMPLETE }), false},
				{"failed overrides resolved", changed(func(n *netlink.Neigh) { n.State |= netlink.NUD_FAILED }), false},
				{"no state", changed(func(n *netlink.Neigh) { n.State = netlink.NUD_NONE }), false},
				{"proxy", changed(func(n *netlink.Neigh) { n.Flags = netlink.NTF_PROXY }), false},
				{"different MAC", changed(func(n *netlink.Neigh) { n.HardwareAddr = net.HardwareAddr{2, 0, 0, 0, 0, 2} }), false},
				{"missing MAC", changed(func(n *netlink.Neigh) { n.HardwareAddr = nil }), false},
				{"missing IP", changed(func(n *netlink.Neigh) { n.IP = nil }), false},
				{"different IP", changed(func(n *netlink.Neigh) { n.IP = net.ParseIP("192.0.2.24") }), false},
			} {
				t.Run(test.name, func(t *testing.T) {
					err := validateClientNeighbor(source, mac, []netlink.Neigh{test.neighbor})
					if (err == nil) != test.want {
						t.Fatalf("error = %v, want accepted = %v", err, test.want)
					}
				})
			}
			if err := validateClientNeighbor(source, mac, nil); err == nil {
				t.Fatal("accepted missing neighbor")
			}
		})
	}
}
