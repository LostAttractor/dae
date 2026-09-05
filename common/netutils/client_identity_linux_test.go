// SPDX-License-Identifier: AGPL-3.0-only

package netutils

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestResolveClientMACRejectsInvalidPeers(t *testing.T) {
	for _, source := range []string{"", "127.0.0.1", "::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1%lo", "255.255.255.255", "fe80::1", "fe80::1%missing-dae-test-interface"} {
		t.Run(source, func(t *testing.T) {
			addr, _ := netip.ParseAddr(source)
			if _, err := ResolveClientMAC(addr, []string{"*"}); err == nil {
				t.Fatal("accepted invalid client address")
			}
		})
	}
	for _, interfaces := range [][]string{nil, {"missing-dae-test-interface"}} {
		if _, err := ResolveClientMAC(netip.MustParseAddr("192.0.2.23"), interfaces); err == nil || !strings.Contains(err.Error(), "global.lan_interface") {
			t.Fatalf("unconfigured LAN: %v", err)
		}
	}
}

func TestSelectClientMAC(t *testing.T) {
	const bridgeIndex = 9
	source := netip.MustParseAddr("192.0.2.23")
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	otherMAC := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	route := netlink.Route{LinkIndex: bridgeIndex, Type: unix.RTN_UNICAST}
	neighbor := func(index, state int, hardware net.HardwareAddr) netlink.Neigh {
		return netlink.Neigh{LinkIndex: index, State: state, IP: source.AsSlice(), HardwareAddr: hardware}
	}
	good := neighbor(bridgeIndex, netlink.NUD_REACHABLE, mac)
	tests := []struct {
		name      string
		routes    []netlink.Route
		addresses []netlink.Addr
		neighbors []netlink.Neigh
		want      bool
	}{
		{name: "bridge L3 neighbor", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{good}, want: true},
		{name: "WAN direct neighbor", routes: []netlink.Route{{LinkIndex: 10, Type: unix.RTN_UNICAST}}, neighbors: []netlink.Neigh{neighbor(10, netlink.NUD_REACHABLE, mac)}},
		{name: "WAN route with matching LAN MAC", routes: []netlink.Route{{LinkIndex: 10, Type: unix.RTN_UNICAST}}, neighbors: []netlink.Neigh{good, neighbor(10, netlink.NUD_REACHABLE, mac)}},
		{name: "stale after idle", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{neighbor(bridgeIndex, netlink.NUD_STALE, mac)}, want: true},
		{name: "delay", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{neighbor(bridgeIndex, netlink.NUD_DELAY, mac)}, want: true},
		{name: "probe with known MAC", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{neighbor(bridgeIndex, netlink.NUD_PROBE, mac)}, want: true},
		{name: "static neighbor", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{neighbor(bridgeIndex, netlink.NUD_PERMANENT, mac)}, want: true},
		{name: "same MAC on two interfaces", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{good, neighbor(10, netlink.NUD_REACHABLE, mac)}, want: true},
		{name: "local assigned address", routes: []netlink.Route{route}, addresses: []netlink.Addr{{IPNet: &net.IPNet{IP: source.AsSlice(), Mask: net.CIDRMask(24, 32)}, LinkIndex: bridgeIndex}}, neighbors: []netlink.Neigh{good}},
		{name: "local route", routes: []netlink.Route{{LinkIndex: bridgeIndex, Type: unix.RTN_LOCAL}}, neighbors: []netlink.Neigh{good}},
		{name: "broadcast route", routes: []netlink.Route{{LinkIndex: bridgeIndex, Type: unix.RTN_BROADCAST}}, neighbors: []netlink.Neigh{good}},
		{name: "via gateway", routes: []netlink.Route{{LinkIndex: bridgeIndex, Type: unix.RTN_UNICAST, Gw: net.ParseIP("192.0.2.1")}}, neighbors: []netlink.Neigh{good}},
		{name: "multipath route", routes: []netlink.Route{{LinkIndex: bridgeIndex, Type: unix.RTN_UNICAST, MultiPath: []*netlink.NexthopInfo{{LinkIndex: 10}}}}, neighbors: []netlink.Neigh{good}},
		{name: "ambiguous route", routes: []netlink.Route{route, {LinkIndex: 10, Type: unix.RTN_UNICAST}}, neighbors: []netlink.Neigh{good}},
		{name: "missing route", neighbors: []netlink.Neigh{good}},
		{name: "missing neighbor", routes: []netlink.Route{route}},
		{name: "neighbor on wrong interface", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{neighbor(10, netlink.NUD_REACHABLE, mac)}},
		{name: "failed neighbor", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{neighbor(bridgeIndex, netlink.NUD_FAILED, mac)}},
		{name: "incomplete neighbor", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{neighbor(bridgeIndex, netlink.NUD_INCOMPLETE, mac)}},
		{name: "failed overrides resolved bit", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{neighbor(bridgeIndex, netlink.NUD_FAILED|netlink.NUD_REACHABLE, mac)}},
		{name: "no neighbor state", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{neighbor(bridgeIndex, netlink.NUD_NONE, mac)}},
		{name: "empty MAC", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{neighbor(bridgeIndex, netlink.NUD_REACHABLE, make(net.HardwareAddr, 6))}},
		{name: "multicast MAC", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{neighbor(bridgeIndex, netlink.NUD_REACHABLE, net.HardwareAddr{1, 0, 0, 0, 0, 1})}},
		{name: "missing MAC", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{neighbor(bridgeIndex, netlink.NUD_REACHABLE, nil)}},
		{name: "non Ethernet MAC", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{neighbor(bridgeIndex, netlink.NUD_REACHABLE, net.HardwareAddr{2, 0, 0, 0, 0, 1, 0, 0})}},
		{name: "ambiguous MAC", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{good, neighbor(bridgeIndex, netlink.NUD_REACHABLE, otherMAC)}},
		{name: "ambiguous global IP across interfaces", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{good, neighbor(10, netlink.NUD_REACHABLE, otherMAC)}},
		{name: "proxy neighbor", routes: []netlink.Route{route}, neighbors: []netlink.Neigh{{LinkIndex: bridgeIndex, State: netlink.NUD_REACHABLE, Flags: netlink.NTF_PROXY, IP: source.AsSlice(), HardwareAddr: mac}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := selectClientMAC(source, 0, test.addresses, test.routes, test.neighbors, map[int]bool{bridgeIndex: true})
			if (err == nil) != test.want {
				t.Fatalf("MAC = %v, err = %v, want accepted = %v", got, err, test.want)
			}
			if test.want && got != [6]byte(mac) {
				t.Fatalf("MAC = %v, want %v", got, mac)
			}
		})
	}

	t.Run("IPv4 mapped peer", func(t *testing.T) {
		got, err := selectClientMAC(netip.MustParseAddr("::ffff:192.0.2.23"), 0, nil, []netlink.Route{route}, []netlink.Neigh{good}, map[int]bool{bridgeIndex: true})
		if err != nil || got != [6]byte(mac) {
			t.Fatalf("MAC = %v, err = %v", got, err)
		}
	})
}

func TestSelectClientMACScopesLinkLocalIPv6(t *testing.T) {
	source := netip.MustParseAddr("fe80::23%lan0")
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	routes := []netlink.Route{{LinkIndex: 9, Type: unix.RTN_UNICAST}}
	neighbors := []netlink.Neigh{
		{LinkIndex: 10, State: netlink.NUD_REACHABLE, IP: source.AsSlice(), HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 2}},
		{LinkIndex: 9, State: netlink.NUD_REACHABLE, IP: source.AsSlice(), HardwareAddr: mac},
	}
	// Identical link-local addresses on other links do not identify this peer.
	addresses := []netlink.Addr{{IPNet: &net.IPNet{IP: source.AsSlice(), Mask: net.CIDRMask(64, 128)}, LinkIndex: 10}}
	got, err := selectClientMAC(source, 9, addresses, routes, neighbors, map[int]bool{9: true})
	if err != nil || got != [6]byte(mac) {
		t.Fatalf("MAC = %v, err = %v", got, err)
	}
	if _, err := selectClientMAC(source, 9, nil, routes, neighbors[:1], map[int]bool{9: true}); err == nil {
		t.Fatal("accepted the neighbor from a different link-local scope")
	}
	if _, err := selectClientMAC(source, 10, nil, routes, neighbors, map[int]bool{9: true}); err == nil {
		t.Fatal("accepted a route outside the link-local scope")
	}
	if _, err := selectClientMAC(source, 9, nil, routes, neighbors, map[int]bool{10: true}); err == nil {
		t.Fatal("accepted an IPv6 neighbor outside LAN interfaces")
	}
	addresses[0].LinkIndex = 9
	if _, err := selectClientMAC(source, 9, addresses, routes, neighbors, map[int]bool{9: true}); err == nil {
		t.Fatal("accepted this router's link-local address")
	}
}
