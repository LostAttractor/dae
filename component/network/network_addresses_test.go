// SPDX-License-Identifier: AGPL-3.0-only

package network

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestHostNetworkSnapshotIncludesLANAddresses(t *testing.T) {
	address := func(value string) netlink.Addr {
		_, prefix, err := net.ParseCIDR(value)
		if err != nil {
			t.Fatal(err)
		}
		return netlink.Addr{IPNet: prefix}
	}
	data := hostNetworkData{
		links:  []netlink.Link{&netlink.Dummy{Index: 2, Name: "lan"}, &netlink.Dummy{Index: 1, Name: "lo"}},
		addrs4: map[int][]netlink.Addr{1: {address("127.0.0.1/32")}, 2: {address("192.0.2.1/32"), address("192.0.2.1/32"), {}}},
		addrs6: map[int][]netlink.Addr{2: {address("2001:db8::1/128")}},
	}
	snapshot := buildHostNetworkSnapshot(data)
	want := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}
	if !slices.Equal(snapshot.LocalAddresses, want) || snapshot.Ready() {
		t.Fatalf("LAN addresses without default routes: %+v", snapshot)
	}
	slices.Reverse(data.links)
	if !snapshot.Equal(buildHostNetworkSnapshot(data)) {
		t.Fatal("link ordering changed the address snapshot")
	}
}

func TestHostAddressChangeNotifiesWithoutConnectivityProbe(t *testing.T) {
	next := HostNetworkSnapshot{
		Interfaces:     []DefaultRouteInterface{{Index: 1, IPv4Default: true, IPv4Source: "192.0.2.1"}},
		LocalAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
	}
	monitor := &HostNetworkMonitor{snapshotFn: func() (HostNetworkSnapshot, error) { return next, nil }}
	if err := monitor.reconcile(); err != nil {
		t.Fatal(err)
	}
	called := 0
	monitor.Register(func(previous, current HostNetworkSnapshot) {
		called++
		if current.Equal(previous) || current.ConnectivityChanged(previous) {
			t.Fatal("address-only changes must notify without rechecking outbound connectivity")
		}
	})
	next.LocalAddresses = append(slices.Clone(next.LocalAddresses), netip.MustParseAddr("198.51.100.1"))
	if err := monitor.reconcile(); err != nil {
		t.Fatal(err)
	}
	snapshot := monitor.Snapshot()
	snapshot.LocalAddresses[0] = netip.Addr{}
	if !monitor.Snapshot().LocalAddresses[0].IsValid() {
		t.Fatal("snapshot exposed the monitor's address storage")
	}
	if err := monitor.reconcile(); err != nil || called != 1 {
		t.Fatalf("unchanged snapshot notified again: calls=%d, err=%v", called, err)
	}
}
