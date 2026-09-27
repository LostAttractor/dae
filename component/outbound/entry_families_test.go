//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestEntryVariantsRequireDNSAndLocalFamily(t *testing.T) {
	dnsFamilies := new(atomic.Uint32)
	server, _ := entryTestDNS(t, dnsFamilies)
	option := &dialer.GlobalOption{DNSResolver: server}
	path := &PathSpec{
		Nodes: []*NodeInfo{{Property: &dialer.Property{Address: "entry.test.:1080"}}},
		Entry: EntryOptions{Interface: "lo", Mark: new(uint32(0))},
	}
	for _, test := range []struct {
		name       string
		dns, local uint8
		filter     *uint8
		want       []int
	}{
		{"A only on dual stack host", family4, allFamilies, nil, []int{4}},
		{"AAAA only", family6, allFamilies, nil, []int{6}},
		{"dual DNS on IPv4 host", allFamilies, family4, nil, []int{4}},
		{"dual DNS on IPv6 host", allFamilies, family6, nil, []int{6}},
		{"both support dual stack", allFamilies, allFamilies, nil, []int{4, 6}},
		{"IPv6 filter cannot invent AAAA", family4, allFamilies, new(uint8(family6)), nil},
		{"IPv6 filter cannot invent local IPv6", allFamilies, family4, new(uint8(family6)), nil},
		{"IPv4 filter", allFamilies, allFamilies, new(uint8(family4)), []int{4}},
		{"no local connectivity", allFamilies, 0, nil, nil},
		{"no DNS addresses", 0, allFamilies, nil, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			dnsFamilies.Store(uint32(test.dns))
			candidate := *path
			candidate.Entry.Families = test.filter
			variants, err := expandIPVariants(t.Context(), []*PathSpec{&candidate}, func(ctx context.Context, path *PathSpec) (uint8, error) {
				return path.availableEntryFamilies(ctx, option, func(address netip.Addr, mark uint32, iface string) bool {
					if mark != 0 || iface != "lo" {
						t.Errorf("route check lost entry options: mark=%d interface=%s", mark, iface)
					}
					if address.Is4() {
						return test.local&family4 != 0
					}
					return test.local&family6 != 0
				})
			})
			if err != nil {
				t.Fatal(err)
			}
			var got []int
			for _, variant := range variants {
				got = append(got, variant.IPVersion)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("created families = %v, want %v", got, test.want)
			}
		})
	}
}

func TestEntryDiscoveryOnRealLocalRoute(t *testing.T) {
	mask := new(atomic.Uint32)
	mask.Store(uint32(family4))
	server, _ := entryTestDNS(t, mask)
	path := &PathSpec{
		Nodes: []*NodeInfo{{Property: &dialer.Property{Address: "entry.test.:1080"}}},
		Entry: EntryOptions{Interface: "lo"},
	}
	option := &dialer.GlobalOption{DNSResolver: server}
	variants, err := ExpandIPVariants(t.Context(), []*PathSpec{path}, option)
	if err != nil || len(variants) != 1 || variants[0].IPVersion != 4 {
		t.Fatalf("A-only node created unsupported candidates: %v, %v", variants, err)
	}
	mask.Store(uint32(allFamilies))
	variants, err = ExpandIPVariants(t.Context(), []*PathSpec{path}, option)
	if err != nil {
		t.Fatal(err)
	}
	want := 1
	if entryAddressUsable(netip.MustParseAddr("::1"), 0, "lo") {
		want = 2
	}
	if len(variants) != want {
		t.Fatalf("dual DNS created %d candidates, local route support permits %d", len(variants), want)
	}
}

// The network namespace keeps these address/route changes off the host. Unlike
// a loopback-only test this proves that IPv6 on another interface cannot enable
// an IPv4-only bound interface, and that fwmark policy routing is respected.
func TestEntryFamilyRouteAndInterface(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	previous, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer previous.Close()
	ns, err := netns.New()
	if errors.Is(err, unix.EPERM) {
		t.Skip("network namespace requires privileges")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	defer func() {
		if err := netns.Set(previous); err != nil {
			t.Fatal(err)
		}
	}()
	addLink := func(name, prefix string) netlink.Link {
		t.Helper()
		link := &netlink.Dummy{Name: name}
		if err := netlink.LinkAdd(link); err != nil {
			t.Fatal(err)
		}
		address, err := netlink.ParseAddr(prefix)
		if err != nil {
			t.Fatal(err)
		}
		address.Flags = unix.IFA_F_NODAD
		if err := netlink.AddrAdd(link, address); err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
		return link
	}
	v4 := addLink("wan4", "192.0.2.1/24")
	v6 := addLink("wan6", "2001:db8:6::1/64")
	linkLocal, err := netlink.ParseAddr("fe80::1/64")
	if err != nil {
		t.Fatal(err)
	}
	linkLocal.Flags = unix.IFA_F_NODAD
	if err := netlink.AddrAdd(v6, linkLocal); err != nil {
		t.Fatal(err)
	}
	// Give wan4 an IPv6 route but no usable IPv6 source address of its own.
	_, prefix, _ := net.ParseCIDR("2001:db8:4::/64")
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: v4.Attrs().Index, Dst: prefix}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		address, iface string
		want           bool
	}{
		{"192.0.2.2", "wan4", true},
		{"2001:db8:6::2", "wan6", true},
		{"2001:db8:6::2", "", true},
		{"2001:db8:6::2", "wan4", false},
		{"2001:db8:4::2", "wan4", false},
		{"192.0.2.2", "absent", false},
		{"fe80::2%wan6", "wan6", true},
		{"fe80::2%" + strconv.Itoa(v6.Attrs().Index), "wan6", true},
		{"fe80::2%" + strconv.Itoa(v6.Attrs().Index), "", true},
		{"fe80::2%wan6", "wan4", false},
	} {
		if got := entryAddressUsable(netip.MustParseAddr(test.address), 0, test.iface); got != test.want {
			t.Errorf("%s on %q usable = %v, want %v", test.address, test.iface, got, test.want)
		}
	}
	rule := netlink.NewRule()
	rule.Family, rule.Priority, rule.Mark, rule.Type = netlink.FAMILY_V6, 100, 0x20, unix.FR_ACT_PROHIBIT
	if err := netlink.RuleAdd(rule); err != nil {
		t.Fatal(err)
	}
	if entryAddressUsable(netip.MustParseAddr("2001:db8:6::2"), 0x20, "wan6") {
		t.Fatal("family discovery ignored the mark's policy-routing rule")
	}
	if err := netlink.LinkSetDown(v6); err != nil {
		t.Fatal(err)
	}
	if entryAddressUsable(netip.MustParseAddr("2001:db8:6::2"), 0, "wan6") {
		t.Fatal("down interface advertised IPv6 support")
	}
}
