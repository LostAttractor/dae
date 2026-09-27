//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestEntryScopedUDPWithoutInterfaceBinding(t *testing.T) {
	// These literal-only lookups and socket operations run synchronously on the
	// locked thread. No DNS workers or subtest goroutines leave the namespace.
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
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	link := &netlink.Veth{Name: "entryzone", PeerName: "entrypeer"}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	peer, err := netlink.LinkByName(link.PeerName)
	if err != nil {
		t.Fatal(err)
	}
	peerNS, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer peerNS.Close()
	if err := netns.Set(ns); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetNsFd(peer, int(peerNS)); err != nil {
		t.Fatal(err)
	}
	configureLink := func(link netlink.Link, prefix string) {
		t.Helper()
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
		addr, err := netlink.ParseAddr(prefix)
		if err != nil {
			t.Fatal(err)
		}
		addr.Flags = unix.IFA_F_NODAD
		if err := netlink.AddrAdd(link, addr); err != nil {
			t.Fatal(err)
		}
	}
	configureLink(link, "fe80::1/64")
	// An unscoped destination must not succeed by choosing the only route.
	wrong := &netlink.Dummy{Name: "wrongzone"}
	if err := netlink.LinkAdd(wrong); err != nil {
		t.Fatal(err)
	}
	configureLink(wrong, "fe80::dead/64")
	_, prefix, _ := net.ParseCIDR("fe80::/64")
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: wrong.Attrs().Index, Dst: prefix, Priority: 1}); err != nil {
		t.Fatal(err)
	}
	if err := netns.Set(peerNS); err != nil {
		t.Fatal(err)
	}
	peer, err = netlink.LinkByName(link.PeerName)
	if err != nil {
		t.Fatal(err)
	}
	configureLink(peer, "fe80::1234/64")
	server, err := net.ListenPacket("udp6", "[fe80::1234%entrypeer]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.LocalAddr().String())
	if err := netns.Set(ns); err != nil {
		t.Fatal(err)
	}
	base, err := (&PathSpec{IPVersion: 6}).entryDialer(new(dialer.GlobalOption))
	if err != nil {
		t.Fatal(err)
	}
	packet, err := base.ListenPacket(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	for _, zone := range []string{link.Attrs().Name, strconv.Itoa(link.Attrs().Index)} {
		address := net.JoinHostPort("fe80::1234%"+zone, port)
		resolved, err := netproxy.ResolveUDPAddr(t.Context(), base, address)
		if err != nil {
			t.Fatal(err)
		}
		// QUIC uses the resolved UDPAddr; ordinary packet proxies may pass a
		// ProxyAddr to WriteTo. Both must retain scope without SO_BINDTODEVICE.
		for _, destination := range []net.Addr{resolved, netproxy.NewProxyAddr("udp", address)} {
			payload := []byte(fmt.Sprintf("%s/%T", zone, destination))
			if _, err := packet.WriteTo(payload, destination); err != nil {
				t.Fatalf("send scoped UDP to %s (%T): %v", destination, destination, err)
			}
			if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 128)
			n, _, err := server.ReadFrom(buffer)
			if err != nil || string(buffer[:n]) != string(payload) {
				t.Fatalf("receive scoped UDP: %q, %v", buffer[:n], err)
			}
		}
		if resolved.Zone != zone {
			t.Fatalf("zone changed: got %q, want %q", resolved.Zone, zone)
		}
	}
}
