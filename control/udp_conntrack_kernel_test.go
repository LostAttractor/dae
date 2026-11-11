// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func inDatapathHost(t *testing.T, ns *DaeNetns, run func()) {
	t.Helper()
	previous, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer previous.Close()
	if err := netns.Set(ns.hostNs); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := netns.Set(previous); err != nil {
			t.Fatal(err)
		}
	}()
	run()
}

func datapathUDPDirection(t *testing.T, ns *DaeNetns, objects *bpfObjects, source, target netip.AddrPort) uint32 {
	t.Helper()
	var direction uint32
	inDatapathHost(t, ns, func() {
		packet, _ := routingKernelPacket(source, target, consts.L4ProtoType_UDP)
		var err error
		direction, err = objects.ConntrackProbe.Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256)})
		if err != nil || direction > 2 {
			t.Fatalf("host conntrack lookup %s -> %s: direction=%d err=%v", source, target, direction, err)
		}
	})
	return direction
}

// A late synthetic reply must not create a reverse host connection that makes
// the client's next request look like an inbound service's reply after restart.
func TestUDPRelayDoesNotCreateInboundConntrack(t *testing.T) {
	if os.Getenv("DAE_TEST_ISOLATED") != "1" {
		t.Skip("requires isolated PID, network and mount namespaces")
	}
	for _, linkType := range []string{"netkit", "veth"} {
		for _, origin := range []string{"LAN", "WAN", "WAN-SNAT"} {
			for _, family := range []string{"4", "6"} {
				t.Run(linkType+"/"+origin+"/IPv"+family, func(t *testing.T) {
					withInternalLinkDatapath(t, linkType, origin == "LAN", func(ns *DaeNetns, objects *bpfObjects, _ []link.Link) {
						testUDPRelayConntrackExpiry(t, ns, objects, family, origin != "LAN", origin == "WAN-SNAT")
					})
				})
			}
		}
	}
}

func testUDPRelayConntrackExpiry(t *testing.T, ns *DaeNetns, objects *bpfObjects, family string, wan, snat bool) {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	target := netip.MustParseAddrPort("203.0.113.8:4444")
	local, translated := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("198.18.0.2")
	ctFamily := netlink.InetFamily(unix.AF_INET)
	if family == "6" {
		target = netip.MustParseAddrPort("[2001:db8:2::8]:4444")
		local, translated = netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:1::2")
		ctFamily = unix.AF_INET6
	}
	if snat {
		installUDPRelaySNAT(t, ns, local, translated, target.Port())
	}
	listener, err := ns.With(func() (net.PacketConn, error) {
		lc := tproxyListenConfig()
		return lc.ListenPacket(t.Context(), "udp"+family, ":0")
	})
	must(err)
	defer listener.Close()
	udp := listener.(*net.UDPConn)
	must(registerSocket(objects.ListenSocketMap, uint32(1), udp))
	must(udp.SetDeadline(time.Now().Add(3 * time.Second)))
	client, err := net.ListenUDP("udp"+family, net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)))
	must(err)
	defer client.Close()
	source := client.LocalAddr().(*net.UDPAddr).AddrPort()
	payload := []byte("late relay reply")
	_, err = client.WriteToUDPAddrPort(payload, target)
	must(err)
	buf := make([]byte, 128)
	n, from, err := udp.ReadFromUDPAddrPort(buf)
	must(err)
	capturedIP := local
	if snat {
		capturedIP = translated
	}
	if from.Addr() != capturedIP || from.Port() == 0 || (!snat && from != source) || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("captured packet from %s: %q, want source IP %s", from, buf[:n], capturedIP)
	}
	relayTarget := from
	reply, err := ns.With(func() (net.PacketConn, error) {
		lc := tproxyListenConfig()
		return lc.ListenPacket(t.Context(), "udp"+family, target.String())
	})
	must(err)
	defer reply.Close()
	want := uint32(0)
	if wan {
		want = 1
	}
	if got := datapathUDPDirection(t, ns, objects, source, target); got != want {
		t.Fatalf("initial host direction = %d, want %d", got, want)
	}
	if snat {
		if got := datapathUDPDirection(t, ns, objects, target, relayTarget); got != 2 {
			t.Fatalf("NAT reply tuple direction = %d, want reply", got)
		}
		livePayload := []byte("live relay through reverse SNAT")
		_, err = reply.WriteTo(livePayload, net.UDPAddrFromAddrPort(relayTarget))
		must(err)
		must(client.SetReadDeadline(time.Now().Add(3 * time.Second)))
		n, from, err = client.ReadFromUDPAddrPort(buf)
		if err != nil || from != target || !bytes.Equal(buf[:n], livePayload) {
			t.Fatalf("reverse SNAT reply to original client: source=%s packet=%q err=%v", from, buf[:n], err)
		}
		_, err = client.WriteToUDPAddrPort(livePayload, target)
		must(err)
		n, from, err = udp.ReadFromUDPAddrPort(buf)
		if err != nil || from != relayTarget || !bytes.Equal(buf[:n], livePayload) {
			t.Fatalf("client packet after live SNAT reply escaped capture: source=%s packet=%q err=%v", from, buf[:n], err)
		}
	}
	if wan {
		inDatapathHost(t, ns, func() {
			// The original key remains pre-NAT; the relay uses the translated reply key.
			filter := new(netlink.ConntrackFilter)
			must(filter.AddProtocol(unix.IPPROTO_UDP))
			must(filter.AddIP(netlink.ConntrackOrigSrcIP, net.IP(source.Addr().AsSlice())))
			must(filter.AddIP(netlink.ConntrackOrigDstIP, net.IP(target.Addr().AsSlice())))
			must(filter.AddPort(netlink.ConntrackOrigSrcPort, source.Port()))
			must(filter.AddPort(netlink.ConntrackOrigDstPort, target.Port()))
			removed, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, ctFamily, filter)
			must(err)
			if removed != 1 {
				t.Fatalf("removed %d host records, want exactly this UDP flow", removed)
			}
		})
	}
	if got := datapathUDPDirection(t, ns, objects, source, target); got != 0 {
		t.Fatalf("expired host direction = %d, want unknown", got)
	}
	if got := datapathUDPDirection(t, ns, objects, target, relayTarget); got != 0 {
		t.Fatalf("expired reply tuple direction = %d, want unknown", got)
	}
	_, err = reply.WriteTo(payload, net.UDPAddrFromAddrPort(relayTarget))
	must(err)
	must(client.SetReadDeadline(time.Now().Add(100 * time.Millisecond)))
	n, _, err = client.ReadFromUDPAddrPort(buf)
	if wan {
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("WAN relay without original conntrack reached client: packet=%q err=%v", buf[:n], err)
		}
	} else if err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("LAN relay reply=%q err=%v", buf[:n], err)
	}
	if got := datapathUDPDirection(t, ns, objects, source, target); got != 0 {
		t.Errorf("synthetic reply created host direction %d, want unknown", got)
	}
	if got := datapathUDPDirection(t, ns, objects, target, relayTarget); got != 0 {
		t.Errorf("synthetic reply created reverse host direction %d, want unknown", got)
	}
	_, err = client.WriteToUDPAddrPort(payload, target)
	must(err)
	n, from, err = udp.ReadFromUDPAddrPort(buf)
	if err != nil || from.Addr() != capturedIP || (!snat && from != source) || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("next client packet escaped capture: source=%s packet=%q err=%v", from, buf[:n], err)
	}
}

func installUDPRelaySNAT(t *testing.T, ns *DaeNetns, source, translated netip.Addr, port uint16) {
	t.Helper()
	conn, err := nftables.New(nftables.WithNetNSFd(int(ns.hostNs)))
	if err != nil {
		t.Fatal(err)
	}
	family, af, offset := nftables.TableFamilyIPv4, uint32(unix.AF_INET), uint32(12)
	if source.Is6() {
		family, af, offset = nftables.TableFamilyIPv6, unix.AF_INET6, 8
	}
	table := conn.AddTable(&nftables.Table{Family: family, Name: "udp_relay_snat"})
	chain := conn.AddChain(&nftables.Chain{Name: "postrouting", Table: table, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource})
	conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(source.AsSlice()))},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: source.AsSlice()},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, port)},
		&expr.Immediate{Register: 1, Data: translated.AsSlice()},
		&expr.NAT{Type: expr.NATTypeSourceNAT, Family: af, RegAddrMin: 1},
	}})
	if err := conn.Flush(); err != nil {
		t.Fatalf("install isolated UDP relay SNAT rule: %v", err)
	}
}
