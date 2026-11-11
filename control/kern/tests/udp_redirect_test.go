//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
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

// A local UDP service behind a port redirect has no socket on the port WAN
// ingress sees before NAT. WAN egress recognizes its replies by their
// conntrack direction even when replacement occurs before the first reply.
// The same socket's new flows still obey proxy and block rules.
func TestUDPInboundStateBehindRedirect(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for the isolated NAT test")
	}
	obj, err := loadTestObjects(t, "TproxyWanIngressL2", "TproxyWanEgressL2")
	if err != nil {
		t.Fatal(err)
	}
	const proxy, exposed, service = 2, 443, 51820
	installRoutingFlow(t, obj, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback), Outbound: proxy}})
	for _, version := range []uint8{4, 6} {
		query := bpftestOutboundConnectivityQuery{Outbound: proxy, L4proto: unix.IPPROTO_UDP, Ipversion: version}
		if err := obj.OutboundConnectivityMap.Update(query, bpftestOutboundConnectivity{}, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	defer original.Close()
	defer func() {
		if err := netns.Set(original); err != nil {
			t.Fatalf("restore namespace: %v", err)
		}
		runtime.UnlockOSThread()
	}()
	remote, err := netns.New()
	must(err)
	defer remote.Close()
	router, err := netns.New()
	must(err)
	defer router.Close()
	up := func(ifname string, cidrs ...string) netlink.Link {
		t.Helper()
		l, err := netlink.LinkByName(ifname)
		must(err)
		for _, cidr := range cidrs {
			addr, err := netlink.ParseAddr(cidr)
			must(err)
			addr.Flags = unix.IFA_F_NODAD
			must(netlink.AddrAdd(l, addr))
		}
		must(netlink.LinkSetUp(l))
		return l
	}
	up("lo")
	must(netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "wan"}, PeerName: "remote"}))
	peerLink, err := netlink.LinkByName("remote")
	must(err)
	must(netlink.LinkSetNsFd(peerLink, int(remote)))
	wan := up("wan", "192.0.2.1/24", "2001:db8::1/64")
	var attachments []link.Link
	for _, attach := range []struct {
		program *ebpf.Program
		kind    ebpf.AttachType
	}{{obj.TproxyWanIngressL2, ebpf.AttachTCXIngress}, {obj.TproxyWanEgressL2, ebpf.AttachTCXEgress}} {
		l, err := link.AttachTCX(link.TCXOptions{Interface: wan.Attrs().Index, Program: attach.program, Attach: attach.kind})
		must(err)
		defer l.Close()
		attachments = append(attachments, l)
	}
	redirectUDP(t, router, exposed, service)
	servers := map[string]*net.UDPConn{}
	for _, network := range []string{"udp4", "udp6"} {
		server, err := net.ListenUDP(network, &net.UDPAddr{Port: service})
		must(err)
		defer server.Close()
		servers[network] = server
	}

	must(netns.Set(remote))
	up("remote", "192.0.2.2/24", "2001:db8::2/64")
	// Sockets stay in the namespace they were created in. Subtests would run on
	// other threads, so the families share this one.
	for _, family := range []struct{ network, local, router string }{
		{"udp4", "192.0.2.2", "192.0.2.1"},
		{"udp6", "2001:db8::2", "2001:db8::1"},
	} {
		must(attachments[0].Update(obj.TproxyWanIngressL2))
		must(attachments[1].Update(obj.TproxyWanEgressL2))
		listen := func() *net.UDPConn {
			t.Helper()
			conn, err := net.ListenUDP(family.network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(family.local), 0)))
			must(err)
			t.Cleanup(func() { conn.Close() })
			return conn
		}
		buf := make([]byte, 64)
		received := func(conn *net.UDPConn, wait time.Duration) bool {
			t.Helper()
			must(conn.SetReadDeadline(time.Now().Add(wait)))
			n, err := conn.Read(buf)
			if err != nil {
				if timeout, ok := errors.AsType[net.Error](err); ok && timeout.Timeout() {
					return false
				}
				t.Fatal(err)
			}
			if string(buf[:n]) != family.network {
				t.Fatalf("unexpected UDP payload %q", buf[:n])
			}
			return true
		}
		server, client, other := servers[family.network], listen(), listen()
		payload := []byte(family.network)
		exposedAddr := netip.AddrPortFrom(netip.MustParseAddr(family.router), exposed)
		_, err := client.WriteToUDPAddrPort(payload, exposedAddr)
		must(err)
		must(server.SetReadDeadline(time.Now().Add(2 * time.Second)))
		_, from, err := server.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("%s: redirected datagram: %v", family.network, err)
		}
		// A received the request; B has fresh private maps and sees the first reply.
		must(netns.Set(router))
		current, err := loadTestObjects(t, "TproxyWanIngressL2", "TproxyWanEgressL2", "ConntrackProbe")
		must(err)
		installRoutingFlow(t, current, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback), Outbound: proxy}})
		for _, version := range []uint8{4, 6} {
			must(current.OutboundConnectivityMap.Update(bpftestOutboundConnectivityQuery{Outbound: proxy, L4proto: unix.IPPROTO_UDP, Ipversion: version}, bpftestOutboundConnectivity{}, ebpf.UpdateAny))
		}
		must(attachments[0].Update(current.TproxyWanIngressL2))
		must(attachments[1].Update(current.TproxyWanEgressL2))
		serviceAddr := netip.AddrPortFrom(netip.MustParseAddr(family.router), service)
		clientAddr := client.LocalAddr().(*net.UDPAddr).AddrPort()
		runUDP(t, current.ConntrackProbe, clientAddr, exposedAddr, 0, 1)
		runUDP(t, current.ConntrackProbe, serviceAddr, clientAddr, 0, 2)
		_, err = server.WriteToUDPAddrPort(payload, from)
		must(err)
		if !received(client, 2*time.Second) {
			t.Fatalf("%s: first reply after replacement did not leave directly", family.network)
		}

		otherAddr := other.LocalAddr().(*net.UDPAddr).AddrPort()
		_, err = server.WriteToUDPAddrPort(payload, otherAddr)
		must(err)
		if received(other, 200*time.Millisecond) {
			t.Fatalf("%s: new flow of the service left directly", family.network)
		}
		var handoff bpftestRoutingHandoff
		must(current.RoutingTuplesMap.Lookup(udpFlowKey(serviceAddr, otherAddr), &handoff))
		if handoff.Result.Outbound != proxy {
			t.Fatalf("%s: new service flow chose outbound %d, want proxy", family.network, handoff.Result.Outbound)
		}
		// The same service socket must also obey a block rule on another flow.
		installRoutingFlow(t, current, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundBlock)}})
		must(current.RoutingGeneration.Set(uint32(2)))
		must(netns.Set(remote))
		blocked := listen()
		_, err = server.WriteToUDPAddrPort(payload, blocked.LocalAddr().(*net.UDPAddr).AddrPort())
		must(err)
		if received(blocked, 200*time.Millisecond) {
			t.Fatalf("%s: new service flow bypassed the block rule", family.network)
		}
		_, err = server.WriteToUDPAddrPort(payload, from)
		must(err)
		if !received(client, 2*time.Second) {
			t.Fatalf("%s: genuine reply was blocked", family.network)
		}
	}
}

// redirectUDP redirects inbound UDP of port from to the local port to.
func redirectUDP(t *testing.T, ns netns.NsHandle, from, to uint16) {
	t.Helper()
	conn, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		t.Fatal(err)
	}
	table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "nat"})
	chain := conn.AddChain(&nftables.Chain{Name: "prerouting", Table: table, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest})
	conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, from)},
		&expr.Immediate{Register: 1, Data: binary.BigEndian.AppendUint16(nil, to)},
		&expr.Redir{RegisterProtoMin: 1},
	}})
	if err := conn.Flush(); err != nil {
		t.Fatalf("install isolated nftables redirect: %v", err)
	}
}
