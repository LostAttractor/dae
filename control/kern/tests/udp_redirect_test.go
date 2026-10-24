//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
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
// conntrack direction and sends them directly; the service's own new flows are
// still routed, here to a proxy that the test leaves without a relay.
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
	must(netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "wan"}, PeerName: "remote"}))
	peerLink, err := netlink.LinkByName("remote")
	must(err)
	must(netlink.LinkSetNsFd(peerLink, int(remote)))
	wan := up("wan", "192.0.2.1/24", "2001:db8::1/64")
	for _, attach := range []struct {
		program *ebpf.Program
		kind    ebpf.AttachType
	}{{obj.TproxyWanIngressL2, ebpf.AttachTCXIngress}, {obj.TproxyWanEgressL2, ebpf.AttachTCXEgress}} {
		l, err := link.AttachTCX(link.TCXOptions{Interface: wan.Attrs().Index, Program: attach.program, Attach: attach.kind})
		must(err)
		defer l.Close()
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
			_, err := conn.Read(buf)
			return err == nil
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
		_, err = server.WriteToUDPAddrPort(payload, from)
		must(err)
		if !received(client, 2*time.Second) {
			t.Fatalf("%s: reply of the redirected service did not leave directly", family.network)
		}
		clientAddr := client.LocalAddr().(*net.UDPAddr).AddrPort()
		if state, ok := udpConnState(t, obj, exposedAddr, clientAddr); !ok || !state.IsWanIngressDirection {
			t.Fatalf("%s: redirected service state = %+v, %v", family.network, state, ok)
		}

		otherAddr := other.LocalAddr().(*net.UDPAddr).AddrPort()
		_, err = server.WriteToUDPAddrPort(payload, otherAddr)
		must(err)
		if received(other, 200*time.Millisecond) {
			t.Fatalf("%s: new flow of the service left directly", family.network)
		}
		serviceAddr := netip.AddrPortFrom(netip.MustParseAddr(family.router), service)
		if state, ok := udpConnState(t, obj, serviceAddr, otherAddr); !ok || state.IsWanIngressDirection {
			t.Fatalf("%s: service outbound state = %+v, %v", family.network, state, ok)
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
		t.Skipf("nftables NAT unavailable: %v", err)
	}
}
