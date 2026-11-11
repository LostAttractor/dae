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

const udpCTServicePort = 51820

// Each case owns its router and both endpoints; only host conntrack survives
// the attachment replacement. No BPF map is shared between A and B.
func TestUDPForwardConntrackReplacement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for isolated conntrack tests")
	}
	for _, network := range []string{"udp4", "udp6"} {
		for _, nat := range []string{"none", "snat"} {
			for _, order := range []string{"reply-first", "client-first"} {
				t.Run(network+"/outbound/"+nat+"/"+order, func(t *testing.T) {
					withUDPForwardNetwork(t, network, nat, func(f *udpForwardNetwork) {
						old, current, replace := f.attachGenerations(t)
						client := f.listen(t, f.lanNS, f.lanIP, 0)
						server := f.listen(t, f.wanNS, f.wanIP, udpCTServicePort)
						clientAddr, serverAddr := udpSocketAddr(client), udpSocketAddr(server)
						sendUDPConntrack(t, client, serverAddr, "request-A")
						from := receiveUDPConntrack(t, server, "request-A")
						if nat == "snat" && from.Addr() != f.gatewayWAN {
							t.Fatalf("SNAT source = %v, want %v", from, f.gatewayWAN)
						}
						runUDP(t, old.ConntrackProbe, clientAddr, serverAddr, 0, 1)
						runUDP(t, old.ConntrackProbe, serverAddr, from, 0, 2)
						replace()
						if order == "client-first" {
							sendUDPConntrack(t, client, serverAddr, "blocked-before-reply")
							rejectUDPConntrack(t, server)
						}
						sendUDPConntrack(t, server, from, "old-reply-B")
						receiveUDPConntrack(t, client, "old-reply-B")
						runUDP(t, current.ConntrackProbe, clientAddr, serverAddr, 0, 1)
						for range 2 {
							sendUDPConntrack(t, client, serverAddr, "blocked-after-reply")
							rejectUDPConntrack(t, server)
						}
					})
				})
			}
		}
		for _, nat := range []string{"none", "dnat"} {
			t.Run(network+"/inbound/"+nat, func(t *testing.T) {
				withUDPForwardNetwork(t, network, nat, func(f *udpForwardNetwork) {
					old, current, replace := f.attachGenerations(t)
					server := f.listen(t, f.lanNS, f.lanIP, udpCTServicePort)
					client := f.listen(t, f.wanNS, f.wanIP, 0)
					serverAddr, clientAddr := udpSocketAddr(server), udpSocketAddr(client)
					exposed := serverAddr
					if nat == "dnat" {
						exposed = netip.AddrPortFrom(f.gatewayWAN, 443)
					}
					sendUDPConntrack(t, client, exposed, "inbound-A")
					from := receiveUDPConntrack(t, server, "inbound-A")
					if from != clientAddr {
						t.Fatalf("inbound source = %v, want %v", from, clientAddr)
					}
					runUDP(t, old.ConntrackProbe, clientAddr, exposed, 0, 1)
					replace()
					runUDP(t, current.ConntrackProbe, serverAddr, clientAddr, 0, 2)
					sendUDPConntrack(t, server, from, "first-reply-B")
					if replyFrom := receiveUDPConntrack(t, client, "first-reply-B"); replyFrom != exposed {
						t.Fatalf("reply source = %v, want %v", replyFrom, exposed)
					}

					// Answering one peer does not exempt this socket's other flows.
					blocked := f.listen(t, f.wanNS, f.wanIP, 0)
					sendUDPConntrack(t, server, udpSocketAddr(blocked), "new-blocked")
					rejectUDPConntrack(t, blocked)
					const proxy = 2
					installRoutingFlow(t, current, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback), Outbound: proxy}})
					if err := current.RoutingGeneration.Set(uint32(2)); err != nil {
						t.Fatal(err)
					}
					version := uint8(4)
					if network == "udp6" {
						version = 6
					}
					if err := current.OutboundConnectivityMap.Update(bpftestOutboundConnectivityQuery{Outbound: proxy, L4proto: unix.IPPROTO_UDP, Ipversion: version}, bpftestOutboundConnectivity{}, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
					proxied := f.listen(t, f.wanNS, f.wanIP, 0)
					sendUDPConntrack(t, server, udpSocketAddr(proxied), "new-proxied")
					rejectUDPConntrack(t, proxied)
					var handoff bpftestRoutingHandoff
					if err := current.RoutingTuplesMap.Lookup(udpFlowKey(serverAddr, udpSocketAddr(proxied)), &handoff); err != nil {
						t.Fatal(err)
					}
					if handoff.Result.Outbound != proxy {
						t.Fatalf("new flow outbound = %d, want proxy", handoff.Result.Outbound)
					}
					sendUDPConntrack(t, server, from, "reply-after-new-flow")
					receiveUDPConntrack(t, client, "reply-after-new-flow")
				})
			})
		}
	}
}

type udpForwardNetwork struct {
	router, lanNS, wanNS                 netns.NsHandle
	lan, wan                             netlink.Link
	network                              string
	lanIP, wanIP, gatewayLAN, gatewayWAN netip.Addr
}

func withUDPForwardNetwork(t *testing.T, network, nat string, run func(*udpForwardNetwork)) {
	t.Helper()
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
		must(netns.Set(original))
		runtime.UnlockOSThread()
	}()
	lanNS, err := netns.New()
	must(err)
	defer lanNS.Close()
	wanNS, err := netns.New()
	must(err)
	defer wanNS.Close()
	router, err := netns.New()
	must(err)
	defer router.Close()
	f := &udpForwardNetwork{
		router: router, lanNS: lanNS, wanNS: wanNS, network: network,
		lanIP: netip.MustParseAddr("192.0.2.2"), gatewayLAN: netip.MustParseAddr("192.0.2.1"),
		wanIP: netip.MustParseAddr("198.51.100.2"), gatewayWAN: netip.MustParseAddr("198.51.100.1"),
	}
	prefix := 24
	forwarding := "/proc/sys/net/ipv4/ip_forward"
	if network == "udp6" {
		f.lanIP, f.gatewayLAN = netip.MustParseAddr("2001:db8:1::2"), netip.MustParseAddr("2001:db8:1::1")
		f.wanIP, f.gatewayWAN = netip.MustParseAddr("2001:db8:2::2"), netip.MustParseAddr("2001:db8:2::1")
		prefix, forwarding = 64, "/proc/sys/net/ipv6/conf/all/forwarding"
	}
	must(os.WriteFile(forwarding, []byte("1"), 0o644))
	up := func(name string, ip netip.Addr) netlink.Link {
		t.Helper()
		l, err := netlink.LinkByName(name)
		must(err)
		if ip.IsValid() {
			addr, err := netlink.ParseAddr(netip.PrefixFrom(ip, prefix).String())
			must(err)
			addr.Flags = unix.IFA_F_NODAD
			must(netlink.AddrAdd(l, addr))
		}
		must(netlink.LinkSetUp(l))
		return l
	}
	up("lo", netip.Addr{})
	for _, side := range []struct {
		name          string
		ns            netns.NsHandle
		gateway, host netip.Addr
	}{
		{"lan", lanNS, f.gatewayLAN, f.lanIP},
		{"wan", wanNS, f.gatewayWAN, f.wanIP},
	} {
		must(netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: side.name}, PeerName: "peer"}))
		peer, err := netlink.LinkByName("peer")
		must(err)
		must(netlink.LinkSetNsFd(peer, int(side.ns)))
		l := up(side.name, side.gateway)
		if side.name == "lan" {
			f.lan = l
		} else {
			f.wan = l
		}
		must(netns.Set(side.ns))
		up("lo", netip.Addr{})
		peer = up("peer", side.host)
		must(netlink.RouteAdd(&netlink.Route{LinkIndex: peer.Attrs().Index, Gw: net.IP(side.gateway.AsSlice())}))
		// Direction tests must not race initial link-local DAD and NDP resolution.
		must(netlink.NeighSet(&netlink.Neigh{LinkIndex: peer.Attrs().Index, IP: net.IP(side.gateway.AsSlice()), HardwareAddr: l.Attrs().HardwareAddr, State: unix.NUD_PERMANENT}))
		must(netns.Set(router))
		must(netlink.NeighSet(&netlink.Neigh{LinkIndex: l.Attrs().Index, IP: net.IP(side.host.AsSlice()), HardwareAddr: peer.Attrs().HardwareAddr, State: unix.NUD_PERMANENT}))
	}
	f.installConntrack(t, nat)
	run(f)
}

func (f *udpForwardNetwork) installConntrack(t *testing.T, nat string) {
	t.Helper()
	conn, err := nftables.New(nftables.WithNetNSFd(int(f.router)))
	if err != nil {
		t.Fatal(err)
	}
	family, af := nftables.TableFamilyIPv4, uint32(unix.AF_INET)
	if f.network == "udp6" {
		family, af = nftables.TableFamilyIPv6, unix.AF_INET6
	}
	table := conn.AddTable(&nftables.Table{Family: family, Name: "udp_conntrack"})
	chain := conn.AddChain(&nftables.Chain{Name: "track", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityFilter})
	// Hold a conntrack hook reference even in the no-NAT topology.
	conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{&expr.Ct{Key: expr.CtKeySTATE, Register: 1}}})
	if nat != "none" {
		hook, priority, kind, address := nftables.ChainHookPostrouting, nftables.ChainPriorityNATSource, expr.NATTypeSourceNAT, f.gatewayWAN
		metaKey := expr.MetaKeyOIF
		if nat == "dnat" {
			hook, priority, kind, address = nftables.ChainHookPrerouting, nftables.ChainPriorityNATDest, expr.NATTypeDestNAT, f.lanIP
			metaKey = expr.MetaKeyIIF
		}
		chain = conn.AddChain(&nftables.Chain{Name: nat, Table: table, Type: nftables.ChainTypeNAT, Hooknum: hook, Priority: priority})
		expressions := []expr.Any{
			&expr.Meta{Key: metaKey, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.NativeEndian.AppendUint32(nil, uint32(f.wan.Attrs().Index))},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		}
		if nat == "dnat" {
			expressions = append(expressions,
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, 443)})
		}
		expressions = append(expressions, &expr.Immediate{Register: 1, Data: address.AsSlice()})
		translation := &expr.NAT{Type: kind, Family: af, RegAddrMin: 1}
		if nat == "dnat" {
			expressions = append(expressions, &expr.Immediate{Register: 2, Data: binary.BigEndian.AppendUint16(nil, udpCTServicePort)})
			translation.RegProtoMin = 2
		}
		expressions = append(expressions, translation)
		conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: expressions})
	}
	if err := conn.Flush(); err != nil {
		t.Fatalf("install isolated conntrack/NAT rules: %v", err)
	}
}

func (f *udpForwardNetwork) attachGenerations(t *testing.T) (old, current *bpftestObjects, replace func()) {
	t.Helper()
	programs := []string{"LanIngressL2", "LanEgressL2", "TproxyWanIngressL2", "TproxyWanEgressL2", "ConntrackProbe"}
	var err error
	old, err = loadTestObjects(t, programs...)
	if err != nil {
		t.Fatal(err)
	}
	current, err = loadTestObjects(t, programs...)
	if err != nil {
		t.Fatal(err)
	}
	installRoutingFlow(t, old, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundDirect)}})
	installRoutingFlow(t, current, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundBlock)}})
	var updates []func()
	for _, attach := range []struct {
		iface        int
		kind         ebpf.AttachType
		old, current *ebpf.Program
	}{
		{f.lan.Attrs().Index, ebpf.AttachTCXIngress, old.LanIngressL2, current.LanIngressL2},
		{f.lan.Attrs().Index, ebpf.AttachTCXEgress, old.LanEgressL2, current.LanEgressL2},
		{f.wan.Attrs().Index, ebpf.AttachTCXIngress, old.TproxyWanIngressL2, current.TproxyWanIngressL2},
		{f.wan.Attrs().Index, ebpf.AttachTCXEgress, old.TproxyWanEgressL2, current.TproxyWanEgressL2},
	} {
		l, err := link.AttachTCX(link.TCXOptions{Interface: attach.iface, Attach: attach.kind, Program: attach.old})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		updates = append(updates, func() {
			if err := l.Update(attach.current); err != nil {
				t.Fatal(err)
			}
		})
	}
	return old, current, func() {
		for _, update := range updates {
			update()
		}
	}
}

func (f *udpForwardNetwork) listen(t *testing.T, ns netns.NsHandle, ip netip.Addr, port uint16) *net.UDPConn {
	t.Helper()
	if err := netns.Set(ns); err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP(f.network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := netns.Set(f.router); err != nil {
		t.Fatal(err)
	}
	return conn
}

func udpSocketAddr(conn *net.UDPConn) netip.AddrPort {
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func sendUDPConntrack(t *testing.T, conn *net.UDPConn, to netip.AddrPort, payload string) {
	t.Helper()
	if _, err := conn.WriteToUDPAddrPort([]byte(payload), to); err != nil {
		t.Fatal(err)
	}
}

func receiveUDPConntrack(t *testing.T, conn *net.UDPConn, payload string) netip.AddrPort {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var buf [64]byte
	n, from, err := conn.ReadFromUDPAddrPort(buf[:])
	if err != nil || string(buf[:n]) != payload {
		t.Fatalf("receive %q: got %q from %v, error %v", payload, buf[:n], from, err)
	}
	return from
}

func rejectUDPConntrack(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var buf [64]byte
	n, from, err := conn.ReadFromUDPAddrPort(buf[:])
	if timeout, ok := errors.AsType[net.Error](err); !ok || !timeout.Timeout() {
		t.Fatalf("blocked/proxied flow: received %q from %v, error %v; want timeout", buf[:n], from, err)
	}
}

func TestUDPNotrackDoesNotExemptReplyAfterReplacement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for isolated conntrack tests")
	}
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			withUDPForwardNetwork(t, network, "none", func(f *udpForwardNetwork) {
				conn, err := nftables.New(nftables.WithNetNSFd(int(f.router)))
				if err != nil {
					t.Fatal(err)
				}
				family := nftables.TableFamilyIPv4
				if network == "udp6" {
					family = nftables.TableFamilyIPv6
				}
				table := conn.AddTable(&nftables.Table{Family: family, Name: "udp_notrack"})
				chain := conn.AddChain(&nftables.Chain{Name: "untracked", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRaw})
				conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
					&expr.Notrack{},
				}})
				if err := conn.Flush(); err != nil {
					t.Fatal(err)
				}
				old, current, replace := f.attachGenerations(t)
				server := f.listen(t, f.lanNS, f.lanIP, udpCTServicePort)
				client := f.listen(t, f.wanNS, f.wanIP, 0)
				serverAddr, clientAddr := udpSocketAddr(server), udpSocketAddr(client)
				sendUDPConntrack(t, client, serverAddr, "untracked-request-A")
				receiveUDPConntrack(t, server, "untracked-request-A")
				runUDP(t, old.ConntrackProbe, clientAddr, serverAddr, 0, 0)
				replace()
				runUDP(t, current.ConntrackProbe, serverAddr, clientAddr, 0, 0)
				sendUDPConntrack(t, server, clientAddr, "unproven-reply-B")
				rejectUDPConntrack(t, client)
			})
		})
	}
}
