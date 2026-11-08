// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// All links, routes, sockets, sysctls and nftables rules belong to disposable
// network namespaces. No program or map is pinned to the host's bpffs.
func TestTCPInboundNativeNATKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("BPF and network namespace privileges required")
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft is required for isolated DNAT tests")
	}
	for _, ipv6 := range []bool{false, true} {
		for _, mode := range []string{"local", "local-dnat", "forwarded-dnat", "bootstrap"} {
			t.Run(fmt.Sprintf("%s/ipv6=%t", mode, ipv6), func(t *testing.T) {
				testTCPInboundNativeNAT(t, nft, ipv6, mode)
			})
		}
	}
}

func testTCPInboundNativeNAT(t *testing.T, nft string, ipv6 bool, mode string) {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	runtime.LockOSThread()
	original, err := netns.Get()
	must(err)
	defer original.Close()
	defer func() {
		must(netns.Set(original))
		runtime.UnlockOSThread()
	}()
	router, err := netns.New()
	must(err)
	defer router.Close()
	configureDatapathTestNamespace(t)
	clientNS, err := netns.New()
	must(err)
	defer clientNS.Close()
	configureDatapathTestNamespace(t)
	must(netns.Set(router))
	serverNS := router
	if mode == "forwarded-dnat" {
		serverNS, err = netns.New()
		must(err)
		defer serverNS.Close()
		configureDatapathTestNamespace(t)
		must(netns.Set(router))
	}

	wan, clientIP := netip.MustParsePrefix("192.0.2.1/24"), netip.MustParsePrefix("192.0.2.2/24")
	lan, serverIP := netip.MustParsePrefix("198.51.100.1/24"), netip.MustParsePrefix("198.51.100.2/24")
	localIP := netip.MustParsePrefix("198.51.100.9/32")
	family, network, nftFamily := uint8(4), "tcp4", "ip"
	if ipv6 {
		wan, clientIP = netip.MustParsePrefix("2001:db8:1::1/64"), netip.MustParsePrefix("2001:db8:1::2/64")
		lan, serverIP = netip.MustParsePrefix("2001:db8:2::1/64"), netip.MustParsePrefix("2001:db8:2::2/64")
		localIP = netip.MustParsePrefix("2001:db8:3::9/128")
		family, network, nftFamily = 6, "tcp6", "ip6"
	}
	address := func(device netlink.Link, prefix netip.Prefix) {
		t.Helper()
		must(netlink.AddrAdd(device, &netlink.Addr{IPNet: &net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())}, Flags: unix.IFA_F_NODAD}))
		must(netlink.LinkSetUp(device))
	}
	pair := func(name, peer string, destination netns.NsHandle, hostIP, peerIP netip.Prefix) netlink.Link {
		t.Helper()
		must(netlink.LinkAdd(&netlink.Veth{Name: name, PeerName: peer}))
		host, err := netlink.LinkByName(name)
		must(err)
		address(host, hostIP)
		other, err := netlink.LinkByName(peer)
		must(err)
		must(netlink.LinkSetNsFd(other, int(destination)))
		must(netns.Set(destination))
		other, err = netlink.LinkByName(peer)
		must(err)
		address(other, peerIP)
		must(netlink.RouteAdd(&netlink.Route{LinkIndex: other.Attrs().Index, Gw: hostIP.Addr().AsSlice()}))
		must(netns.Set(router))
		return host
	}
	wanLink := pair("tcp-wan", "tcp-client", clientNS, wan, clientIP)
	var lanLink netlink.Link
	listenIP := wan.Addr()
	if mode == "forwarded-dnat" {
		lanLink = pair("tcp-lan", "tcp-server", serverNS, lan, serverIP)
		listenIP = serverIP.Addr()
		must(os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0))
		must(os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0))
	} else if mode == "local-dnat" {
		lo, err := netlink.LinkByName("lo")
		must(err)
		address(lo, localIP)
		listenIP = localIP.Addr()
	}

	collection, state := routingKernelFixture(t, nil, 0, func(spec *ebpf.CollectionSpec) {
		full, err := loadBpf()
		must(err)
		for _, name := range []string{"lan_egress_l2", "tproxy_wan_ingress_l2"} {
			spec.Programs[name] = full.Programs[name]
		}
	})
	builder, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "l4proto(tcp) -> proxy"))
	builder.bpf = state
	must(builder.BuildKernspace())
	must(collection.Maps["outbound_connectivity_map"].Update(bpfOutboundConnectivityQuery{Outbound: uint8(consts.OutboundUserDefinedMin), Ipversion: family, L4proto: unix.IPPROTO_TCP}, bpfOutboundConnectivity{State: outboundConnectivityAlive}, ebpf.UpdateAny))
	must(collection.Variables["unexpected_exit_behavior"].Set(uint32(consts.OutboundBlock)))
	attach := func(device netlink.Link, program string, direction ebpf.AttachType) {
		t.Helper()
		attached, err := link.AttachTCX(link.TCXOptions{Interface: device.Attrs().Index, Program: collection.Programs[program], Attach: direction})
		must(err)
		t.Cleanup(func() { _ = attached.Close() })
	}
	attach(wanLink, "tproxy_wan_ingress_l2", ebpf.AttachTCXIngress)
	attach(wanLink, "tproxy_wan_egress_l2", ebpf.AttachTCXEgress)
	if lanLink != nil {
		attach(lanLink, "lan_ingress_l2", ebpf.AttachTCXIngress)
		attach(lanLink, "lan_egress_l2", ebpf.AttachTCXEgress)
	}
	listenerNS := serverNS
	if mode == "bootstrap" {
		listenerNS, listenIP = clientNS, clientIP.Addr()
	}
	must(netns.Set(listenerNS))
	listener, err := net.Listen(network, netip.AddrPortFrom(listenIP, 0).String())
	must(err)
	defer listener.Close()
	deadline := time.Now().Add(5 * time.Second)
	must(listener.(*net.TCPListener).SetDeadline(deadline))
	target := netip.AddrPortFrom(wan.Addr(), listener.Addr().(*net.TCPAddr).AddrPort().Port())
	must(netns.Set(router))
	if mode == "bootstrap" {
		target = netip.AddrPortFrom(clientIP.Addr(), target.Port())
	}
	if mode != "local" && mode != "bootstrap" {
		target = netip.AddrPortFrom(wan.Addr(), 43000)
		rules := fmt.Sprintf("table %s dae_test {\n chain prerouting {\n  type nat hook prerouting priority dstnat; policy accept;\n  %s daddr %s tcp dport %d dnat to %s;\n }\n}\n", nftFamily, nftFamily, wan.Addr(), target.Port(), listener.Addr())
		cmd := exec.Command(nft, "-f", "-")
		cmd.Stdin = strings.NewReader(rules)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("install private DNAT rule: %v: %s", err, output)
		}
	}
	served := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(deadline)
		var payload [3]byte
		for range 2 {
			if _, err := io.ReadFull(conn, payload[:]); err != nil {
				served <- err
				return
			}
			if _, err := conn.Write(payload[:]); err != nil {
				served <- err
				return
			}
		}
		served <- nil
	}()
	dialer := net.Dialer{Deadline: deadline}
	if mode == "bootstrap" {
		setKernelOffline(t, collection, true)
		must(collection.Maps["daemon_identity_map"].Update(uint32(0), uint64(os.Getpid()), ebpf.UpdateAny))
		owner := uint32(os.Getpid() + 1)
		dialer.Control = func(_, _ string, raw syscall.RawConn) error {
			var result error
			err := raw.Control(func(fd uintptr) {
				result = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, 0x100)
				if result == nil {
					result = collection.Maps["socket_owner_map"].Update(uint32(fd), bpfPidPname{Pid: owner}, ebpf.UpdateAny)
				}
			})
			return errors.Join(err, result)
		}
		// A real socket carrying the same mark but a different recorded owner
		// must not inherit the daemon's offline bootstrap permission.
		dialer.Timeout = 150 * time.Millisecond
		unexpected, err := dialer.DialContext(t.Context(), network, target.String())
		if unexpected != nil {
			unexpected.Close()
			t.Fatal("unregistered socket bypassed offline proxy policy")
		}
		if failure, ok := errors.AsType[net.Error](err); !ok || !failure.Timeout() {
			t.Fatalf("unregistered dial: %v, want policy-induced timeout", err)
		}
		owner, dialer.Timeout = uint32(os.Getpid()), 0
	} else {
		must(netns.Set(clientNS))
	}
	client, err := dialer.DialContext(t.Context(), network, target.String())
	must(err)
	defer client.Close()
	must(client.SetDeadline(deadline))
	must(netns.Set(router))
	for _, payload := range [][]byte{[]byte("one"), []byte("two")} {
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
		var response [3]byte
		if _, err := io.ReadFull(client, response[:]); err != nil || !bytes.Equal(response[:], payload) {
			t.Fatalf("native TCP echo: got %q, error %v; want %q", response, err, payload)
		}
		setKernelOffline(t, collection, true)
	}
	must(<-served)
}
