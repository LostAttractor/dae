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
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Exercise real namespace crossings, SK_LOOKUP and replies through the
// production programs. Everything, including sysctls and interface names, lives
// in disposable namespaces; the machine's active dae instance is untouched.
func TestInternalLinkDatapathIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for isolated datapath tests")
	}
	for _, linkType := range []string{"netkit", "veth"} {
		for _, origin := range []string{"WAN", "LAN"} {
			t.Run(linkType+"/"+origin, func(t *testing.T) {
				withInternalLinkDatapath(t, linkType, origin == "LAN", func(ns *DaeNetns, objects *bpfObjects) {
					for _, family := range []string{"4", "6"} {
						target := netip.MustParseAddrPort("203.0.113.8:4444")
						if family == "6" {
							target = netip.MustParseAddrPort("[2001:db8:2::8]:4444")
						}
						t.Log("TCP" + family)
						testInternalLinkTCP(t, ns, objects, family, target)
						t.Log("UDP" + family)
						testInternalLinkUDP(t, ns, objects, family, target)
					}
				})
			})
		}
	}
}

func withInternalLinkDatapath(t *testing.T, linkType string, lan bool, run func(*DaeNetns, *bpfObjects)) {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(rlimit.RemoveMemlock())
	runtime.LockOSThread()
	original, err := netns.Get()
	must(err)
	defer original.Close()
	defer func() {
		// Leave a thread locked on restoration failure so it cannot be reused.
		must(netns.Set(original))
		runtime.UnlockOSThread()
	}()
	host, err := netns.New()
	must(err)
	defer host.Close()
	configureDatapathTestNamespace(t)
	peerNS, err := netns.New()
	must(err)
	defer peerNS.Close()
	configureDatapathTestNamespace(t)
	must(netns.Set(host))
	err = createDaeLinkPair(hostLinkName, peerLinkName, func(device netlink.Link) error {
		if linkType == "veth" && device.Type() == "netkit" {
			return unix.EOPNOTSUPP
		}
		return netlink.LinkAdd(device)
	})
	must(err)
	primary, err := netlink.LinkByName(hostLinkName)
	must(err)
	if primary.Type() != linkType {
		t.Skipf("kernel does not support %s", linkType)
	}
	must(netlink.LinkSetUp(primary))
	peer, err := netlink.LinkByName(peerLinkName)
	must(err)
	must(netlink.LinkSetNsFd(peer, int(peerNS)))
	must(netns.Set(peerNS))
	peer, err = netlink.LinkByName(peerLinkName)
	must(err)
	must(netlink.LinkSetUp(peer))
	must(netns.Set(host))
	ns := &DaeNetns{dae0: primary, dae0peer: peer, hostNs: host, daeNs: peerNS}
	ns.setupDone.Store(true)
	must(ns.setupIPv4Datapath())
	must(ns.setupIPv6Datapath())
	must(ns.setupRoutingPolicy())

	var uplink netlink.Link = &netlink.Dummy{Name: "dae-uplink", HardwareAddr: net.HardwareAddr{2, 1, 2, 3, 4, 5}}
	if lan {
		uplink = &netlink.Veth{Name: "dae-uplink", PeerName: "test-client"}
	}
	must(netlink.LinkAdd(uplink))
	uplink, err = netlink.LinkByName("dae-uplink")
	must(err)
	must(netlink.LinkSetUp(uplink))
	clientNS := host
	clientLink, targetMAC := uplink, net.HardwareAddr{2, 1, 2, 3, 4, 8}
	if lan {
		clientLink, err = netlink.LinkByName("test-client")
		must(err)
		clientNS, err = netns.New()
		must(err)
		defer clientNS.Close()
		configureDatapathTestNamespace(t)
		must(netns.Set(host))
		must(netlink.LinkSetNsFd(clientLink, int(clientNS)))
		must(netns.Set(clientNS))
		clientLink, err = netlink.LinkByName("test-client")
		must(err)
		must(netlink.LinkSetUp(clientLink))
		targetMAC = uplink.Attrs().HardwareAddr
	}
	for _, cidr := range []string{"198.18.0.1/24", "2001:db8:1::1/64"} {
		addr, err := netlink.ParseAddr(cidr)
		must(err)
		addr.Flags = unix.IFA_F_NODAD
		must(netlink.AddrAdd(clientLink, addr))
	}
	for _, address := range []string{"203.0.113.8/32", "2001:db8:2::8/128"} {
		ip, prefix, err := net.ParseCIDR(address)
		must(err)
		must(netlink.RouteAdd(&netlink.Route{LinkIndex: clientLink.Attrs().Index, Dst: prefix, Scope: netlink.SCOPE_LINK}))
		must(netlink.NeighSet(&netlink.Neigh{LinkIndex: clientLink.Attrs().Index, IP: ip, HardwareAddr: targetMAC, State: netlink.NUD_PERMANENT}))
	}
	must(netns.Set(host))

	spec, err := loadBpf()
	must(err)
	must(spec.Variables["PARAM"].Set(bpfDaeParam{
		ControlPlanePid: uint32(os.Getpid()), Dae0Ifindex: uint32(primary.Attrs().Index),
		Dae0peerIfindex: uint32(peer.Attrs().Index), Dae0peerMac: [6]uint8(peer.Attrs().HardwareAddr), SoMarkFromDae: 0x100,
	}))
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	objects := new(bpfObjects)
	must(spec.LoadAndAssign(objects, nil))
	defer objects.Close()
	_, builder := routingMatcherForTest(t, prepareFlowRulesForTest(t, "dport(4444) -> must", "dport(4444) -> proxy(mark:37)"))
	builder.bpf = &BPFState{bpfObjects: objects}
	must(builder.BuildKernspace())
	for _, family := range []uint8{4, 6} {
		for _, proto := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			must(objects.OutboundConnectivityMap.Update(bpfOutboundConnectivityQuery{
				Outbound: uint8(consts.OutboundUserDefinedMin), Ipversion: family, L4proto: proto,
			}, uint32(0), ebpf.UpdateAny))
		}
	}
	internalLinks, err := ns.attachPrograms(objects.bpfPrograms)
	must(err)
	defer closeBpfLinks(internalLinks)
	ingressProgram, egressProgram := objects.TproxyWanIngressL2, objects.TproxyWanEgressL2
	if lan {
		ingressProgram, egressProgram = objects.LanIngressL2, objects.LanEgressL2
	}
	egress, err := link.AttachTCX(link.TCXOptions{Interface: uplink.Attrs().Index, Program: egressProgram, Attach: ebpf.AttachTCXEgress})
	must(err)
	defer egress.Close()
	ingress, err := link.AttachTCX(link.TCXOptions{Interface: uplink.Attrs().Index, Program: ingressProgram, Attach: ebpf.AttachTCXIngress})
	must(err)
	defer ingress.Close()
	must(netns.Set(clientNS))
	run(ns, objects)
}

func configureDatapathTestNamespace(t *testing.T) {
	t.Helper()
	for _, setting := range []string{
		"ipv4/conf/all/rp_filter", "ipv4/conf/default/rp_filter",
		"ipv6/conf/all/disable_ipv6", "ipv6/conf/default/disable_ipv6",
		"ipv6/conf/all/accept_dad", "ipv6/conf/default/accept_dad",
	} {
		if err := os.WriteFile("/proc/sys/net/"+setting, []byte("0"), 0); err != nil {
			t.Fatal(err)
		}
	}
	lo, err := netlink.LinkByIndex(consts.LoopbackIfIndex)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
}

func internalLinkListenerConfig() net.ListenConfig {
	return net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error { return dialer.TproxyControl(raw) }}
}

func testInternalLinkTCP(t *testing.T, ns *DaeNetns, objects *bpfObjects, family string, target netip.AddrPort) {
	t.Helper()
	listener, err := ns.With(func() (net.Listener, error) {
		lc := internalLinkListenerConfig()
		return lc.Listen(t.Context(), "tcp"+family, ":0")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	tcp := listener.(*net.TCPListener)
	if err := registerListener(objects.ListenSocketMap, 0, tcp); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	tcp.SetDeadline(deadline)
	payload := []byte("internal TCP echo")
	response := make(chan error, 1)
	go func() {
		accepted, err := tcp.AcceptTCP()
		if err != nil {
			response <- err
			return
		}
		defer accepted.Close()
		accepted.SetDeadline(deadline)
		if accepted.LocalAddr().(*net.TCPAddr).AddrPort() != target {
			response <- fmt.Errorf("TCP destination changed: %s, want %s", accepted.LocalAddr(), target)
			return
		}
		buf := make([]byte, len(payload))
		_, err = io.ReadFull(accepted, buf)
		if err == nil {
			_, err = accepted.Write(buf)
		}
		response <- err
	}()
	client, err := (&net.Dialer{Deadline: deadline}).DialContext(t.Context(), "tcp"+family, target.String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(deadline)
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(client, buf); err != nil || !bytes.Equal(buf, payload) {
		t.Fatalf("TCP reply=%q err=%v", buf, err)
	}
	if err := <-response; err != nil {
		t.Fatal(err)
	}
	assertInternalLinkRoute(t, objects, client.LocalAddr().(*net.TCPAddr).AddrPort(), target, unix.IPPROTO_TCP)
}

func testInternalLinkUDP(t *testing.T, ns *DaeNetns, objects *bpfObjects, family string, target netip.AddrPort) {
	t.Helper()
	listener, err := ns.With(func() (net.PacketConn, error) {
		lc := internalLinkListenerConfig()
		return lc.ListenPacket(t.Context(), "udp"+family, ":0")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	udp := listener.(*net.UDPConn)
	if err := registerListener(objects.ListenSocketMap, 1, udp); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	udp.SetDeadline(deadline)
	client, err := (&net.Dialer{Deadline: deadline}).DialContext(t.Context(), "udp"+family, target.String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(deadline)
	payload := []byte("internal UDP echo")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf, oob := make([]byte, 256), make([]byte, 128)
	n, oobn, _, source, err := udp.ReadMsgUDPAddrPort(buf, oob)
	if err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("UDP request=%q err=%v", buf[:n], err)
	}
	if destination := common.ConvergeAddrPort(RetrieveOriginalDest(oob[:oobn])); destination != target {
		t.Fatalf("UDP destination changed: %s, want %s", destination, target)
	}
	if source != client.LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Fatalf("UDP source changed: %s, want %s", source, client.LocalAddr())
	}
	reply, err := ns.With(func() (net.PacketConn, error) {
		lc := internalLinkListenerConfig()
		return lc.ListenPacket(t.Context(), "udp"+family, target.String())
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Close()
	if _, err := reply.WriteTo(buf[:n], net.UDPAddrFromAddrPort(source)); err != nil {
		t.Fatal(err)
	}
	n, err = client.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("UDP reply=%q err=%v", buf[:n], err)
	}
	assertInternalLinkRoute(t, objects, source, target, unix.IPPROTO_UDP)
}

func assertInternalLinkRoute(t *testing.T, objects *bpfObjects, source, destination netip.AddrPort, proto uint8) {
	t.Helper()
	key := bpfTuplesKey{Sport: common.Htons(source.Port()), Dport: common.Htons(destination.Port()), L4proto: proto}
	key.Sip.U6Addr8, key.Dip.U6Addr8 = source.Addr().As16(), destination.Addr().As16()
	var result bpfRoutingResult
	err := lookupKernelHandoff(objects.RoutingTuplesMap, key, &result)
	if err != nil || result.Outbound != uint8(consts.OutboundUserDefinedMin) || result.Mark != 37 || result.Must != 1 {
		t.Fatalf("handoff changed outbound/mark/must: result=%+v err=%v", result, err)
	}
	// Direct rules never gain a userspace handoff merely because veth is used.
	if !source.Addr().Is4() {
		return
	}
	packet, _ := routingKernelPacket(source, netip.MustParseAddrPort("10.0.0.1:22"), consts.L4ProtoType_TCP)
	verdict, err := objects.TproxyWanEgressL2.Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256), Repeat: 1})
	if err != nil || verdict != ^uint32(0) {
		t.Fatalf("SSH left the kernel-direct path: verdict=%d err=%v", verdict, err)
	}
	key.Dip.U6Addr8, key.Dport, key.L4proto = netip.MustParseAddr("10.0.0.1").As16(), common.Htons(22), unix.IPPROTO_TCP
	if err := lookupKernelHandoff(objects.RoutingTuplesMap, key, &result); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("direct SSH created proxy state: %+v %v", result, err)
	}
}
