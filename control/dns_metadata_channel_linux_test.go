// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestDNSMetadataChannelIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for isolated datapath tests")
	}
	for _, kind := range []string{"netkit", "veth"} {
		for _, lan := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/LAN=%v", kind, lan), func(t *testing.T) {
				withInternalLinkDatapath(t, kind, lan, func(ns *DaeNetns, objects *bpfObjects) {
					if _, err := ns.With(func() (struct{}, error) {
						return struct{}{}, netlink.LinkSetMTU(ns.dae0peer, 1280)
					}); err != nil {
						t.Fatal(err)
					}
					for _, family := range []string{"4", "6"} {
						maximum := maxUDPv4Payload
						if family == "6" {
							maximum = maxUDPv6Payload
						}
						for _, raw := range []bool{false, true} {
							for _, size := range []int{32, 64000, maximum} {
								t.Logf("IPv%s/raw=%v/size=%d", family, raw, size)
								testDNSMetadataChannel(t, ns, objects, family, lan, raw, size, 1)
							}
						}
					}
				})
			})
		}
	}
}

func TestDNSLargeRequestIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for isolated datapath tests")
	}
	for _, kind := range []string{"netkit", "veth"} {
		for _, lan := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/LAN=%v", kind, lan), func(t *testing.T) {
				withInternalLinkDatapath(t, kind, lan, func(ns *DaeNetns, objects *bpfObjects) {
					must := func(err error) {
						t.Helper()
						if err != nil {
							t.Fatal(err)
						}
					}
					clientNS, err := netns.Get()
					must(err)
					defer clientNS.Close()
					defer func() { must(netns.Set(clientNS)) }()
					// Test complete large requests without widening fragment support; veth does not fragment oversized packets.
					for _, namespace := range []netns.NsHandle{ns.hostNs, ns.daeNs, clientNS} {
						must(netns.Set(namespace))
						links, err := netlink.LinkList()
						must(err)
						for _, l := range links {
							must(netlink.LinkSetMTU(l, 65535))
						}
					}
					for _, family := range []string{"4", "6"} {
						testDNSMetadataChannel(t, ns, objects, family, lan, false, 64000, 64000)
					}
				})
			})
		}
	}
}

func TestDNSQueuedSourceIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for isolated datapath tests")
	}
	for _, kind := range []string{"netkit", "veth"} {
		for _, family := range []string{"4", "6"} {
			t.Run(kind+"/IPv"+family, func(t *testing.T) {
				withInternalLinkDatapath(t, kind, true, func(ns *DaeNetns, objects *bpfObjects) {
					testDNSQueuedSources(t, ns, objects, family)
				})
			})
		}
	}
}

func testDNSQueuedSources(t *testing.T, ns *DaeNetns, objects *bpfObjects, family string) {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	plane, cleanup := dnsMetadataReplyPlane(ns, objects)
	defer cleanup()
	target := netip.MustParseAddrPort("203.0.113.8:53")
	if family == "6" {
		target = netip.MustParseAddrPort("[2001:db8:2::8]:53")
	}
	listener := dnsMetadataListener(t, ns, objects, family)
	defer listener.Close()
	lan, err := net.DialUDP("udp"+family, nil, net.UDPAddrFromAddrPort(target))
	must(err)
	defer lan.Close()
	source := lan.LocalAddr().(*net.UDPAddr).AddrPort()
	original, err := netns.Get()
	must(err)
	defer original.Close()
	defer func() { must(netns.Set(original)) }()
	must(netns.Set(ns.hostNs))
	// Add a local egress inside the test namespace with the same source address and port as the LAN client.
	must(netlink.LinkAdd(&netlink.Dummy{Name: "dns-local", HardwareAddr: net.HardwareAddr{2, 1, 2, 3, 4, 9}}))
	localLink, err := netlink.LinkByName("dns-local")
	must(err)
	must(netlink.LinkSetUp(localLink))
	bits := source.Addr().BitLen()
	addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", source.Addr(), bits))
	must(err)
	addr.Flags = unix.IFA_F_NODAD
	must(netlink.AddrAdd(localLink, addr))
	ip, prefix, err := net.ParseCIDR(fmt.Sprintf("%s/%d", target.Addr(), bits))
	must(err)
	must(netlink.RouteAdd(&netlink.Route{LinkIndex: localLink.Attrs().Index, Dst: prefix, Scope: netlink.SCOPE_LINK}))
	must(netlink.NeighSet(&netlink.Neigh{LinkIndex: localLink.Attrs().Index, IP: ip, HardwareAddr: net.HardwareAddr{2, 1, 2, 3, 4, 8}, State: netlink.NUD_PERMANENT}))
	for _, attachment := range []struct {
		program *ebpf.Program
		kind    ebpf.AttachType
	}{{objects.TproxyWanIngressL2, ebpf.AttachTCXIngress}, {objects.TproxyWanEgressL2, ebpf.AttachTCXEgress}} {
		l, err := link.AttachTCX(link.TCXOptions{Interface: localLink.Attrs().Index, Program: attachment.program, Attach: attachment.kind})
		must(err)
		defer l.Close()
	}
	local, err := net.DialUDP("udp"+family, net.UDPAddrFromAddrPort(source), net.UDPAddrFromAddrPort(target))
	must(err)
	defer local.Close()
	_, err = lan.Write([]byte("LAN"))
	must(err)
	_, err = local.Write([]byte("local"))
	must(err)
	identities := make(map[string]*routingResult)
	for range 2 {
		query, receivedSource, identity := receiveDNSMetadata(t, listener, objects)
		if receivedSource != source {
			t.Fatalf("source=%v, want=%v", receivedSource, source)
		}
		identities[string(query)] = identity
	}
	if len(identities) != 2 || identities["LAN"] == nil || identities["local"] == nil {
		t.Fatalf("queued requests: %v", identities)
	}
	lanIdentity, localIdentity := identities["LAN"], identities["local"]
	if lanIdentity.sourceOrigin() != plugin.SourceLAN || localIdentity.sourceOrigin() != plugin.SourceLocal || lanIdentity.dns.cookie == localIdentity.dns.cookie || lanIdentity.Ifindex == localIdentity.Ifindex {
		t.Fatalf("source identity was overwritten: LAN=%+v local=%+v", lanIdentity, localIdentity)
	}
	for _, reply := range []struct {
		name   string
		client *net.UDPConn
	}{{"local", local}, {"LAN", lan}} {
		must(plane.sendDNSReply([]byte(reply.name), target, source, identities[reply.name].dns))
		reply.client.SetReadDeadline(time.Now().Add(3 * time.Second))
		var buffer [32]byte
		n, from, err := reply.client.ReadFromUDPAddrPort(buffer[:])
		must(err)
		if from != target || string(buffer[:n]) != reply.name {
			t.Fatalf("reply reached wrong source: %s from=%v data=%q", reply.name, from, buffer[:n])
		}
	}
}

func dnsMetadataListener(t *testing.T, ns *DaeNetns, objects *bpfObjects, family string) *net.UDPConn {
	t.Helper()
	listener, err := ns.With(func() (net.PacketConn, error) {
		lc := tproxyListenConfig()
		return lc.ListenPacket(t.Context(), "udp"+family, ":0")
	})
	if err != nil {
		t.Fatal(err)
	}
	udp := listener.(*net.UDPConn)
	if err := registerSocket(objects.ListenSocketMap, uint32(1), udp); err != nil {
		udp.Close()
		t.Fatal(err)
	}
	return udp
}

func receiveDNSMetadata(t *testing.T, listener *net.UDPConn, objects *bpfObjects) ([]byte, netip.AddrPort, *routingResult) {
	t.Helper()
	listener.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf, oob := make([]byte, udpReceiveBufferSize), make([]byte, udpOOBSize)
	n, oobn, flags, source, err := listener.ReadMsgUDPAddrPort(buf, oob)
	if err != nil {
		t.Fatalf("receive DNS request: %v", err)
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		t.Fatalf("truncated DNS request: flags=%d", flags)
	}
	metadata, valid := parseUDPMetadata(oob[:oobn])
	if !valid || !metadata.validDNS() {
		t.Fatalf("invalid DNS metadata: %+v", metadata)
	}
	source = common.ConvergeAddrPort(source)
	identity, err := retrieveDNSRoutingResult(objects.DnsHandoffMap, source, metadata.destination, metadata.cookie)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retrieveDNSRoutingResult(objects.DnsHandoffMap, source, metadata.destination, metadata.cookie); err == nil {
		t.Fatal("DNS handoff was consumed twice")
	}
	return buf[:n], source, identity
}

func dnsMetadataReplyPlane(ns *DaeNetns, objects *bpfObjects) (*ControlPlane, func()) {
	previousNS, previousPool := daeNetns, DefaultAnyfromPool
	pool := NewAnyfromPool()
	daeNetns, DefaultAnyfromPool = ns, pool
	return &ControlPlane{core: &controlPlaneCore{bpf: &BPFState{bpfObjects: objects}}}, func() {
		pool.mu.Lock()
		for _, socket := range pool.pool {
			socket.idleEvictTimer.Stop()
			socket.Close()
		}
		pool.mu.Unlock()
		daeNetns, DefaultAnyfromPool = previousNS, previousPool
	}
}

func testDNSMetadataChannel(t *testing.T, ns *DaeNetns, objects *bpfObjects, family string, lan, raw bool, size, querySize int) {
	t.Helper()
	plane, cleanup := dnsMetadataReplyPlane(ns, objects)
	defer cleanup()
	target := netip.MustParseAddrPort("203.0.113.8:53")
	if family == "6" {
		target = netip.MustParseAddrPort("[2001:db8:2::8]:53")
	}
	listener := dnsMetadataListener(t, ns, objects, family)
	defer listener.Close()
	if raw {
		// Occupy wildcard:53 so a real bind failure sends sendDNSReply through raw fallback.
		conflict, err := ns.With(func() (net.PacketConn, error) {
			return net.ListenPacket("udp"+family, ":53")
		})
		if err != nil {
			t.Fatal(err)
		}
		defer conflict.Close()
	}
	client, err := net.DialUDP("udp"+family, nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	// Queue three packets with the same tuple, consume their snapshots, then reply in reverse order.
	for i := range 3 {
		if _, err := client.Write(bytes.Repeat([]byte{byte(i)}, querySize)); err != nil {
			t.Fatal(err)
		}
	}
	var identities [3]*routingResult
	var source netip.AddrPort
	for i := range identities {
		var query []byte
		query, source, identities[i] = receiveDNSMetadata(t, listener, objects)
		if !bytes.Equal(query, bytes.Repeat([]byte{byte(i)}, querySize)) {
			t.Fatalf("queued query = %x", query)
		}
		wantOrigin := plugin.SourceLocal
		if lan {
			wantOrigin = plugin.SourceLAN
		}
		if identities[i].sourceOrigin() != wantOrigin || identities[i].Must != 0 {
			t.Fatalf("identity = %+v", identities[i])
		}
		if i != 0 && identities[i].dns.cookie <= identities[i-1].dns.cookie {
			t.Fatal("DNS packet cookies were reused")
		}
	}
	for i := len(identities) - 1; i >= 0; i-- {
		payload := bytes.Repeat([]byte{byte(i)}, size)
		if err := plane.sendDNSReply(payload, target, source, identities[i].dns); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, udpReceiveBufferSize)
		n, from, err := client.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("read DNS reply: %v", err)
		}
		if from != target || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("reply source=%v length=%d, want source=%v length=%d", from, n, target, size)
		}
	}
	var key bpfRedirectTuple
	var value bpfRedirectEntry
	if objects.RedirectTrack.Iterate().Next(&key, &value) {
		t.Fatal("ordinary DNS wrote the shared legacy reply table")
	}
}
