// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/internal/routingabi"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Old sockets close before any new downstream program is installed.
// Exercise both internal link types without sharing generation-private maps.
func TestReplacementBlockAndIdleResetKernel(t *testing.T) {
	if os.Getenv("DAE_TEST_ISOLATED") != "1" {
		t.Skip("requires isolated network/mount namespaces and BPF privileges")
	}
	for _, device := range []string{"netkit", "veth"} {
		for _, origin := range []string{"LAN", "WAN"} {
			for _, family := range []string{"4", "6"} {
				t.Run(device+"/"+origin+"/IPv"+family, func(t *testing.T) {
					withInternalLinkDatapath(t, device, origin == "LAN", func(ns *DaeNetns, old *bpfObjects, links []link.Link) {
						testReplacementBlock(t, ns, old, links, family)
					})
				})
			}
		}
	}
}

func testReplacementBlock(t *testing.T, ns *DaeNetns, old *bpfObjects, links []link.Link, family string) {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	spec, err := loadBpf()
	must(err)
	var params bpfDaeParam
	must(old.PARAM.Get(&params))
	must(spec.Variables["PARAM"].Set(params))
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	next := new(bpfObjects)
	must(spec.LoadAndAssign(next, nil))
	defer next.Close()
	builder, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "dport(4444) -> must", "dport(4444) -> proxy(mark:37)"))
	builder.bpf = &BPFState{bpfObjects: next}
	must(builder.BuildKernspace())
	for _, version := range []uint8{4, 6} {
		for _, protocol := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			must(next.OutboundConnectivityMap.Update(bpfOutboundConnectivityQuery{Outbound: uint8(consts.OutboundUserDefinedMin), Ipversion: version, L4proto: protocol}, bpfOutboundConnectivity{State: outboundConnectivityAlive}, ebpf.UpdateAny))
		}
	}
	concurrentListenConfig := func() net.ListenConfig {
		lc := tproxyListenConfig()
		base := lc.Control
		lc.Control = func(network, address string, c syscall.RawConn) error {
			if err := base(network, address, c); err != nil {
				return err
			}
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}); err != nil {
				return err
			}
			return sockErr
		}
		return lc
	}
	listenTCP := func(address string, objects *bpfObjects) *net.TCPListener {
		t.Helper()
		l, err := ns.With(func() (net.Listener, error) {
			lc := concurrentListenConfig()
			return lc.Listen(t.Context(), "tcp"+family, address)
		})
		must(err)
		tcp := l.(*net.TCPListener)
		t.Cleanup(func() { tcp.Close() })
		must(registerSocket(objects.ListenSocketMap, uint32(0), tcp))
		must(tcp.SetDeadline(time.Now().Add(3 * time.Second)))
		return tcp
	}
	listenUDP := func(address string, objects *bpfObjects) *net.UDPConn {
		t.Helper()
		l, err := ns.With(func() (net.PacketConn, error) {
			lc := concurrentListenConfig()
			return lc.ListenPacket(t.Context(), "udp"+family, address)
		})
		must(err)
		udp := l.(*net.UDPConn)
		t.Cleanup(func() { udp.Close() })
		must(registerSocket(objects.ListenSocketMap, uint32(1), udp))
		must(udp.SetDeadline(time.Now().Add(3 * time.Second)))
		return udp
	}
	oldTCP, oldUDP := listenTCP(":0", old), listenUDP(":0", old)
	nextTCP, nextUDP := listenTCP(oldTCP.Addr().String(), next), listenUDP(oldUDP.LocalAddr().String(), next)
	target, firstIP, secondIP := "203.0.113.8:4444", "198.18.0.1", "198.18.0.2"
	if family == "6" {
		target, firstIP, secondIP = "[2001:db8:2::8]:4444", "2001:db8:1::1", "2001:db8:1::2"
	}
	dial := func(protocol, ip string) net.Conn {
		t.Helper()
		var addr net.Addr = &net.TCPAddr{IP: net.ParseIP(ip)}
		if protocol == "udp" {
			addr = &net.UDPAddr{IP: net.ParseIP(ip)}
		}
		conn, err := (&net.Dialer{LocalAddr: addr, Timeout: 3 * time.Second}).DialContext(t.Context(), protocol+family, target)
		must(err)
		t.Cleanup(func() { conn.Close() })
		must(conn.SetDeadline(time.Now().Add(3 * time.Second)))
		return conn
	}
	oldPeer := dial("tcp", firstIP)
	accepted, err := oldTCP.AcceptTCP()
	must(err)
	defer accepted.Close()
	backlogPeer := dial("tcp", firstIP)
	// Keep the old classifier serving while selecting the candidate's socket
	// program, so readiness is exercised independently of the entry guard.
	probe := dial("udp", secondIP)
	buf := make([]byte, 64)
	must(next.ExitedMap.Update(uint32(0), uint8(routingabi.DAEMON_STOPPING), ebpf.UpdateAny))
	must(links[netnsSocketLookup].Update(next.TproxySkLookup))
	_, err = probe.Write([]byte("not ready"))
	must(err)
	must(nextUDP.SetReadDeadline(time.Now().Add(30 * time.Millisecond)))
	if _, _, err := nextUDP.ReadFrom(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("candidate socket received before readiness: %v", err)
	}
	// SK_LOOKUP rejection can queue an ICMPv6 error on the connected probe.
	// Consume the stopped packet's result before testing the same socket online.
	must(probe.SetReadDeadline(time.Now().Add(30 * time.Millisecond)))
	if _, err := probe.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, unix.ECONNREFUSED) {
		t.Fatalf("stopped socket probe received data or an unexpected error: %v", err)
	}
	must(probe.SetReadDeadline(time.Now().Add(3 * time.Second)))
	// A ready socket can receive without route records in its private maps;
	// userspace admission owns the subsequent association/routing decision.
	must(next.ExitedMap.Update(uint32(0), uint8(routingabi.DAEMON_ONLINE), ebpf.UpdateAny))
	if _, err := probe.Write([]byte("ready")); err != nil {
		t.Fatalf("ready socket probe: %v", err)
	}
	must(nextUDP.SetReadDeadline(time.Now().Add(3 * time.Second)))
	n, _, err := nextUDP.ReadFrom(buf)
	must(err)
	if string(buf[:n]) != "ready" {
		t.Fatalf("candidate socket: %q", buf[:n])
	}
	must(links[netnsSocketLookup].Update(old.TproxySkLookup))
	must(next.ExitedMap.Update(uint32(0), uint8(routingabi.DAEMON_STOPPING), ebpf.UpdateAny))
	savedClient, err := netns.Get()
	must(err)
	defer savedClient.Close()
	oldRuntime := NewRuntime()
	oldRuntime.shared["exited_map"] = old.ExitedMap
	oldRuntime.kernelLinks.frozen = true
	snapshot := &ReplacementSnapshot{runtime: oldRuntime, frozen: true}
	defer snapshot.Release()
	info, err := links[netnsRoleCount].Info()
	must(err)
	ingressRole, egressRole := hostTCXLanIngress, hostTCXLanEgress
	if info.Program != programID(t, old.LanIngressL2) {
		ingressRole, egressRole = hostTCXWanIngress, hostTCXWanEgress
	}
	for i, l := range links {
		info, err := l.Info()
		must(err)
		retained, err := link.NewFromID(info.ID)
		must(err)
		d := ReplacementLink{Kind: "netns", Role: uint8(i), ID: uint32(info.ID)}
		if i >= netnsRoleCount {
			role := ingressRole
			if i == netnsRoleCount+1 {
				role = egressRole
			}
			d = ReplacementLink{Kind: "host", Role: uint8(role), Ifindex: int(info.TCX().Ifindex), Ethernet: true, ID: uint32(info.ID)}
		}
		snapshot.Links = append(snapshot.Links, d)
		snapshot.links = append(snapshot.links, retained)
	}
	nsPrograms := next.namespacePrograms()
	successor := append(nsPrograms[:], ingressRole.program(&next.bpfPrograms, true), egressRole.program(&next.bpfPrograms, true))
	nextRuntime := NewRuntime()
	defer nextRuntime.Close()
	nextRuntime.staged, nextRuntime.kernelLinks.preparing = true, true
	nextRuntime.shared["exited_map"] = next.ExitedMap
	nextRuntime.current = &ControlPlane{core: &controlPlaneCore{closed: t.Context()}}
	if ingressRole == hostTCXLanIngress {
		nextRuntime.current.lanInterface = []string{"dae-uplink"}
	} else {
		nextRuntime.current.wanInterface = []string{"dae-uplink"}
	}
	for i, d := range snapshot.Links {
		l := snapshot.links[i]
		if d.Kind == "netns" {
			if err := updateReplacementLink(l, successor[i], successor[i]); err == nil {
				t.Fatal("downstream update accepted a different old program")
			}
		}
		nextRuntime.replacementDescriptors = append(nextRuntime.replacementDescriptors, d)
		nextRuntime.replacementLinks = append(nextRuntime.replacementLinks, replacementAttachment{link: l, next: successor[i]})
		if d.Kind == "host" {
			nextRuntime.kernelLinks.hostTCXLinks = append(nextRuntime.kernelLinks.hostTCXLinks, hostTCXLink{linkIndex: d.Ifindex, role: hostTCXRole(d.Role), link: l, program: successor[i], close: l.Close})
		} else {
			nextRuntime.kernelLinks.netnsLinks = append(nextRuntime.kernelLinks.netnsLinks, l)
		}
	}
	must(snapshot.Block(t.Context()))
	// Captured UDP is blackholed while the old listener still exists.
	blocked := dial("udp", secondIP)
	_, err = blocked.Write([]byte("must drop"))
	must(err)
	must(oldUDP.SetReadDeadline(time.Now().Add(30 * time.Millisecond)))
	if _, _, err := oldUDP.ReadFrom(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("stopping reader received traffic: %v", err)
	}
	tracked := new(tcpConnectionSet)
	tracked.add(accepted)
	<-tracked.abort()
	must(oldTCP.Close())
	must(oldUDP.Close())
	if _, err := oldPeer.Read(buf); !errors.Is(err, unix.ECONNRESET) {
		t.Fatalf("idle peer did not receive RST through old return program: %v", err)
	}
	if _, err := backlogPeer.Read(buf); !errors.Is(err, unix.ECONNRESET) {
		t.Fatalf("old listener backlog did not receive RST: %v", err)
	}
	// The old return path has finished its job. Install entirely private
	// downstream programs, then new host entries behind the pinned guards.
	must(next.ExitedMap.Update(uint32(0), uint8(routingabi.DAEMON_STOPPING), ebpf.UpdateAny))
	must(netns.Set(ns.hostNs))
	must(activateReplacementForTest(nextRuntime))
	must(netns.Set(savedClient))
	// New sockets remain unreachable until the final guard is released.
	_, err = blocked.Write([]byte("still blocked"))
	must(err)
	must(nextUDP.SetReadDeadline(time.Now().Add(30 * time.Millisecond)))
	if _, _, err := nextUDP.ReadFrom(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("candidate bypassed stopping state: %v", err)
	}
	must(links[netnsRoleCount].Close())
	must(links[netnsRoleCount+1].Close())
	snapshot.Release()
	must(nextRuntime.finishReplacementGuards())
	must(nextUDP.SetReadDeadline(time.Now().Add(3 * time.Second)))
	connPeer, udpPeer := dial("tcp", secondIP), dial("udp", secondIP)
	_, err = connPeer.Write([]byte("new TCP"))
	must(err)
	_, err = udpPeer.Write([]byte("new UDP"))
	must(err)
	conn, err := nextTCP.AcceptTCP()
	must(err)
	defer conn.Close()
	must(conn.SetDeadline(time.Now().Add(3 * time.Second)))
	n, err = io.ReadFull(conn, buf[:len("new TCP")])
	must(err)
	if string(buf[:n]) != "new TCP" {
		t.Fatalf("new TCP: %q", buf[:n])
	}
	n, _, err = nextUDP.ReadFrom(buf)
	must(err)
	if string(buf[:n]) != "new UDP" {
		t.Fatalf("new UDP: %q", buf[:n])
	}
	_, err = conn.Write([]byte("new reply"))
	must(err)
	n, err = io.ReadFull(connPeer, buf[:len("new reply")])
	must(err)
	if string(buf[:n]) != "new reply" {
		t.Fatalf("new return: %q", buf[:n])
	}
	testInternalLinkUDP(t, ns, next, family, netip.MustParseAddrPort(target))
}

func programID(t *testing.T, p *ebpf.Program) ebpf.ProgramID {
	t.Helper()
	info, err := p.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := info.ID()
	return id
}
