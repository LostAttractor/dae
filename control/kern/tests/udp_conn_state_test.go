//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

// Matches DAE_REPLY_MARK in tproxy.c.
const daeReplyMark = 0xdae0dae0

const (
	tcxNext     = math.MaxUint32
	tcxRedirect = 7 // TC_ACT_REDIRECT
)

// Matches UDP_CONN_STATE_TIMEOUT_S in tproxy.c.
const udpConnStateTimeout = 300

func udpFlowKey(source, destination netip.AddrPort) bpftestTuplesKey {
	key := bpftestTuplesKey{Sport: nativeUint16(source.Port()), Dport: nativeUint16(destination.Port()), L4proto: unix.IPPROTO_UDP}
	key.Sip.U6Addr8 = source.Addr().As16()
	key.Dip.U6Addr8 = destination.Addr().As16()
	return key
}

func udpConnState(t *testing.T, obj *bpftestObjects, source, destination netip.AddrPort) (bpftestUdpConnState, bool) {
	t.Helper()
	var state bpftestUdpConnState
	err := obj.UdpConnStateMap.Lookup(udpFlowKey(source, destination), &state)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatal(err)
	}
	return state, err == nil
}

// pendingInbound reports whether an unanswered inbound flow waits for its
// first reply from source to destination.
func pendingInbound(t *testing.T, obj *bpftestObjects, source, destination netip.AddrPort) bool {
	t.Helper()
	var seen uint32
	err := obj.UdpInboundPendingMap.Lookup(udpFlowKey(source, destination), &seen)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// Datagrams from many sources that nobody answers take no state; the answer
// to one of them gives its flow inbound state, and the answer leaves directly.
// An inbound flow idle for the timeout has ended: its late answer is routed.
func testInboundAnswer(t *testing.T, obj *bpftestObjects, inbound, answer *ebpf.Program, local netip.AddrPort, remote func(uint16) netip.AddrPort, routed uint32) {
	t.Helper()
	for port := uint16(5000); port < 5064; port++ {
		runUDP(t, inbound, remote(port), local, 0, tcxNext)
		if _, ok := udpConnState(t, obj, local, remote(port)); ok || !pendingInbound(t, obj, local, remote(port)) {
			t.Fatalf("unanswered datagram from %v: state %v", remote(port), ok)
		}
	}
	runUDP(t, answer, local, remote(5000), 0, tcxNext)
	if state, ok := udpConnState(t, obj, local, remote(5000)); !ok || !state.IsWanIngressDirection {
		t.Fatalf("answered inbound state = %+v, %v", state, ok)
	}
	// Further datagrams refresh the state.
	runUDP(t, inbound, remote(5000), local, 0, tcxNext)
	runUDP(t, answer, local, remote(5000), 0, tcxNext)

	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC_COARSE, &now); err != nil {
		t.Fatal(err)
	}
	if err := obj.UdpInboundPendingMap.Update(udpFlowKey(local, remote(5001)), uint32(now.Sec)-udpConnStateTimeout-1, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	runUDP(t, answer, local, remote(5001), 0, routed)
	if state, ok := udpConnState(t, obj, local, remote(5001)); !ok || state.IsWanIngressDirection {
		t.Fatalf("late answer state = %+v, %v", state, ok)
	}
}

// runUDP classifies one datagram; ctx carries __sk_buff.cb[0] and returns the
// context after the program.
func runUDP(t *testing.T, program *ebpf.Program, source, destination netip.AddrPort, cb0 uint32, want uint32) []byte {
	t.Helper()
	ctx := make([]byte, 256)
	binary.NativeEndian.PutUint32(ctx[48:52], cb0) // __sk_buff.cb[0].
	packet := bridgePacket(source, destination, unix.IPPROTO_UDP, net.HardwareAddr{2, 0, 0, 0, 0, 1}, 0)
	status, _, ctxOut, err := runBpfProgram(program, packet, ctx)
	if err != nil || status != want {
		t.Fatalf("%v -> %v: status %d, error %v; want %d", source, destination, status, err, want)
	}
	return ctxOut
}

// WAN ingress runs before NAT and the firewall. Only a local socket can answer
// a packet without state, so only such a packet starts an inbound flow there,
// which takes state once the socket answers; forwarded flows get their state
// on LAN egress. Replies that dae relays belong to proxied associations and
// start outbound state.
func TestUDPInboundStateNeedsLocalSocket(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	const proxy = 2
	installRoutingFlow(t, obj, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback), Outbound: proxy}})
	for _, family := range []struct {
		network            string
		local, other, peer netip.Addr
		version            uint8
	}{
		{"udp4", netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.7"), 4},
		{"udp6", netip.MustParseAddr("::1"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8:1::7"), 6},
	} {
		t.Run(family.network, func(t *testing.T) {
			if err := obj.OutboundConnectivityMap.Update(bpftestOutboundConnectivityQuery{Outbound: proxy, L4proto: unix.IPPROTO_UDP, Ipversion: family.version}, bpftestOutboundConnectivity{}, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			conn, err := net.ListenUDP(family.network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(family.local, 0)))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			// The socket holds this address and port, so no wildcard socket does.
			service := conn.LocalAddr().(*net.UDPAddr).AddrPort()
			peer := func(port uint16) netip.AddrPort { return netip.AddrPortFrom(family.peer, port) }

			forwarded := netip.AddrPortFrom(family.other, service.Port())
			runUDP(t, obj.TproxyWanIngressL2, peer(4000), forwarded, 0, tcxNext)
			if _, ok := udpConnState(t, obj, forwarded, peer(4000)); ok || pendingInbound(t, obj, forwarded, peer(4000)) {
				t.Fatal("forwarded datagram started an inbound flow on WAN ingress")
			}

			testInboundAnswer(t, obj, obj.TproxyWanIngressL2, obj.TproxyWanEgressL2, service, peer, tcxRedirect)
			// The service's own new flows are routed.
			runUDP(t, obj.TproxyWanEgressL2, service, peer(4002), 0, tcxRedirect)
			if state, ok := udpConnState(t, obj, service, peer(4002)); !ok || state.IsWanIngressDirection {
				t.Fatalf("local outbound state = %+v, %v", state, ok)
			}
			// Its replies refresh the outbound state without turning it inbound.
			runUDP(t, obj.TproxyWanIngressL2, peer(4002), service, 0, tcxNext)
			if state, _ := udpConnState(t, obj, service, peer(4002)); state.IsWanIngressDirection {
				t.Fatal("reply turned an outbound flow inbound")
			}

			ctx := runUDP(t, obj.TproxyWanIngressL2, peer(4003), service, daeReplyMark, tcxNext)
			if state, ok := udpConnState(t, obj, service, peer(4003)); !ok || state.IsWanIngressDirection {
				t.Fatalf("relayed reply state = %+v, %v", state, ok)
			}
			if binary.NativeEndian.Uint32(ctx[48:52]) != 0 {
				t.Fatal("relay mark outlived the reply path")
			}

			raw, err := conn.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var updateErr error
			if err := raw.Control(func(fd uintptr) {
				updateErr = obj.SocketOwnerMap.Update(int32(fd), bpftestPidPname{Pid: uint32(os.Getpid())}, ebpf.UpdateAny)
			}); err != nil || updateErr != nil {
				t.Fatal(err, updateErr)
			}
			if err := obj.DaemonIdentityMap.Update(uint32(0), uint64(os.Getpid()), ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			runUDP(t, obj.TproxyWanIngressL2, peer(4004), service, 0, tcxNext)
			if _, ok := udpConnState(t, obj, service, peer(4004)); ok || pendingInbound(t, obj, service, peer(4004)) {
				t.Fatal("datagram to dae's socket started an inbound flow")
			}
		})
	}
}

// LAN egress sees forwarded flows after NAT. A datagram without state starts
// an inbound flow, e.g. a port forward, which takes state once the LAN host
// answers, unless dae relayed it: then the flow is outbound.
func TestUDPLANEgressInboundState(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	const proxy = 2
	installRoutingFlow(t, obj, []bpftestMatchSet{{Type: uint8(consts.MatchType_Fallback), Outbound: proxy}})
	if err := obj.OutboundConnectivityMap.Update(bpftestOutboundConnectivityQuery{Outbound: proxy, L4proto: unix.IPPROTO_UDP, Ipversion: 4}, bpftestOutboundConnectivity{}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	host := netip.MustParseAddrPort("192.168.1.10:5000")
	peer := func(port uint16) netip.AddrPort { return netip.AddrPortFrom(netip.MustParseAddr("198.51.100.7"), port) }

	testInboundAnswer(t, obj, obj.LanEgressL2, obj.LanIngressL2, host, peer, tcxRedirect)
	runUDP(t, obj.LanEgressL2, peer(4001), host, daeReplyMark, tcxNext)
	if state, ok := udpConnState(t, obj, host, peer(4001)); !ok || state.IsWanIngressDirection {
		t.Fatalf("relayed reply state = %+v, %v", state, ok)
	}
}

func TestUDPConnStateExpiry(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	if status, _, _, err := runBpfProgram(obj.TestExpireUdpConnState, make([]byte, 64), make([]byte, 256)); err != nil || status != 0 {
		t.Fatalf("UDP conn state expiry failed at step %d: %v", status, err)
	}
}
