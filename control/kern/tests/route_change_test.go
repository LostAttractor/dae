//go:build linux && dae_bpf_tests

package tests

import (
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Checksums are irrelevant to TC program tests, which inspect routing before
// the host IP/TCP stacks. Exercise both address families with the same MAC.
func devicePacket(ipv6 bool, proto byte, flags byte) ([]byte, bpftestTuplesKey) {
	mac := [6]byte{2, 0, 0, 0, 0, 10}
	key := bpftestTuplesKey{Sport: nativeUint16(32000), Dport: nativeUint16(443), L4proto: proto}
	size := 20
	if ipv6 {
		size = 40
	}
	transport := 20
	if proto == unix.IPPROTO_UDP {
		transport = 8
	}
	packet := make([]byte, 14+size+transport+8)
	copy(packet[6:12], mac[:])
	if ipv6 {
		binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IPV6)
		key.Sip.U6Addr8 = netip.MustParseAddr("fd00::10").As16()
		key.Dip.U6Addr8 = netip.MustParseAddr("2001:db8::1").As16()
		packet[14] = 0x60
		packet[20] = proto
		packet[21] = 64
		binary.BigEndian.PutUint16(packet[18:20], uint16(transport+8))
		copy(packet[22:38], key.Sip.U6Addr8[:])
		copy(packet[38:54], key.Dip.U6Addr8[:])
	} else {
		binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IP)
		key.Sip.U6Addr8 = netip.MustParseAddr("192.0.2.10").As16()
		key.Dip.U6Addr8 = netip.MustParseAddr("198.51.100.1").As16()
		packet[14] = 0x45
		packet[22] = 64
		packet[23] = proto
		binary.BigEndian.PutUint16(packet[16:18], uint16(size+transport+8))
		copy(packet[26:30], key.Sip.U6Addr8[12:])
		copy(packet[30:34], key.Dip.U6Addr8[12:])
	}
	payload := packet[14+size:]
	binary.BigEndian.PutUint16(payload[:2], 32000)
	binary.BigEndian.PutUint16(payload[2:4], 443)
	if proto == unix.IPPROTO_TCP {
		payload[12] = 0x50
		payload[13] = flags
	} else {
		binary.BigEndian.PutUint16(payload[4:6], uint16(transport+8))
	}
	return packet, key
}

func TestDeviceRouteEpochs(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	const (
		next     = uint32(math.MaxUint32)
		drop     = uint32(2)
		redirect = uint32(7)
	)
	mac := [6]byte{2, 0, 0, 0, 0, 10}
	run := func(packet []byte, want uint32) {
		t.Helper()
		status, _, _, err := runBpfProgram(obj.LanIngressL2, packet, make([]byte, 256))
		if err != nil || status != want {
			t.Fatalf("TC status=%d want=%d: %v", status, want, err)
		}
	}
	epoch := func(value uint64, updating uint32) {
		t.Helper()
		if err := obj.UnusedDeviceRoutes.Update(mac, bpftestDeviceRouteState{Epoch: value, Updating: updating}, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	route := func(outbound uint8) {
		t.Helper()
		if err := obj.RoutingMap.Update(uint32(0), bpftestMatchSet{Type: 11, Outbound: outbound}, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	for _, ipv6 := range []bool{false, true} {
		t.Logf("IPv6=%v", ipv6)
		version := uint8(4)
		if ipv6 {
			version = 6
		}
		for _, proto := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			if err := obj.OutboundConnectivityMap.Update(bpftestOutboundConnectivityQuery{Outbound: 2, Ipversion: version, L4proto: proto}, uint32(0), ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
		}
		epoch(0, 0)
		route(0)
		syn, key := devicePacket(ipv6, unix.IPPROTO_TCP, 0x02)
		ack, _ := devicePacket(ipv6, unix.IPPROTO_TCP, 0x10)
		rst, _ := devicePacket(ipv6, unix.IPPROTO_TCP, 0x04)
		run(syn, next)
		run(ack, next)
		epoch(0, 1)
		run(ack, drop)
		epoch(0, 0)
		run(ack, next) // rolled-back update preserves native flow
		epoch(1, 0)
		run(ack, redirect)
		run(rst, drop)
		other := append([]byte(nil), ack...)
		other[11]++
		run(other, next)
		// API TCP traffic survives even with an old/missing tuple.
		exempt := bpftestIpPort{Port: key.Dport}
		exempt.Ip.U6Addr8 = key.Dip.U6Addr8
		if err := obj.RouteExemptMap.Update(exempt, uint8(1), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		run(ack, next)
		if err := obj.RouteExemptMap.Delete(exempt); err != nil {
			t.Fatal(err)
		}
		run(syn, next)
		run(ack, next)
		var saved bpftestTcpFlowState
		if err := obj.TcpFlowMap.Lookup(key, &saved); err != nil || saved.RouteEpoch != 1 || saved.Proxy != 0 {
			t.Fatalf("new direct flow %+v: %v", saved, err)
		}
		epoch(2, 0)
		run(ack, redirect)
		route(2)
		run(syn, redirect)
		run(ack, redirect)
		if err := obj.TcpFlowMap.Lookup(key, &saved); err != nil || saved.RouteEpoch != 2 || saved.Proxy != 1 {
			t.Fatalf("new proxy flow %+v: %v", saved, err)
		}

		epoch(0, 0)
		route(0)
		udp, udpTuple := devicePacket(ipv6, unix.IPPROTO_UDP, 0)
		source := bpftestUdpRoutingCacheKey{Sport: udpTuple.Sport}
		source.Sip.U6Addr8 = udpTuple.Sip.U6Addr8
		run(udp, next)
		route(2)
		run(udp, next) // first packet's route is pinned
		epoch(0, 1)
		run(udp, drop)
		epoch(0, 0)
		run(udp, next)
		epoch(1, 0)
		run(udp, redirect)
		var decision bpftestUdpRoutingCacheValue
		if err := obj.UdpRoutingCacheMap.Lookup(source, &decision); err != nil || decision.Result.RouteEpoch != 1 || decision.Result.Outbound != 2 {
			t.Fatalf("new UDP route %+v: %v", decision, err)
		}
		if err := obj.UdpBindingsMap.Update(source, uint64(1), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		epoch(2, 0)
		run(udp, drop) // wait for the old endpoint to release ownership
		if err := obj.UdpBindingsMap.Delete(source); err != nil {
			t.Fatal(err)
		}
		run(udp, redirect) // same source port starts a new lifetime
		if err := obj.UdpRoutingCacheMap.Lookup(source, &decision); err != nil || decision.Result.RouteEpoch != 2 {
			t.Fatalf("reused UDP port %+v: %v", decision, err)
		}
	}
}
