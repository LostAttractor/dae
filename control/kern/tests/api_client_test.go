//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func apiClientPacket(ipv6 bool, flags byte) ([]byte, bpftestTuplesKey) {
	source, destination := netip.MustParseAddr("192.0.2.23"), netip.MustParseAddr("192.0.2.1")
	ipLen := 20
	if ipv6 {
		source, destination = netip.MustParseAddr("2001:db8::23"), netip.MustParseAddr("2001:db8::1")
		ipLen = 40
	}
	packet := make([]byte, 14+ipLen+20)
	copy(packet[:6], []byte{2, 0, 0, 0, 0, 1})
	copy(packet[6:12], []byte{2, 0, 0, 0, 0, 23})
	ip := packet[14:]
	if ipv6 {
		binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IPV6)
		ip[0], ip[6], ip[7] = 0x60, unix.IPPROTO_TCP, 64
		binary.BigEndian.PutUint16(ip[4:6], 20)
		copy(ip[8:24], source.AsSlice())
		copy(ip[24:40], destination.AsSlice())
	} else {
		binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IP)
		ip[0], ip[8], ip[9] = 0x45, 64, unix.IPPROTO_TCP
		binary.BigEndian.PutUint16(ip[2:4], 40)
		copy(ip[12:16], source.AsSlice())
		copy(ip[16:20], destination.AsSlice())
	}
	tcp := ip[ipLen:]
	binary.BigEndian.PutUint16(tcp[:2], 40001)
	binary.BigEndian.PutUint16(tcp[2:4], 9080)
	tcp[12], tcp[13] = 5<<4, flags
	key := bpftestTuplesKey{Sport: nativeUint16(40001), Dport: nativeUint16(9080), L4proto: unix.IPPROTO_TCP}
	key.Sip.U6Addr8, key.Dip.U6Addr8 = source.As16(), destination.As16()
	return packet, key
}

func TestAPIClientIngressObservation(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	fallback := bpftestMatchSet{Type: 11, Outbound: 0}
	if err := obj.RoutingMap.Update(uint32(0), &fallback, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	for _, ipv6 := range []bool{false, true} {
		name := "IPv4"
		if ipv6 {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			for _, test := range []struct {
				name string
				port uint16
				prog *ebpf.Program
				flag byte
				want bool
			}{
				{"direct SYN on LAN", 9080, obj.LanIngressL2, 0x02, true},
				{"keep alive data on LAN", 9080, obj.LanIngressL2, 0x18, true},
				{"API disabled", 0, obj.LanIngressL2, 0x18, false},
				{"different port", 9081, obj.LanIngressL2, 0x18, false},
				{"WAN ingress", 9080, obj.TproxyWanIngressL2, 0x18, false},
				{"WAN egress", 9080, obj.TproxyWanEgressL2, 0x18, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					packet, key := apiClientPacket(ipv6, test.flag)
					_ = obj.ApiClientMap.Delete(&key)
					if err := obj.ApiPort.Set(nativeUint16(test.port)); err != nil {
						t.Fatal(err)
					}
					status, _, _, err := runBpfProgram(test.prog, packet, make([]byte, 256))
					if err != nil || status != math.MaxUint32 { // TCX_NEXT
						t.Fatalf("packet verdict = %d, error = %v", status, err)
					}
					var client bpftestApiClient
					err = obj.ApiClientMap.Lookup(&key, &client)
					if !test.want {
						if !errors.Is(err, ebpf.ErrKeyNotExist) {
							t.Fatalf("recorded non-LAN/API connection: %+v, error = %v", client, err)
						}
						return
					}
					if err != nil || client.ObservedAt == 0 || client.Mac != [6]byte{2, 0, 0, 0, 0, 23} {
						t.Fatalf("LAN observation = %+v, error = %v", client, err)
					}
					var result bpftestRoutingResult
					if err := obj.RoutingTuplesMap.Lookup(&key, &result); !errors.Is(err, ebpf.ErrKeyNotExist) {
						t.Fatalf("API observation polluted proxy handoff: %+v, error = %v", result, err)
					}
					// A later HTTP request must refresh an old entry even without SYN.
					client.ObservedAt = 1
					if err := obj.ApiClientMap.Update(&key, &client, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
					packet, _ = apiClientPacket(ipv6, 0x18)
					if _, _, _, err := runBpfProgram(test.prog, packet, make([]byte, 256)); err != nil {
						t.Fatal(err)
					}
					if err := obj.ApiClientMap.Lookup(&key, &client); err != nil || client.ObservedAt <= 1 {
						t.Fatalf("observation not refreshed: %+v, error = %v", client, err)
					}
					packet[11]++
					if _, _, _, err := runBpfProgram(test.prog, packet, make([]byte, 256)); err != nil {
						t.Fatal(err)
					}
					if err := obj.ApiClientMap.Lookup(&key, &client); err != nil || client.Mac != [6]byte{2, 0, 0, 0, 0, 24} {
						t.Fatalf("latest packet MAC not recorded: %+v, error = %v", client, err)
					}
				})
			}
		})
	}
}
