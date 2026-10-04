//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
)

func TestCaptureRouting(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range []struct {
		name   string
		pktgen *ebpf.Program
		tcp    bool
	}{
		{"tcp4", obj.TestpktgenMacMatch, true},
		{"tcp6", obj.TestpktgenParserIpv6Udp, true},
		{"udp4", obj.TestpktgenUdpRouteCacheMiss, false},
		{"udp6", obj.TestpktgenParserIpv6Udp, false},
	} {
		t.Run(network.name, func(t *testing.T) {
			status, packet, ctx, err := runBpfProgram(network.pktgen, make([]byte, 4096-256-320), make([]byte, 256))
			if err != nil || status != 0 {
				t.Fatalf("generate packet: status %d, error %v", status, err)
			}
			if network.name == "tcp6" {
				// Reuse the IPv6 fixture's addresses and ports with a TCP SYN.
				header := make([]byte, 20)
				copy(header[:4], packet[54:58])
				header[12], header[13] = 5<<4, 2
				packet = append(packet[:54], header...)
				packet[20] = 6 // IPv6 next header: TCP.
				binary.BigEndian.PutUint16(packet[18:20], uint16(len(header)))
			}
			var ip netip.Addr
			if packet[14]>>4 == 4 {
				ip = netip.AddrFrom4([4]byte(packet[30:34]))
			} else {
				ip = netip.AddrFrom16([16]byte(packet[38:54]))
			}
			address := ip.As16()
			var key [20]byte // lpm_key: prefix length followed by the 16-byte address.
			binary.NativeEndian.PutUint32(key[:4], 128)
			copy(key[4:], address[:])
			for _, test := range []struct {
				name              string
				ips, ipMatch, tcp bool
			}{
				{"IP hit", true, true, false}, {"IP miss", true, false, false},
				{"HTTP", false, false, true}, {"IP and HTTP hit", true, true, true}, {"IP miss and HTTP", true, false, true},
			} {
				t.Run(test.name, func(t *testing.T) {
					if network.tcp {
						// Each policy case is a new connection, not a retransmit.
						tcpOffset := 34
						if packet[14]>>4 == 6 {
							tcpOffset = 54
						}
						packet[tcpOffset+7]++
					}
					var rules []bpftestMatchSet
					if test.ips {
						rules = append(rules, bpftestMatchSet{Type: uint8(consts.MatchType_IpSet), Flags: (2) << 3, Action: uint8(consts.MatchActionCapture)})
					}
					if test.tcp {
						rules = append(rules, bpftestMatchSet{Type: uint8(consts.MatchType_L4Proto), Value: [16]byte{byte(consts.L4ProtoType_TCP)}, Flags: 1 << 3, Action: uint8(consts.MatchActionCapture)})
					}
					rules = append(rules, bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundDirect)})
					for i, rule := range rules {
						if err := obj.RoutingMap.Update(uint32(i), rule, ebpf.UpdateAny); err != nil {
							t.Fatal(err)
						}
					}

					// Update the same LPM entry instead of sharing test state across cases.
					if err := obj.UnusedLpmType.Update(key, uint32(1), ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
					if !test.ipMatch {
						if err := obj.UnusedLpmType.Delete(key); err != nil {
							t.Fatal(err)
						}
					}
					if err := clearUDPRoutingCache(obj.UdpRoutingCacheMap); err != nil {
						t.Fatal(err)
					}
					want := ^uint32(0) // TCX_NEXT for uncaptured direct traffic.
					if test.ips && test.ipMatch || network.tcp && test.tcp {
						want = 7 // TC_ACT_REDIRECT to the control plane.
					}
					if status, _, _, err := runBpfProgram(obj.TproxyWanEgressL2, packet, ctx); err != nil || status != want {
						t.Fatalf("kernel decision=%d error=%v, want %d", status, err, want)
					}
				})
			}
		})
	}
}
