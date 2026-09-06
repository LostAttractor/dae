//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"math"
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
				name                  string
				ips, ipMatch, domains bool
				bump, routing         uint32
			}{
				{"Host hit", true, true, false, 0, 0},
				{"Host miss", true, false, false, 1, 1},
				{"MITM full match", false, false, true, 1, 1},
				{"MITM shared IP", false, false, true, 1, 0},
				{"combined IP hit", true, true, true, 0, 0},
				{"combined domain hit", true, false, true, 1, 0},
				{"combined miss", true, false, true, 0, 0},
			} {
				t.Run(test.name, func(t *testing.T) {
					capture := bpftestMatchSet{Type: uint8(consts.MatchType_Capture), Outbound: uint8(consts.OutboundControlPlaneRouting)}
					index := uint32(math.MaxUint32)
					if test.ips {
						index = 0
					}
					binary.NativeEndian.PutUint32(capture.Value[:4], index)
					if test.domains {
						capture.Value[4] = 1
					}
					if err := obj.RoutingMap.Update(uint32(0), capture, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
					fallback := bpftestMatchSet{Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundBlock)}
					if err := obj.RoutingMap.Update(uint32(1), fallback, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
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
					var domain bpftestDomainRouting
					domain.Bump[0], domain.Routing[0] = test.bump, test.routing
					if err := obj.DomainRoutingMap.Update(address, domain, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
					if err := clearUDPRoutingCache(obj.UdpRoutingCacheMap); err != nil {
						t.Fatal(err)
					}
					want := uint32(2) // TCX_DROP from the block fallback.
					if test.ips && test.ipMatch || network.tcp && test.domains && test.bump|test.routing != 0 {
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
