//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
)

// Exercise the real classifier, not just a userspace final outbound named
// "direct". SSH and unrelated HTTPS must return TCX_NEXT without a proxy tuple.
func TestDomainCapturePreservesEBPFDirect(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	for _, ipv6 := range []bool{false, true} {
		pktgen, tcpOffset := obj.TestpktgenMacMatch, 34
		if ipv6 {
			pktgen, tcpOffset = obj.TestpktgenParserIpv6Udp, 54
		}
		status, packet, ctx, err := runBpfProgram(pktgen, make([]byte, 4096-256-320), make([]byte, 256))
		if err != nil || status != 0 {
			t.Fatalf("generate packet: status=%d err=%v", status, err)
		}
		if ipv6 {
			header := make([]byte, 20)
			copy(header[:4], packet[tcpOffset:tcpOffset+4])
			header[12], header[13] = 5<<4, 2
			packet = append(packet[:tcpOffset], header...)
			packet[20] = 6
			binary.BigEndian.PutUint16(packet[18:20], uint16(len(header)))
		}
		var src, dst netip.Addr
		if ipv6 {
			src, dst = netip.AddrFrom16([16]byte(packet[22:38])), netip.AddrFrom16([16]byte(packet[38:54]))
		} else {
			src, dst = netip.AddrFrom4([4]byte(packet[26:30])), netip.AddrFrom4([4]byte(packet[30:34]))
		}
		address := dst.As16()
		for _, capture := range []uint8{1, 2} { // HTTP and destination capture.
			for _, dns := range []string{"missing", "unrelated", "matched", "shared"} {
				var domain bpftestDomainRouting
				if dns == "matched" || dns == "shared" {
					domain.Bump[0] = 1 << 1 // The domain predicate is at index 1.
				}
				if dns == "matched" {
					domain.Routing[0] = domain.Bump[0]
				}
				if err := obj.DomainRoutingMap.Update(address, domain, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				if dns == "missing" {
					if err := obj.DomainRoutingMap.Delete(address); err != nil {
						t.Fatal(err)
					}
				}
				for _, port := range []uint16{22, 443} {
					binary.BigEndian.PutUint16(packet[tcpOffset+2:tcpOffset+4], port)
					for _, mark := range []uint32{0, 37} {
						t.Run(fmt.Sprintf("ipv6=%v/capture=%d/%s/port=%d/mark=%d", ipv6, capture, dns, port, mark), func(t *testing.T) {
							portRule := bpftestMatchSet{Type: uint8(consts.MatchType_Port), CaptureFlags: capture, Action: uint8(consts.MatchActionCapture)}
							binary.NativeEndian.PutUint16(portRule.Value[:2], 443)
							binary.NativeEndian.PutUint16(portRule.Value[2:4], 443)
							rules := []bpftestMatchSet{
								{Type: uint8(consts.MatchType_L4Proto), Value: [16]byte{byte(consts.L4ProtoType_TCP)}, Action: uint8(consts.MatchActionAnd)},
								{Type: uint8(consts.MatchType_DomainSet), Value: [16]byte{1}, Action: uint8(consts.MatchActionAnd)},
								portRule,
								{Type: uint8(consts.MatchType_Fallback), Outbound: uint8(consts.OutboundDirect), Mark: mark, Must: true},
							}
							for i, rule := range rules {
								if err := obj.RoutingMap.Update(uint32(i), rule, ebpf.UpdateAny); err != nil {
									t.Fatal(err)
								}
							}
							key := bpftestTuplesKey{Sport: binary.NativeEndian.Uint16(packet[tcpOffset : tcpOffset+2]), Dport: nativeUint16(port), L4proto: 6}
							key.Sip.U6Addr8, key.Dip.U6Addr8 = src.As16(), address
							captured := port == 443 && (dns == "matched" || dns == "shared")
							want := ^uint32(0) // TCX_NEXT
							if captured {
								want = 7 // TC_ACT_REDIRECT
							}
							for _, program := range []*ebpf.Program{obj.LanIngressL2, obj.TproxyWanEgressL2} {
								status, _, _, err := runBpfProgram(program, packet, ctx)
								if err != nil || status != want {
									t.Fatalf("%s: status=%d err=%v, want=%d", program, status, err, want)
								}
								var route bpftestRoutingResult
								err = obj.RoutingTuplesMap.Lookup(key, &route)
								if !captured && mark == 0 {
									if !errors.Is(err, ebpf.ErrKeyNotExist) {
										t.Fatalf("eBPF direct retained proxy state: %+v, %v", route, err)
									}
									continue
								}
								var wantCapture uint8
								outbound, wantMark, must := uint8(0), mark, uint8(1)
								if captured {
									wantCapture = capture
									if capture == 2 {
										outbound, wantMark, must = uint8(consts.OutboundControlPlaneRouting), 0, 0
									}
								}
								if err != nil || route.Outbound != outbound || route.Mark != wantMark || route.Must != must || route.CaptureFlags != wantCapture {
									t.Fatalf("capture changed original route: %+v, %v", route, err)
								}
							}
						})
					}
				}
			}
		}
	}
}
