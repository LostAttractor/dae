//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

func bigTCPPacket(ipv6, hopopts bool) (packet, ctx []byte, tcpOffset int) {
	packet, _ = apiClientPacket(ipv6, 0x18)
	tcpOffset = 34
	if ipv6 {
		tcpOffset = 54
		clear(packet[18:20])
		if hopopts {
			packet = slices.Insert(packet, tcpOffset, unix.IPPROTO_TCP, 0, 0xc2, 4, 0, 1, 0, 0)
			packet[20] = unix.IPPROTO_HOPOPTS
			tcpOffset += 8
		}
		packet = append(packet, make([]byte, 14+40+65536-len(packet))...)
	} else {
		clear(packet[16:18])
		packet = append(packet, make([]byte, 14+65536-len(packet))...)
	}
	ctx = make([]byte, 256)
	// __sk_buff: put the TCP header in non-linear data.
	binary.NativeEndian.PutUint32(ctx[80:84], uint32(tcpOffset)) // data_end
	binary.NativeEndian.PutUint32(ctx[164:168], 46)              // gso_segs
	binary.NativeEndian.PutUint32(ctx[176:180], 1448)            // gso_size
	return packet, ctx, tcpOffset
}

func TestBigTCP(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	programs := []*ebpf.Program{obj.LanEgressL2, obj.TproxyWanIngressL2, obj.LanIngressL2, obj.TproxyWanEgressL2}
	for _, format := range []struct {
		name          string
		ipv6, hopopts bool
	}{
		{"IPv4", false, false}, {"IPv6", true, false}, {"IPv6-HBH", true, true},
	} {
		t.Run(format.name, func(t *testing.T) {
			packet, ctx, tcpOffset := bigTCPPacket(format.ipv6, format.hopopts)
			t.Run("direct", func(t *testing.T) {
				for _, prog := range programs {
					status, output, _, err := runBpfProgram(prog, packet, ctx)
					if err != nil || status != ^uint32(0) {
						t.Fatalf("%s: kernel decision=%d err=%v, want TCX_NEXT", prog, status, err)
					}
					if !bytes.Equal(output, packet) {
						t.Fatalf("%s modified a direct BIG TCP packet", prog)
					}
				}
			})
			type invalidPacket struct {
				name   string
				mutate func(packet, ctx []byte) []byte
			}
			invalid := []invalidPacket{
				{"no-GSO", func(p, c []byte) []byte { clear(c[164:168]); clear(c[176:180]); return p }},
				{"short-zero-length", func(p, c []byte) []byte { return p[:tcpOffset+20] }},
				{"bad-TCP-offset", func(p, c []byte) []byte { p[tcpOffset+12] = 4 << 4; return p }},
				{"UDP-is-not-BIG-TCP", func(p, c []byte) []byte {
					proto := 23
					if format.ipv6 {
						proto = 20
					}
					if format.hopopts {
						proto = 54
					}
					p[proto] = unix.IPPROTO_UDP
					binary.BigEndian.PutUint16(p[tcpOffset+4:tcpOffset+6], 8)
					return p
				}},
			}
			if !format.ipv6 {
				for _, fragment := range []uint16{0x2000, 1, 0x8000} {
					invalid = append(invalid, invalidPacket{fmt.Sprintf("fragment-%x", fragment), func(p, c []byte) []byte { binary.BigEndian.PutUint16(p[20:22], fragment); return p }})
				}
			} else {
				invalid = append(invalid, invalidPacket{"atomic-fragment", func(p, c []byte) []byte {
					p[20] = unix.IPPROTO_FRAGMENT
					return slices.Insert(p, 54, unix.IPPROTO_TCP, 0, 0, 0, 0, 0, 0, 0)
				}})
			}
			if format.hopopts {
				for _, field := range []int{55, 56, 57, 61} {
					invalid = append(invalid, invalidPacket{fmt.Sprintf("bad-jumbo-field-%d", field), func(p, c []byte) []byte { p[field]++; return p }})
				}
			}
			for _, tc := range invalid {
				t.Run(tc.name, func(t *testing.T) {
					c := slices.Clone(ctx)
					p := tc.mutate(slices.Clone(packet), c)
					for _, prog := range programs {
						status, _, _, err := runBpfProgram(prog, p, c)
						if err != nil || status != 2 {
							t.Fatalf("%s: kernel decision=%d err=%v, want TCX_DROP", prog, status, err)
						}
					}
				})
			}
		})
	}
}

func TestBigTCPRouting(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	for _, ipv6 := range []bool{false, true} {
		for _, tc := range []struct {
			name            string
			port            uint16
			domain, capture bool
			outbound        uint8
			mark            uint32
			must            uint8
		}{
			{"SSH", 22, true, false, 0, 0, 0},
			{"unrelated-HTTPS", 443, false, false, 0, 0, 0},
			{"missing-DNS-map", 443, false, false, 0, 37, 1},
			{"target-capture", 443, true, true, 0, 37, 0},
			{"original-outbound", 443, true, true, 2, 37, 0},
			{"must-direct", 8443, true, false, 0, 37, 1},
			{"must-capture", 443, true, true, 0, 37, 1},
			{"API", 9080, true, false, 0, 0, 0},
		} {
			t.Run(fmt.Sprintf("%s/IPv6=%v", tc.name, ipv6), func(t *testing.T) {
				syn, key := apiClientPacket(ipv6, 2)
				packet, ctx, tcpOffset := bigTCPPacket(ipv6, ipv6)
				key.Dport = nativeUint16(tc.port)
				binary.BigEndian.PutUint16(syn[len(syn)-18:len(syn)-16], tc.port)
				binary.BigEndian.PutUint16(packet[tcpOffset+2:tcpOffset+4], tc.port)
				if !ipv6 && tc.port == 22 {
					key.Dip.U6Addr8 = netip.MustParseAddr("10.0.0.1").As16()
					copy(syn[30:34], key.Dip.U6Addr8[12:])
					copy(packet[30:34], key.Dip.U6Addr8[12:])
				}
				_ = obj.RoutingTuplesMap.Delete(key)
				_ = obj.ApiClientMap.Delete(key)
				_ = obj.DomainRoutingMap.Delete(key.Dip.U6Addr8)
				if tc.domain {
					var domain bpftestDomainRouting
					domain.Routing[0] = 1
					if err := obj.DomainRoutingMap.Update(key.Dip.U6Addr8, domain, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
				} else if tc.name == "unrelated-HTTPS" {
					if err := obj.DomainRoutingMap.Update(key.Dip.U6Addr8, bpftestDomainRouting{}, ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
				}
				capture := routingPortRule(443, consts.MatchActionCapture, 0)
				capture.Flags = 1 << 3
				installRoutingFlow(t, obj, []bpftestMatchSet{
					routingDomainRule(0, consts.MatchActionAnd, 0), capture,
					{Type: uint8(consts.MatchType_Fallback), Outbound: tc.outbound, Mark: tc.mark, Flags: tc.must << 1},
				})
				if err := obj.ApiPort.Set(nativeUint16(9080)); err != nil {
					t.Fatal(err)
				}
				want := ^uint32(0)
				if tc.capture {
					want = 7
				}
				for _, prog := range []*ebpf.Program{obj.LanIngressL2, obj.TproxyWanEgressL2} {
					for _, input := range []struct{ data, ctx []byte }{{syn, make([]byte, 256)}, {packet, ctx}} {
						status, _, outputCtx, err := runBpfProgram(prog, input.data, input.ctx)
						if err != nil || status != want {
							t.Fatalf("%s: kernel decision=%d err=%v, want %d", prog, status, err, want)
						}
						if !tc.capture && binary.NativeEndian.Uint32(outputCtx[8:12]) != tc.mark {
							t.Fatalf("lost direct mark: %x", outputCtx[8:12])
						}
					}
					var route bpftestRoutingResult
					err := lookupHandoff(obj.RoutingTuplesMap, key, &route)
					if tc.capture {
						if err != nil || route.Outbound != tc.outbound || route.Mark != tc.mark || route.Must != tc.must || (route.CaptureFlags != 0) != tc.capture {
							t.Fatalf("lost routing metadata: %+v, %v", route, err)
						}
					} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
						t.Fatalf("direct traffic created handoff state: %+v, %v", route, err)
					}
					if !tc.capture {
						assertDirectTCPFlow(t, obj, key, tc.mark)
					}
				}
				if tc.port == 9080 {
					var client bpftestApiClient
					if err := obj.ApiClientMap.Lookup(key, &client); err != nil || client.ObservedAt == 0 {
						t.Fatalf("lost API observation: %+v, %v", client, err)
					}
				}
			})
		}
	}
}
