//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Seed the persistent byte format independently of generated structs and
// constants, so changing both a writer and reader cannot hide an ABI break.
func TestPinnedTCPFlowEncoding(t *testing.T) {
	obj, err := loadTestObjects(t, "LanIngressL2")
	if err != nil {
		t.Fatal(err)
	}
	for _, ipv6 := range []bool{false, true} {
		for _, test := range []struct {
			name     string
			owner    uint32
			mark     uint32
			leased   bool
			ack, rst uint32
		}{
			{"direct", 0, 0, false, tcxNext, tcxNext},
			{"marked", 0, 37, false, tcxNext, tcxNext},
			{"proxy", 1, 0, false, tcxRedirect, tcxRedirect},
			{"first token", 2, 73, true, tcxNext, tcxNext},
			{"last token", ^uint32(0), 73, true, tcxNext, tcxNext},
			{"ended token", 9, 0, false, tcxRedirect, 2},
		} {
			t.Run(fmt.Sprintf("%s/IPv6=%v", test.name, ipv6), func(t *testing.T) {
				source, destination := netip.MustParseAddrPort("192.168.1.2:40000"), netip.MustParseAddrPort("203.0.113.1:443")
				if ipv6 {
					source, destination = netip.MustParseAddrPort("[2001:db8::2]:40000"), netip.MustParseAddrPort("[2001:db8::1]:443")
				}
				var key [40]byte
				sip, dip := source.Addr().As16(), destination.Addr().As16()
				copy(key[0:16], sip[:])
				copy(key[16:32], dip[:])
				binary.BigEndian.PutUint16(key[32:34], source.Port())
				binary.BigEndian.PutUint16(key[34:36], destination.Port())
				key[36] = unix.IPPROTO_TCP
				var value [16]byte
				binary.NativeEndian.PutUint32(value[8:12], test.mark)
				binary.NativeEndian.PutUint32(value[12:16], test.owner)
				if err := obj.TcpFlowMap.Update(key, value, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				if test.leased {
					if err := obj.FallbackLeaseMap.Update(test.owner, uint8(1), ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
				}
				for _, packet := range []struct {
					flags uint8
					want  uint32
				}{{0x10, test.ack}, {0x14, test.rst}} {
					data := bridgePacket(source, destination, unix.IPPROTO_TCP, net.HardwareAddr{2, 0, 0, 0, 0, 1}, packet.flags)
					status, _, ctx, err := runBpfProgram(obj.LanIngressL2, data, make([]byte, 256))
					if err != nil || status != packet.want {
						t.Fatalf("owner=%#x flags=%#x: status=%d, %v; want %d", test.owner, packet.flags, status, err, packet.want)
					}
					if packet.want == tcxNext && binary.NativeEndian.Uint32(ctx[8:12]) != test.mark {
						t.Fatalf("owner=%#x flags=%#x: lost mark %#x", test.owner, packet.flags, test.mark)
					}
				}
			})
		}
	}
}
