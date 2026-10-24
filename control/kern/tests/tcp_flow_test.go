//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// The sender's RST ends a kernel-forwarded TCP flow: the RST itself still
// follows the flow's state, which is then deleted, so the tuple's next packets
// start over. A relayed flow outlives the RST: the sender's further RSTs, which
// answer the relay's segments in flight, still go to dae.
func TestTCPFlowStateEndsWithReset(t *testing.T) {
	obj, err := loadTestObjects(t)
	if err != nil {
		t.Fatal(err)
	}
	const (
		ack     = 0x10
		rstAck  = 0x14
		tcxDrop = 2
		token   = uint32(9) // not leased: an ended fallback generation
	)
	destination := netip.MustParseAddrPort("203.0.113.1:443")
	for i, flow := range []struct {
		name  string
		state bpftestTcpFlowState
		want  uint32
		ends  bool
	}{
		{"proxied", bpftestTcpFlowState{Owner: tcpFlowProxy}, tcxRedirect, false},
		{"mark", bpftestTcpFlowState{Mark: 0x37}, tcxNext, true},
		{"ended fallback", bpftestTcpFlowState{Owner: token}, tcxDrop, true},
	} {
		t.Run(flow.name, func(t *testing.T) {
			source := netip.AddrPortFrom(netip.MustParseAddr("192.168.1.2"), uint16(40000+i))
			key := bpftestTuplesKey{Sport: nativeUint16(source.Port()), Dport: nativeUint16(destination.Port()), L4proto: unix.IPPROTO_TCP}
			key.Sip.U6Addr8, key.Dip.U6Addr8 = source.Addr().As16(), destination.Addr().As16()
			if err := obj.TcpFlowMap.Update(&key, flow.state, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			run := func(flags uint8, want uint32) []byte {
				t.Helper()
				packet := bridgePacket(source, destination, unix.IPPROTO_TCP, net.HardwareAddr{2, 0, 0, 0, 0, 1}, flags)
				status, _, ctx, err := runBpfProgram(obj.LanIngressL2, packet, make([]byte, 256))
				if err != nil || status != want {
					t.Fatalf("flags %#x: status %d, error %v; want %d", flags, status, err, want)
				}
				return ctx
			}
			exists := func() bool {
				t.Helper()
				var state bpftestTcpFlowState
				err := obj.TcpFlowMap.Lookup(&key, &state)
				if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatal(err)
				}
				return err == nil
			}
			if flow.want != tcxDrop {
				run(ack, flow.want)
				if !exists() {
					t.Fatal("ACK ended the flow")
				}
			}
			ctx := run(rstAck, flow.want)
			if mark := binary.NativeEndian.Uint32(ctx[8:12]); mark != flow.state.Mark {
				t.Fatalf("RST mark = %#x, want %#x", mark, flow.state.Mark)
			}
			if kept := exists(); kept == flow.ends {
				t.Fatalf("flow state kept after RST = %v, want %v", kept, !flow.ends)
			}
			if flow.ends {
				run(ack, tcxNext)
			} else {
				run(rstAck, tcxRedirect)
			}
		})
	}
}
