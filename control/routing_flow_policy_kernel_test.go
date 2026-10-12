// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
)

func TestPolicyFlowKernelIsolation(t *testing.T) {
	collection, state := dnsKernelCollection(t)
	conf := parseStructuredTestConfig(t, `policy {
 main {
  rules {
   dport(443) -> dnat('198.51.100.20:8443')
   dport(53) -> must
   dport(9443) -> bump
  }
  fallback: direct
 }
 tor { fallback: direct }
} default: main interface { tor0: tor }`)
	m, b := routingMatcherForTest(t, preparedRules{routing: &conf.Routing})
	ids := flowPolicyIDs(m)
	// BPF_PROG_TEST_RUN supplies the loopback ifindex for its test skb.
	// Bind it only in private maps; no host interface is watched or attached.
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	for i := range b.profiles {
		b.profiles[i].InterfaceNames = nil
	}
	b.bpf = state
	if err := b.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	sequence := uint16(45000)
	for _, name := range []string{"main", "tor"} {
		if err := state.RoutingInterfaceMap.Update(uint32(loopback.Index), ids[name], ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		for _, port := range []uint16{443, 53, 9443, 80} {
			for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
				for _, program := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
					sequence++
					src := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), sequence)
					dst := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.20"), port)
					packet, protocol := routingKernelPacket(src, dst, proto)
					input := routingInput{src: src, dst: dst, l4proto: proto, profileID: ids[name], kernel: true}
					decision, err := m.evaluateSpans(m.profiles[ids[name]], input)
					if err != nil {
						t.Fatal(err)
					}
					want := ^uint32(0)
					if name == "main" && (port == 443 || port == 9443) || name == "tor" && port == 53 {
						want = 7
					}
					verdict, err := collection.Programs[program].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256)})
					if err != nil || verdict != want {
						t.Fatalf("%s %s port=%d proto=%d: verdict=%d, %v; want %d", name, program, port, proto, verdict, err, want)
					}
					key := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(port), L4proto: protocol}
					key.Sip.U6Addr8, key.Dip.U6Addr8 = src.Addr().As16(), dst.Addr().As16()
					var handoff bpfRoutingResult
					err = lookupKernelHandoff(collection.Maps["routing_tuples_map"], key, &handoff)
					if want != 7 {
						if !errors.Is(err, ebpf.ErrKeyNotExist) || decision.outbound != consts.OutboundDirect || decision.captureFlags != 0 {
							t.Fatalf("direct flow retained capture state: %+v, %+v, %v", handoff, decision, err)
						}
						continue
					}
					if err != nil || handoff.ProfileId != ids[name] || handoff.Outbound != uint8(decision.outbound) || handoff.CaptureFlags != decision.captureFlags || (handoff.Must != 0) != decision.must {
						t.Fatalf("kernel/userspace policy mismatch: %+v, %+v, %v", handoff, decision, err)
					}
				}
			}
		}
	}
}
