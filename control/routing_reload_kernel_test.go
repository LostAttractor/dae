// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
)

func TestReloadKernelPreservesEstablishedTCP(t *testing.T) {
	collection, state := dnsKernelCollection(t)
	state.RoutingGeneration = collection.Variables["routing_generation"]
	prepared := prepareFlowRulesForTest(t, "dport(8443) -> must", "dport(8443) -> direct(mark:37)")
	prepared.enableMITMPlan(plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{{Host: "198.51.100.1", Ports: []uint16{443}}, {Host: "service.example", Ports: []uint16{443}}}, PreserveRoute: true}}})
	prepared.bypassAPI(443, []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}})
	_, builder := routingMatcherForTest(t, prepared)
	builder.bpf = state
	if err := builder.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	type flow struct {
		name          string
		syn, ack      []byte
		verdict, mark uint32
	}
	var flows []flow
	for i, test := range []struct {
		name, destination string
		capture           bool
		mark              uint32
	}{
		{"captured target", "198.51.100.1:443", true, 0},
		{"SSH", "10.0.0.1:22", false, 0},
		{"unrelated HTTPS", "198.51.100.2:443", false, 0},
		{"missing DNS mapping", "198.51.100.3:443", false, 0},
		{"API bypass", "10.0.0.1:443", false, 0},
		{"must and mark", "198.51.100.1:8443", false, 37},
		{"IPv6 direct", "[2001:db8::1]:443", false, 0},
	} {
		dst := netip.MustParseAddrPort(test.destination)
		src := netip.MustParseAddr("192.0.2.1")
		if dst.Addr().Is6() {
			src = netip.MustParseAddr("2001:db8::2")
		}
		syn, _ := routingKernelPacket(netip.AddrPortFrom(src, uint16(42000+i)), dst, consts.L4ProtoType_TCP)
		ack := append([]byte(nil), syn...)
		ack[len(ack)-7] = 0x10
		verdict := ^uint32(0)
		if test.capture {
			verdict = 7
		}
		flows = append(flows, flow{test.name, syn, ack, verdict, test.mark})
	}
	run := func(t *testing.T, collection *ebpf.Collection, packet []byte, verdict, mark uint32) {
		t.Helper()
		for _, name := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
			output := make([]byte, 256)
			status, err := collection.Programs[name].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256), ContextOut: output})
			if err != nil || status != verdict || binary.NativeEndian.Uint32(output[8:12]) != mark {
				t.Fatalf("%s: verdict=%d mark=%d err=%v; want %d/%d", name, status, binary.NativeEndian.Uint32(output[8:12]), err, verdict, mark)
			}
		}
	}
	for _, f := range flows {
		t.Run("establish/"+f.name, func(t *testing.T) { run(t, collection, f.syn, f.verdict, f.mark) })
	}
	next, nextState := dnsKernelGeneration(t, map[string]*ebpf.Map{"tcp_flow_map": collection.Maps["tcp_flow_map"], "routing_tuples_map": collection.Maps["routing_tuples_map"]}, 1)
	// Publish an intentionally incompatible new policy while attachments remain
	// active. Established flows must not consult either old or partial new rules.
	_, replacement := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "l4proto(tcp) -> block"))
	replacement.bpf = nextState
	if err := replacement.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	for _, f := range flows {
		t.Run("prepared/"+f.name, func(t *testing.T) {
			run(t, collection, f.ack, f.verdict, f.mark)
			run(t, collection, f.syn, f.verdict, f.mark)
		})
	}
	for _, f := range flows {
		t.Run("committed/"+f.name, func(t *testing.T) {
			run(t, next, f.ack, f.verdict, f.mark)
			if f.verdict == 7 {
				// An identical initial sequence is still the old setup, even
				// though a new connection to that destination is now blocked.
				run(t, next, f.syn, f.verdict, f.mark)
				var key bpfTuplesKey
				var handoff bpfRoutingHandoff
				it := next.Maps["routing_tuples_map"].Iterate()
				if !it.Next(&key, &handoff) || handoff.Result.Generation != 0 {
					t.Fatalf("SYN retransmit changed generation: %+v, %v", handoff, it.Err())
				}
				if err := next.Maps["routing_tuples_map"].Delete(key); err != nil {
					t.Fatal(err)
				}
				run(t, next, f.ack, f.verdict, f.mark) // accept consumed only the short handoff
			}
			freshSYN := append([]byte(nil), f.syn...)
			freshSYN[len(freshSYN)-13]++ // a new initial sequence, not a SYN retransmit
			run(t, next, freshSYN, 2, 0)
		})
	}
}

func TestReloadKernelRejectsStaleUDPCache(t *testing.T) {
	collection, state := dnsKernelCollection(t)
	state.RoutingGeneration = collection.Variables["routing_generation"]
	_, builder := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", ""))
	builder.bpf = state
	if err := builder.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	packet, _ := routingKernelPacket(netip.MustParseAddrPort("192.0.2.1:43000"), netip.MustParseAddrPort("198.51.100.1:443"), consts.L4ProtoType_UDP)
	run := func(collection *ebpf.Collection, want uint32) {
		t.Helper()
		status, err := collection.Programs["lan_ingress_l2"].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256)})
		if err != nil || status != want {
			t.Fatalf("UDP verdict=%d err=%v, want %d", status, err, want)
		}
	}
	run(collection, ^uint32(0))
	next, nextState := dnsKernelGeneration(t, map[string]*ebpf.Map{"udp_routing_cache_map": collection.Maps["udp_routing_cache_map"]}, 1)
	_, replacement := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "l4proto(udp) -> block"))
	replacement.bpf = nextState
	if err := replacement.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	run(collection, ^uint32(0)) // Candidate preparation leaves the old generation usable.
	run(next, 2)                // No explicit cache sweep: a late old-generation insertion is stale too.
}
