// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/internal/routingabi"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"golang.org/x/sys/unix"
)

func setKernelOffline(t testing.TB, collection *ebpf.Collection, offline bool) {
	t.Helper()
	var value uint8
	if offline {
		value = 1
	}
	if err := collection.Maps["exited_map"].Update(uint32(0), value, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
}

func runTCPAdmissionPacket(t testing.TB, collection *ebpf.Collection, program string, packet []byte, verdict, mark uint32) {
	t.Helper()
	var contextOut [256]byte
	got, err := collection.Programs[program].Run(&ebpf.RunOptions{
		Data: packet, Context: make([]byte, len(contextOut)), ContextOut: &contextOut,
	})
	if err != nil || got != verdict {
		t.Fatalf("%s: verdict=%d err=%v, want %d", program, got, err, verdict)
	}
	if got := binary.NativeEndian.Uint32(contextOut[8:12]); verdict == ^uint32(0) && got != mark {
		t.Fatalf("%s: mark=%d, want %d", program, got, mark)
	}
}

func TestTCPUnexpectedExitPolicy(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, program := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
			for _, test := range []struct {
				name, rules string
				behavior    consts.OutboundIndex
				capture     bool
				port        uint16
				want, mark  uint32
			}{
				{"block new direct", "l4proto(tcp) -> direct", consts.OutboundBlock, false, 443, 2, 0},
				{"bypass ignores route mark", "l4proto(tcp) -> direct(mark:37)", consts.OutboundDirect, false, 443, ^uint32(0), 0},
				{"block new proxy", "l4proto(tcp) -> proxy(mark:37)", consts.OutboundBlock, false, 443, 2, 0},
				{"bypass proxy", "l4proto(tcp) -> proxy(mark:37)", consts.OutboundDirect, false, 443, ^uint32(0), 0},
				{"bypass explicit block", "l4proto(tcp) -> block", consts.OutboundDirect, false, 443, ^uint32(0), 0},
				{"bypass skips rule evaluation", "l4proto(tcp) -> proxy(skip_while_noalive)\nl4proto(tcp) -> direct(mark:23)", consts.OutboundDirect, false, 443, ^uint32(0), 0},
				{"bypass capture", "l4proto(tcp) -> direct", consts.OutboundDirect, true, 443, ^uint32(0), 0},
				{"block capture", "l4proto(tcp) -> direct", consts.OutboundBlock, true, 443, 2, 0},
				{"bypass DNS", "l4proto(tcp) -> proxy", consts.OutboundDirect, false, 53, ^uint32(0), 0},
				{"block DNS", "l4proto(tcp) -> direct", consts.OutboundBlock, false, 53, 2, 0},
			} {
				t.Run(fmt.Sprintf("%s/%s/ipv6=%t", test.name, program, ipv6), func(t *testing.T) {
					collection, state := dnsKernelCollection(t)
					src, dst := netip.MustParseAddrPort("192.0.2.1:40000"), netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), test.port)
					if ipv6 {
						src, dst = netip.MustParseAddrPort("[2001:db8::1]:40000"), netip.AddrPortFrom(netip.MustParseAddr("2001:db8::2"), test.port)
					}
					prepared := prepareFlowRulesForTest(t, "", test.rules)
					if test.capture {
						prepared.enableMITMPlan(plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{{Host: dst.Addr().String(), Ports: []uint16{dst.Port()}}}, PreserveRoute: true}}})
					}
					builder, _ := routingMatcherForTest(t, prepared)
					builder.bpf = state
					if err := builder.BuildKernspace(); err != nil {
						t.Fatal(err)
					}
					if err := collection.Variables["unexpected_exit_behavior"].Set(uint32(test.behavior)); err != nil {
						t.Fatal(err)
					}
					setKernelOffline(t, collection, true)
					packet, _ := routingKernelPacket(src, dst, consts.L4ProtoType_TCP)
					runTCPAdmissionPacket(t, collection, program, packet, test.want, test.mark)
					if test.want == ^uint32(0) {
						packet[len(packet)-7] = 0x10
						runTCPAdmissionPacket(t, collection, program, packet, test.want, test.mark)
					}
				})
			}
		}
	}
}

func TestTCPAdmissionSurvivesOffline(t *testing.T) {
	for _, program := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
		for _, proxy := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/proxy=%t", program, proxy), func(t *testing.T) {
				collection, state := dnsKernelCollection(t)
				rule := "l4proto(tcp) -> direct(mark:37)"
				if proxy {
					rule = "l4proto(tcp) -> proxy(mark:37)"
				}
				builder, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", rule))
				builder.bpf = state
				if err := builder.BuildKernspace(); err != nil {
					t.Fatal(err)
				}
				query := bpfOutboundConnectivityQuery{Outbound: uint8(consts.OutboundUserDefinedMin), L4proto: unix.IPPROTO_TCP, Ipversion: 4}
				if err := collection.Maps["outbound_connectivity_map"].Update(query, bpfOutboundConnectivity{State: outboundConnectivityAlive}, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				src, dst := netip.MustParseAddrPort("192.0.2.1:40000"), netip.MustParseAddrPort("198.51.100.1:443")
				packet, _ := routingKernelPacket(src, dst, consts.L4ProtoType_TCP)
				want := ^uint32(0)
				if proxy {
					want = 7
				}
				runTCPAdmissionPacket(t, collection, program, packet, want, 37)
				if err := collection.Variables["unexpected_exit_behavior"].Set(uint32(consts.OutboundBlock)); err != nil {
					t.Fatal(err)
				}
				setKernelOffline(t, collection, true)
				if proxy {
					want = 2
				}
				for _, flags := range []byte{0x10, 0x11, 0x14} {
					packet[len(packet)-7] = flags
					runTCPAdmissionPacket(t, collection, program, packet, want, 37)
				}
				if proxy {
					if err := collection.Variables["unexpected_exit_behavior"].Set(uint32(consts.OutboundDirect)); err != nil {
						t.Fatal(err)
					}
					packet[len(packet)-7] = 0x02
					runTCPAdmissionPacket(t, collection, program, packet, 2, 0)
					seq := packet[len(packet)-16 : len(packet)-12]
					binary.BigEndian.PutUint32(seq, binary.BigEndian.Uint32(seq)+1)
					runTCPAdmissionPacket(t, collection, program, packet, ^uint32(0), 0)
				}
			})
		}
	}
}

func TestTCPFallbackGrantDoesNotReviveAfterRestart(t *testing.T) {
	for _, interruptible := range []bool{false, true} {
		t.Run(fmt.Sprintf("interruptible=%t", interruptible), func(t *testing.T) {
			collection, state := dnsKernelCollection(t)
			configure := func(collection *ebpf.Collection, state *BPFState) uint32 {
				t.Helper()
				builder, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "l4proto(tcp) -> proxy(mark:37)"))
				builder.bpf = state
				if err := builder.BuildKernspace(); err != nil {
					t.Fatal(err)
				}
				var token uint32
				if interruptible {
					tokens := newFallbackTokens(collection.Maps["fallback_lease_map"], collection.Maps["fallback_sequence_map"])
					token = tokens.token(netproxy.NewLease(netproxy.NewResourceRef()))
					if token <= routingabi.FALLBACK_TOKEN_RESERVED {
						t.Fatalf("fallback grant was not issued: %d", token)
					}
				}
				query := bpfOutboundConnectivityQuery{Outbound: uint8(consts.OutboundUserDefinedMin), L4proto: unix.IPPROTO_TCP, Ipversion: 4}
				if err := collection.Maps["outbound_connectivity_map"].Update(query, bpfOutboundConnectivity{
					State: outboundConnectivityNoAliveDirect, Fallback: token,
				}, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				return token
			}
			oldToken := configure(collection, state)
			packet, _ := routingKernelPacket(netip.MustParseAddrPort("192.0.2.1:40000"), netip.MustParseAddrPort("198.51.100.1:443"), consts.L4ProtoType_TCP)
			runTCPAdmissionPacket(t, collection, "lan_ingress_l2", packet, ^uint32(0), 37)
			packet[len(packet)-7] = 0x10
			setKernelOffline(t, collection, true)
			runTCPAdmissionPacket(t, collection, "lan_ingress_l2", packet, ^uint32(0), 37)

			// A cold runtime shares admissions and issuance, never the old live set.
			next, nextState := dnsKernelGeneration(t, map[string]*ebpf.Map{
				"tcp_flow_map":          collection.Maps["tcp_flow_map"],
				"fallback_sequence_map": collection.Maps["fallback_sequence_map"],
			}, 1)
			newToken := configure(next, nextState)
			if interruptible && oldToken == newToken {
				t.Fatalf("cold restart reused fallback token %d", oldToken)
			}
			for _, offline := range []bool{false, true} {
				setKernelOffline(t, next, offline)
				want := ^uint32(0)
				if interruptible {
					want = 7
					if offline {
						want = 2
					}
				}
				for _, program := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
					runTCPAdmissionPacket(t, next, program, packet, want, 37)
				}
			}
			// A new handshake bypasses old policy without acquiring a group lease.
			packet[len(packet)-7] = 0x02
			binary.BigEndian.PutUint32(packet[len(packet)-16:len(packet)-12], 1)
			runTCPAdmissionPacket(t, next, "lan_ingress_l2", packet, ^uint32(0), 0)
		})
	}
}

// Eviction drops a flow's properties, not its connection: online and offline,
// the flow continues natively with its packets' own mark.
func TestTCPFlowEvictionKeepsConnection(t *testing.T) {
	for _, fallback := range []uint32{0, 9} {
		t.Run(fmt.Sprintf("fallback=%d", fallback), func(t *testing.T) {
			collection, state := routingKernelFixture(t, nil, 0, func(spec *ebpf.CollectionSpec) {
				spec.Maps["tcp_flow_map"].MaxEntries = 32
			})
			builder, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "l4proto(tcp) -> direct(mark:37)"))
			builder.bpf = state
			if err := builder.BuildKernspace(); err != nil {
				t.Fatal(err)
			}
			src, dst := netip.MustParseAddrPort("192.0.2.1:40000"), netip.MustParseAddrPort("198.51.100.1:443")
			packet, _ := routingKernelPacket(src, dst, consts.L4ProtoType_TCP)
			runTCPAdmissionPacket(t, collection, "lan_ingress_l2", packet, ^uint32(0), 37)
			key := tuplesKey(src, dst, unix.IPPROTO_TCP)
			var flow bpfTcpFlowState
			if err := collection.Maps["tcp_flow_map"].Lookup(key, &flow); err != nil {
				t.Fatal(err)
			}
			if fallback != 0 {
				flow.Fallback = fallback
				if err := collection.Maps["tcp_flow_map"].Update(key, flow, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			}
			for i := range 512 {
				other := tuplesKey(netip.AddrPortFrom(src.Addr(), uint16(41000+i)), dst, unix.IPPROTO_TCP)
				if err := collection.Maps["tcp_flow_map"].Update(other, bpfTcpFlowState{}, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			}
			if err := collection.Maps["tcp_flow_map"].Lookup(key, &flow); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("fixture did not evict the original admission: %v", err)
			}
			ack := slices.Clone(packet)
			ack[len(ack)-7] = 0x10
			for _, offline := range []bool{false, true} {
				setKernelOffline(t, collection, offline)
				for _, program := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
					runTCPAdmissionPacket(t, collection, program, ack, ^uint32(0), 0)
				}
			}
		})
	}
}

func TestTCPHandshakeGateKeepsEstablishedTraffic(t *testing.T) {
	collection, state := dnsKernelCollection(t)
	builder, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "l4proto(tcp) -> direct(mark:37)"))
	builder.bpf = state
	if err := builder.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	src, dst := netip.MustParseAddrPort("192.0.2.1:40000"), netip.MustParseAddrPort("198.51.100.1:443")
	syn, _ := routingKernelPacket(src, dst, consts.L4ProtoType_TCP)
	runTCPAdmissionPacket(t, collection, "lan_ingress_l2", syn, ^uint32(0), 37)
	key, err := binary.Append(nil, binary.NativeEndian, tuplesKey(src, dst, unix.IPPROTO_TCP))
	if err != nil {
		t.Fatal(err)
	}
	hash := uint32(2166136261)
	for i := 0; i < len(key); i += 4 {
		hash = (hash ^ binary.NativeEndian.Uint32(key[i:i+4])) * 16777619
	}
	gates := collection.Maps["tcp_handshake_gate_map"]
	index := hash & (gates.MaxEntries() - 1)
	if err := gates.Update(index, uint64(1), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	ack := slices.Clone(syn)
	ack[len(ack)-7] = 0x10
	runTCPAdmissionPacket(t, collection, "lan_ingress_l2", ack, ^uint32(0), 37)
	runTCPAdmissionPacket(t, collection, "lan_ingress_l2", syn, 2, 0)
	var held uint64
	if err := gates.Lookup(index, &held); err != nil || held != 1 {
		t.Fatalf("a contender released another handshake's gate: %d, %v", held, err)
	}
	if err := gates.Update(index, uint64(0), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	runTCPAdmissionPacket(t, collection, "lan_ingress_l2", syn, ^uint32(0), 37)
	if err := gates.Lookup(index, &held); err != nil || held != 0 {
		t.Fatalf("handshake retained its gate: %d, %v", held, err)
	}
}

func TestTCPConcurrentInboundAndOutboundAdmission(t *testing.T) {
	collection, state := routingKernelFixture(t, nil, 0, func(spec *ebpf.CollectionSpec) {
		full, err := loadBpf()
		if err != nil {
			t.Fatal(err)
		}
		spec.Programs["lan_egress_l2"] = full.Programs["lan_egress_l2"]
	})
	builder, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "l4proto(tcp) -> direct(mark:37)"))
	builder.bpf = state
	if err := builder.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	src, dst := netip.MustParseAddrPort("192.0.2.1:40000"), netip.MustParseAddrPort("198.51.100.1:443")
	type result struct {
		verdict uint32
		err     error
	}
	for i := range 128 {
		peer, _ := routingKernelPacket(dst, src, consts.L4ProtoType_TCP)
		binary.BigEndian.PutUint32(peer[len(peer)-16:], uint32(i*3+1))
		runTCPAdmissionPacket(t, collection, "lan_egress_l2", peer, ^uint32(0), 0)
		fresh, _ := routingKernelPacket(src, dst, consts.L4ProtoType_TCP)
		binary.BigEndian.PutUint32(fresh[len(fresh)-16:], uint32(i*3+2))
		late := slices.Clone(fresh)
		late[len(late)-7] = 0x12
		binary.BigEndian.PutUint32(late[len(late)-16:], uint32(i*3+3))
		binary.BigEndian.PutUint32(late[len(late)-12:], uint32(i*3+2))
		start := make(chan struct{})
		results := [2]chan result{make(chan result, 1), make(chan result, 1)}
		for n, packet := range [][]byte{fresh, late} {
			go func() {
				<-start
				verdict, err := collection.Programs["lan_ingress_l2"].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256)})
				results[n] <- result{verdict, err}
			}()
		}
		close(start)
		outbound, inbound := <-results[0], <-results[1]
		if outbound.err != nil || inbound.err != nil {
			t.Fatalf("concurrent handshake: outbound=%+v inbound=%+v", outbound, inbound)
		}
		if outbound.verdict == ^uint32(0) {
			fresh[len(fresh)-7] = 0x10
			runTCPAdmissionPacket(t, collection, "lan_ingress_l2", fresh, ^uint32(0), 37)
		} else if outbound.verdict != 2 {
			t.Fatalf("new outbound handshake: verdict=%d", outbound.verdict)
		}
	}
}
