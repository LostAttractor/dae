// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/internal/routingabi"
	"golang.org/x/sys/unix"
)

func TestUDPUnexpectedExitPolicy(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, program := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
			for _, block := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/ipv6=%t/block=%t", program, ipv6, block), func(t *testing.T) {
					collection, state := dnsKernelCollection(t)
					builder, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "l4proto(udp) -> block"))
					builder.bpf = state
					if err := builder.BuildKernspace(); err != nil {
						t.Fatal(err)
					}
					mode, verdict := uint32(consts.OutboundDirect), ^uint32(0)
					if block {
						mode, verdict = uint32(consts.OutboundBlock), 2
					}
					if err := collection.Variables["unexpected_exit_behavior"].Set(mode); err != nil {
						t.Fatal(err)
					}
					setKernelOffline(t, collection, true)
					for _, port := range []uint16{443, 53} {
						src, dst := netip.MustParseAddrPort("192.0.2.1:40000"), netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), port)
						if ipv6 {
							src, dst = netip.MustParseAddrPort("[2001:db8::1]:40000"), netip.AddrPortFrom(netip.MustParseAddr("2001:db8::2"), port)
						}
						packet, _ := routingKernelPacket(src, dst, consts.L4ProtoType_UDP)
						runTCPAdmissionPacket(t, collection, program, packet, verdict, 0)
						if !block {
							origin := plugin.SourceLAN
							if program == "tproxy_wan_egress_l2" {
								origin = plugin.SourceLocal
							}
							var cached bpfUdpRoutingCacheValue
							if err := collection.Maps["udp_routing_cache_map"].Lookup(udpSourceKey(src), &cached); err != nil || cached.Result.SourceOrigin != uint8(origin) {
								t.Fatalf("crash bypass lost source origin: %+v, %v", cached.Result, err)
							}
						}
					}
				})
			}
		}
	}
}

func TestUDPUnexpectedExitPreservesSourceOwnership(t *testing.T) {
	for _, proxy := range []bool{false, true} {
		t.Run(fmt.Sprintf("proxy=%t", proxy), func(t *testing.T) {
			collection, state := dnsKernelCollection(t)
			rules := "l4proto(udp) -> direct(mark:37)"
			verdict := ^uint32(0)
			if proxy {
				rules, verdict = "l4proto(udp) -> proxy(mark:37)", 7
			}
			builder, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", rules))
			builder.bpf = state
			if err := builder.BuildKernspace(); err != nil {
				t.Fatal(err)
			}
			query := bpfOutboundConnectivityQuery{Outbound: uint8(consts.OutboundUserDefinedMin), Ipversion: 4, L4proto: unix.IPPROTO_UDP}
			if err := collection.Maps["outbound_connectivity_map"].Update(query, bpfOutboundConnectivity{}, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			src, dst := netip.MustParseAddrPort("192.0.2.1:40000"), netip.MustParseAddrPort("198.51.100.1:443")
			packet, _ := routingKernelPacket(src, dst, consts.L4ProtoType_UDP)
			runTCPAdmissionPacket(t, collection, "lan_ingress_l2", packet, verdict, 37)
			setKernelOffline(t, collection, true)
			if proxy {
				verdict = 2
			} else if err := collection.Variables["unexpected_exit_behavior"].Set(uint32(consts.OutboundBlock)); err != nil {
				t.Fatal(err)
			}
			dns, _ := routingKernelPacket(src, netip.AddrPortFrom(dst.Addr(), 53), consts.L4ProtoType_UDP)
			for _, input := range [][]byte{packet, dns} {
				runTCPAdmissionPacket(t, collection, "lan_ingress_l2", input, verdict, 37)
			}
			if !proxy {
				return
			}
			source := udpSourceKey(src)
			binding := bpfUdpBinding{SourceOrigin: uint8(plugin.SourceLAN), Mac: [6]byte(packet[6:12])}
			if err := collection.Maps["udp_bindings_map"].Update(source, binding, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			if err := collection.Maps["udp_routing_cache_map"].Delete(source); err != nil {
				t.Fatal(err)
			}
			// A DNS destination cannot evade an established proxy source binding.
			runTCPAdmissionPacket(t, collection, "lan_ingress_l2", dns, 2, 0)
			if err := collection.Maps["udp_bindings_map"].Delete(source); err != nil {
				t.Fatal(err)
			}
			// Once both owners are gone, this source can start a new bypass lifetime.
			runTCPAdmissionPacket(t, collection, "lan_ingress_l2", dns, ^uint32(0), 0)
		})
	}
}

func TestStartingDoesNotGrantCrashBypass(t *testing.T) {
	collection, state := dnsKernelCollection(t)
	builder, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", "l4proto(tcp) -> block"))
	builder.bpf = state
	if err := builder.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["exited_map"].Update(uint32(0), uint8(routingabi.DAEMON_STARTING), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	packet, _ := routingKernelPacket(netip.MustParseAddrPort("192.0.2.1:40000"), netip.MustParseAddrPort("198.51.100.1:443"), consts.L4ProtoType_TCP)
	runTCPAdmissionPacket(t, collection, "lan_ingress_l2", packet, 2, 0)
	setKernelOffline(t, collection, true)
	var contextIn, contextOut [256]byte
	binary.NativeEndian.PutUint32(contextIn[8:12], 41)
	verdict, err := collection.Programs["lan_ingress_l2"].Run(&ebpf.RunOptions{Data: packet, Context: &contextIn, ContextOut: &contextOut})
	if err != nil || verdict != ^uint32(0) || binary.NativeEndian.Uint32(contextOut[8:12]) != 41 {
		t.Fatalf("crash bypass lost the original mark: verdict=%d err=%v mark=%d", verdict, err, binary.NativeEndian.Uint32(contextOut[8:12]))
	}
	packet[len(packet)-7] = 0x10
	runTCPAdmissionPacket(t, collection, "lan_ingress_l2", packet, ^uint32(0), 41)
}
