// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
)

// Exercise configuration -> compiler -> map publication -> actual classifier.
// All maps are private; programs run with BPF_PROG_TEST_RUN and never attach.
func TestRoutingProgramsKernelIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for isolated BPF program tests")
	}
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	for name := range spec.Programs {
		if name != "lan_ingress_l2" && name != "tproxy_wan_egress_l2" {
			delete(spec.Programs, name)
		}
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer collection.Close()
	state := &BPFState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{
		RoutingMap:        collection.Maps["routing_map"],
		RoutingProfileMap: collection.Maps["routing_profile_map"], RoutingInterfaceMap: collection.Maps["routing_interface_map"], LpmArrayMap: collection.Maps["lpm_array_map"], UnusedLpmType: collection.Maps["unused_lpm_type"],
	}, bpfVariables: bpfVariables{DefaultRoutingProfile: collection.Variables["default_routing_profile"]}}}
	for _, laterMust := range []bool{false, true} {
		controls := `domain(full: one.example) && dport(443) -> must
domain(full: bump.example) && dport(443) -> bump
domain(full: one.example) && dport(443) -> dnat(198.51.100.20)`
		if laterMust {
			controls += "\ndport(443) -> must"
		}
		prepared := prepareFlowRulesForTest(t, controls, "dip(198.51.100.20) -> proxy(mark:91)\ndomain(full: one.example) && dport(443) -> block\ndport(443) -> direct(mark:37)")
		prepared.enableMITMPlan(mitmRoutingPlugin("one.example").Plan())
		prepared.destinations = append(prepared.destinations, prepareFlowRulesForTest(t, "dip(192.0.2.20) -> dnat(198.51.100.20)", "").destinations...)
		prepared.bypassAPI(443, []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}})
		matcher, builder := routingMatcherForTest(t, prepared)
		unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
		plane := &ControlPlane{routingMatcher: matcher, sniffVerifyMode: consts.SniffVerifyMode_None,
			core:      &controlPlaneCore{domainRegistry: newRoutingDomainRegistry()},
			outbounds: []*outbound.DialerGroup{downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), downloadTestGroup(t, "proxy", unused)}}
		builder.bpf = state
		if err := builder.BuildKernspace(); err != nil {
			t.Fatal(err)
		}
		// Read back a new table slot beyond kernel end: exact destination
		// predicates must not have been uploaded. Kernel length only grows here.
		var extra bpfMatchSet
		if err := state.RoutingMap.Lookup(uint32(builder.routing.end), &extra); err != nil || extra != (bpfMatchSet{}) {
			t.Fatalf("userspace destination instructions leaked into kernel: %+v, %v", extra, err)
		}
		for _, test := range []struct {
			name, source, destination string
			domains                   []string
			capture, ambiguous, bump  bool
		}{
			{"SSH", "192.0.2.1:40001", "10.0.0.1:22", nil, false, false, false},
			{"missing DNS", "192.0.2.1:40002", "198.51.100.1:443", nil, false, false, false},
			{"unrelated HTTPS", "192.0.2.1:40003", "198.51.100.1:443", []string{"outside.example"}, false, false, false},
			{"matched", "192.0.2.1:40004", "198.51.100.1:443", []string{"one.example"}, true, false, false},
			{"shared IP", "192.0.2.1:40005", "198.51.100.1:443", []string{"one.example", "outside.example"}, true, true, false},
			{"explicit bump", "192.0.2.1:40006", "198.51.100.1:443", []string{"bump.example"}, false, false, true},
			{"wrong port", "192.0.2.1:40007", "198.51.100.1:22", []string{"one.example"}, false, false, false},
			{"API bypass", "192.0.2.1:40008", "10.0.0.1:443", []string{"one.example", "bump.example"}, false, false, false},
			{"IPv6 missing DNS", "[2001:db8::1]:40009", "[2001:db8::2]:443", nil, false, false, false},
			{"IPv6 matched", "[2001:db8::1]:40010", "[2001:db8::2]:443", []string{"one.example"}, true, false, false},
			{"plugin destination without DNS", "192.0.2.1:40011", "192.0.2.20:443", nil, true, false, false},
		} {
			t.Run(test.name, func(t *testing.T) {
				for _, network := range []consts.L4ProtoStr{consts.L4ProtoStr_TCP, consts.L4ProtoStr_UDP} {
					proto := network.ToL4ProtoType()
					t.Run(string(network), func(t *testing.T) {
						source, destination := netip.MustParseAddrPort(test.source), netip.MustParseAddrPort(test.destination)
						if laterMust {
							// A fresh tuple avoids the previous program's UDP routing cache.
							source = netip.AddrPortFrom(source.Addr(), source.Port()+1000)
						}
						var domains bpfDomainRouting
						for i, host := range test.domains {
							bitmap := matcher.domainMatcher.MatchDomainBitmap(host)
							for j, bits := range bitmap {
								domains.Bump[j] |= bits
								if i == 0 {
									domains.Routing[j] = bits
								} else {
									domains.Routing[j] &= bits
								}
							}
						}
						if err := collection.Maps["domain_routing_map"].Update(destination.Addr().As16(), domains, ebpf.UpdateAny); err != nil {
							t.Fatal(err)
						}
						packet, ipProto := routingKernelPacket(source, destination, proto)
						key := bpfTuplesKey{Sport: common.Htons(source.Port()), Dport: common.Htons(destination.Port()), L4proto: ipProto}
						key.Sip.U6Addr8, key.Dip.U6Addr8 = source.Addr().As16(), destination.Addr().As16()
						capture, bump, ambiguous := test.capture, test.bump, test.ambiguous
						apiBypass := test.name == "API bypass" && proto == consts.L4ProtoType_TCP
						if test.name == "API bypass" && !apiBypass {
							capture, bump, ambiguous = true, true, true
						}
						for _, name := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
							want := ^uint32(0) // TCX_NEXT
							if capture || bump {
								want = 7 // TC_ACT_REDIRECT
							}
							status, err := collection.Programs[name].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256), Repeat: 1})
							if err != nil || status != want {
								t.Fatalf("%s laterMust=%v: verdict=%d err=%v, want=%d", name, laterMust, status, err, want)
							}
							var result bpfRoutingResult
							err = collection.Maps["routing_tuples_map"].Lookup(key, &result)
							if destination.Port() == 22 || apiBypass || proto == consts.L4ProtoType_UDP && !capture && !bump {
								if !errors.Is(err, ebpf.ErrKeyNotExist) {
									t.Fatalf("kernel direct retained proxy state: %+v, %v", result, err)
								}
								continue
							}
							outbound, mark := consts.OutboundDirect, uint32(37)
							if capture || bump || ambiguous && !laterMust {
								outbound, mark = consts.OutboundControlPlaneRouting, 0
							}
							var flags, must uint8
							if capture {
								flags = captureDestination
							}
							if !capture && laterMust {
								must = 1
							}
							if err != nil || result.CaptureFlags != flags || result.Must != must || result.Mark != mark || result.Outbound != uint8(outbound) {
								t.Fatalf("%s laterMust=%v: result=%+v err=%v, want=(%v,%d,%d,%d)", name, laterMust, result, err, outbound, mark, must, flags)
							}
							if capture {
								domain, wantMust := "one.example", uint8(1)
								if len(test.domains) == 0 {
									// The literal Host rule must work without DNS or SNI.
									domain = ""
									if !laterMust {
										wantMust = 0
									}
								}
								p := &RouteParam{Src: source, Dest: destination, Domain: domain, routingResult: &result, networkType: common.NetworkType{
									L4Proto: network, IpVersion: consts.IpVersionStrFromAddr(destination.Addr()),
								}}
								option, err := plane.RouteDialOption(context.Background(), p)
								if err != nil || option.Outbound.Name != "proxy" || option.DialTarget != "198.51.100.20:443" || option.NetworkType.IpVersion != consts.IpVersionStr_4 || result.Mark != 91 || result.Must != wantMust {
									t.Fatalf("%s: kernel handoff did not route the rewritten target: %+v result=%+v err=%v", name, option, result, err)
								}
							}

						}
					})
				}
			})
		}
	}
}

// A TCP SYN and a UDP datagram both classify the original destination. Keep
// the packet shape shared by the DNS and routing program integration tests.
func routingKernelPacket(source, destination netip.AddrPort, proto consts.L4ProtoType) ([]byte, uint8) {
	packet := apiIdentityPacket(source, destination, [6]byte{2, 0, 0, 0, 0, 1})
	if proto == consts.L4ProtoType_TCP {
		packet[len(packet)-7] = 2
		return packet, 6
	}
	ip := packet[14:]
	if source.Addr().Is4() {
		ip[9] = 17
	} else {
		ip[6] = 17
	}
	udp := packet[len(packet)-20:]
	clear(udp[4:])
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	return packet, 17
}
