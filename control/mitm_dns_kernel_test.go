// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
	dnsmessage "github.com/miekg/dns"
)

// Cover DNS response acceptance and production map publication as well as the
// classifier. HTTP capture must work on its own, without a DNAT or bump rule.
// These private programs/maps are never attached to a network interface.
func TestMITMDNSCaptureKernelIntegration(t *testing.T) {
	testHTTPKernelCapture(t, false)
}

func TestMITMRequestRoutingKernelIntegration(t *testing.T) {
	testHTTPKernelCapture(t, true)
}

func testHTTPKernelCapture(t *testing.T, requestRouting bool) {
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
		RoutingProfileMap: collection.Maps["routing_profile_map"], RoutingInterfaceMap: collection.Maps["routing_interface_map"], LpmArrayMap: collection.Maps["lpm_array_map"],
		UnusedLpmType: collection.Maps["unused_lpm_type"], DomainRoutingMap: collection.Maps["domain_routing_map"],
	}, bpfVariables: bpfVariables{DefaultRoutingProfile: collection.Variables["default_routing_profile"]}}}
	prepared := prepareFlowRulesForTest(t, "", "")
	plan := mitmRoutingPlugin("grpc.biliapi.net", "app.bilibili.com", "api.bilibili.com", "www.bilibili.com").Plan()
	if requestRouting {
		// An old-target block/must/mark cannot precede request transformations.
		prepared = prepareFlowRulesForTest(t, "dport(80,443) -> must", "domain(full: grpc.biliapi.net, full: app.bilibili.com, full: api.bilibili.com, full: www.bilibili.com) && dport(80,443) -> block(mark:37)")
		for i := range plan.Scopes {
			plan.Scopes[i].PreserveRoute = false
		}
	}
	prepared.enableMITMPlan(plan)
	prepared.enableMITMPlan(plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{
		{Host: "service.example", Ports: []uint16{8443}},
		{Host: "192.0.2.10", Ports: []uint16{8443}},
		{Host: "2001:db8::10", Ports: []uint16{443}},
	}, PreserveRoute: !requestRouting}}})
	prepared.bypassAPI(443, []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}})
	matcher, builder := routingMatcherForTest(t, prepared)
	builder.bpf = state
	if err := builder.BuildKernspace(); err != nil {
		t.Fatal(err)
	}
	core := &controlPlaneCore{bpf: state}
	registry := newDomainRegistry(int(state.DomainRoutingMap.MaxEntries()), consts.DefaultDNSRetentionWindow, core.writeDomainBitmaps, core.deleteDomainBitmaps)
	for i, test := range []struct {
		name, destination, host string
		cname, capture          bool
	}{
		{"gRPC A", "198.51.100.1:443", "grpc.biliapi.net", false, true},
		{"gRPC CNAME", "198.51.100.2:443", "grpc.biliapi.net", true, true},
		{"app CNAME", "198.51.100.3:443", "app.bilibili.com", true, true},
		{"API HTTP", "198.51.100.4:80", "api.bilibili.com", true, true},
		{"web HTTPS", "198.51.100.5:443", "www.bilibili.com", false, true},
		{"gRPC AAAA", "[2001:db8::2]:443", "grpc.biliapi.net", false, true},
		{"gRPC CNAME AAAA", "[2001:db8::3]:443", "grpc.biliapi.net", true, true},
		{"SSH", "10.0.0.1:22", "grpc.biliapi.net", false, false},
		{"unrelated HTTPS", "198.51.100.6:443", "outside.example", false, false},
		{"missing DNS", "198.51.100.7:443", "", false, false},
		{"missing DNS AAAA", "[2001:db8::4]:443", "", false, false},
		{"wrong port", "198.51.100.8:8443", "grpc.biliapi.net", false, false},
		{"API bypass", "10.0.0.1:443", "grpc.biliapi.net", false, false},
		{"custom port", "198.51.100.9:8443", "service.example", false, true},
		{"custom domain wrong port", "198.51.100.10:443", "service.example", false, false},
		{"literal IPv4", "192.0.2.10:8443", "", false, true},
		{"literal IPv4 wrong port", "192.0.2.10:443", "", false, false},
		{"literal IPv6", "[2001:db8::10]:443", "", false, true},
		{"literal IPv6 wrong port", "[2001:db8::10]:8443", "", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, network := range []consts.L4ProtoStr{consts.L4ProtoStr_TCP, consts.L4ProtoStr_UDP} {
				proto := network.ToL4ProtoType()
				t.Run(string(network), func(t *testing.T) {
					destination := netip.MustParseAddrPort(test.destination)
					sourceIP := netip.MustParseAddr("192.0.2.1")
					qtype := uint16(dnsmessage.TypeA)
					if destination.Addr().Is6() {
						sourceIP, qtype = netip.MustParseAddr("2001:db8::1"), dnsmessage.TypeAAAA
					}
					if test.host != "" {
						name := dnsmessage.Fqdn(test.host)
						request := new(dnsmessage.Msg).SetQuestion(name, qtype)
						response := new(dnsmessage.Msg).SetReply(request)
						owner := name
						if test.cname {
							owner = "edge.cdn.example."
							response.Answer = append(response.Answer, testCNAMERecord(name, owner))
						}
						header := dnsmessage.RR_Header{Name: owner, Rrtype: qtype, Class: dnsmessage.ClassINET, Ttl: 60}
						if qtype == dnsmessage.TypeA {
							response.Answer = append(response.Answer, &dnsmessage.A{Hdr: header, A: net.IP(destination.Addr().AsSlice())})
						} else {
							response.Answer = append(response.Answer, &dnsmessage.AAAA{Hdr: header, AAAA: net.IP(destination.Addr().AsSlice())})
						}
						observeDNSRegistry(registry, matcher.domainMatcher.MatchDomainBitmap,
							&plugin.DNSRequest{Message: request}, &plugin.DNSResponse{Message: response, ReceivedAt: time.Now()})
					}
					source := netip.AddrPortFrom(sourceIP, uint16(41000+i))
					packet, ipProto := routingKernelPacket(source, destination, proto)
					key := bpfTuplesKey{Sport: common.Htons(source.Port()), Dport: common.Htons(destination.Port()), L4proto: ipProto}
					key.Sip.U6Addr8, key.Dip.U6Addr8 = source.Addr().As16(), destination.Addr().As16()
					// The management API listens only on TCP. Its bypass must not
					// prevent a declared HTTP/3 target from being captured on UDP.
					capture := test.capture || test.name == "API bypass" && proto == consts.L4ProtoType_UDP
					for _, name := range []string{"lan_ingress_l2", "tproxy_wan_egress_l2"} {
						want := ^uint32(0) // TCX_NEXT: kernel direct, no proxy connection.
						if capture {
							want = 7 // TC_ACT_REDIRECT
						}
						status, err := collection.Programs[name].Run(&ebpf.RunOptions{Data: packet, Context: make([]byte, 256), Repeat: 1})
						if err != nil || status != want {
							t.Fatalf("%s: verdict=%d err=%v, want=%d", name, status, err, want)
						}
						var result bpfRoutingResult
						err = collection.Maps["routing_tuples_map"].Lookup(key, &result)
						if !capture {
							if !errors.Is(err, ebpf.ErrKeyNotExist) {
								t.Fatalf("kernel direct retained proxy state: %+v, %v", result, err)
							}
							continue
						}
						flags, outbound := captureHTTP, uint8(consts.OutboundDirect)
						if requestRouting {
							flags, outbound = captureHTTP|captureHTTPRequest, uint8(consts.OutboundControlPlaneRouting)
						}
						if err != nil || result.CaptureFlags != flags || result.Outbound != outbound || result.Mark != 0 || result.Must != 0 {
							t.Fatalf("%s: HTTP capture changed original route: %+v, %v", name, result, err)
						}
					}
				})
			}
		})
	}
}
