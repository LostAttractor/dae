// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

func TestRoutingCaptureBudgetAndUnion(t *testing.T) {
	for _, test := range []struct {
		name         string
		ips, domains bool
	}{
		{"disabled", false, false}, {"Host", true, false},
		{"MITM", false, true}, {"Host and MITM", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared := preparedRules{}
			if test.domains {
				prepared.enableSurgeRouting(surgeRoutingEngine(t, "service.example", "*.example"))
			}
			if test.ips {
				prepared.enableDestinationRewrites(routing.DestinationRewrites{
					{From: netip.MustParseAddr("10.0.0.1")},
					{From: netip.MustParseAddr("2001:db8::1")},
					{From: netip.MustParseAddr("10.0.0.1")},
				})
			}
			prepared.bypassAPI(8081, []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}})
			matcher, builder := surgeRoutingMatcher(t, prepared)
			wantSlots, wantLPM := 4, 1 // API: three predicates and one LPM; fallback: one slot.
			if test.ips || test.domains {
				wantSlots++
				if matcher.captureIndex != 3 {
					t.Fatal("capture displaced the API bypass")
				}
				builder.rules[matcher.captureIndex].Outbound = uint8(consts.OutboundUserDefinedMin)
			} else if matcher.captureIndex != -1 {
				t.Fatal("disabled capture consumes a slot")
			}
			if test.ips {
				wantLPM++
				if len(builder.simulatedLpmTries[1]) != 2 {
					t.Fatal("Host IPs were not combined and deduplicated")
				}
			}
			if len(builder.rules) != wantSlots || len(builder.simulatedLpmTries) != wantLPM {
				t.Fatalf("kernel resources: match sets=%d LPM maps=%d, want %d/%d", len(builder.rules), len(builder.simulatedLpmTries), wantSlots, wantLPM)
			}
			for _, ip := range []string{"10.0.0.1", "2001:db8::1", "192.0.2.1"} {
				for _, host := range []string{"service.example", "outside.test"} {
					for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
						for _, port := range []uint16{443, 8081} {
							address := netip.MustParseAddr(ip)
							bytes := address.As16()
							got, _, _, err := matcher.Match(bytes[:], bytes[:], 12345, port, consts.IpVersionFromAddr(address), proto, host, [16]uint8{}, 0, 0, make([]byte, 16))
							capture := test.ips && ip != "192.0.2.1" || test.domains && host == "service.example" && proto == consts.L4ProtoType_TCP
							api := ip == "10.0.0.1" && port == 8081 && proto == consts.L4ProtoType_TCP
							want := consts.OutboundDirect
							if capture && !api {
								want = consts.OutboundUserDefinedMin
							}
							if err != nil || got != want {
								t.Fatalf("%s:%d %s/%v: route=%v err=%v, want %v", ip, port, host, proto, got, err, want)
							}
						}
					}
				}
			}
		})
	}
}
