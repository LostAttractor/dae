// SPDX-License-Identifier: AGPL-3.0-only
package control

import (
	"github.com/daeuniverse/dae/common/consts"
	"net"
	"net/netip"
	"testing"
)

func TestCaptureAPIPrefixAndIndependentActions(t *testing.T) {
	for _, http := range []bool{false, true} {
		prepared := prepareFlowRulesForTest(t, "dip(10.0.0.1) -> dnat(198.51.100.1)", "")
		if http {
			prepared.enableMITMPlan(mitmRoutingPlugin("service.example").Plan())
		}
		prepared.bypassAPI(8081, []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}})
		matcher, builder := routingMatcherForTest(t, prepared)
		for i := range builder.rules {
			if builder.rules[i].CaptureFlags != 0 {
				if i < 3 {
					t.Fatal("capture precedes API bypass")
				}
				builder.rules[i].CaptureFlags = 0
				builder.rules[i].Action = uint8(consts.MatchActionRoute)
				builder.rules[i].Outbound = 2
			}
		}
		for _, address := range []string{"10.0.0.1", "192.0.2.1"} {
			for _, port := range []uint16{443, 8081} {
				for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
					ip := netip.MustParseAddr(address).As16()
					for _, host := range []string{"", "service.example", "outside.test"} {
						got, _, _, err := matcher.Match(ip[:], ip[:], 12345, port, consts.IpVersion_4, proto, host, [16]uint8{}, 0, 0, make([]byte, 16))
						capture := address == "10.0.0.1" || http && host == "service.example" && port == 443
						bypass := address == "10.0.0.1" && port == 8081 && proto == consts.L4ProtoType_TCP
						if err != nil || (got == 2) != (capture && !bypass) {
							t.Fatalf("%s:%d/%v host=%q got=%v err=%v", address, port, proto, host, got, err)
						}
					}
				}
			}
		}
	}
}

// Keep production predicates, exposing only their action. Merely checking the
// final userspace outbound would miss the regression: a captured flow can still
// be dialed with "direct" after leaving the kernel fast path.
func exposeCapturePredicates(t *testing.T, builder *RoutingMatcherBuilder) {
	t.Helper()
	count := 0
	for i := range builder.rules {
		if builder.rules[i].CaptureFlags != 0 {
			builder.rules[i].CaptureFlags = 0
			builder.rules[i].Action = uint8(consts.MatchActionRoute)
			builder.rules[i].Outbound = uint8(consts.OutboundUserDefinedMin)
			count++
		}
	}
	if count == 0 {
		t.Fatal("no capture predicates")
	}
}
