// SPDX-License-Identifier: AGPL-3.0-only
package control

import (
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"net"
	"net/netip"
	"testing"
)

func TestCaptureAPIPrefixAndIndependentActions(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		_, base := destinationTestMatcher(t, "dip(10.0.0.1) -> dnat(198.51.100.1)")
		prepared := preparedRules{destinations: []routing.DestinationRewrite{base.destinations[0].rule}}
		if tcp {
			prepared.enableMITMPlan(surgeRoutingEngine(t, "service.example").Plan())
		}
		prepared.bypassAPI(8081, []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}})
		matcher, builder := surgeRoutingMatcher(t, prepared)
		for i := range builder.rules {
			if builder.rules[i].CaptureFlags != 0 {
				if i < 3 {
					t.Fatal("capture precedes API bypass")
				}
				builder.rules[i].CaptureFlags = 0
				builder.rules[i].Outbound = 2
			}
		}
		for _, address := range []string{"10.0.0.1", "192.0.2.1"} {
			for _, port := range []uint16{443, 8081} {
				for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
					ip := netip.MustParseAddr(address).As16()
					got, _, _, err := matcher.Match(ip[:], ip[:], 12345, port, consts.IpVersion_4, proto, "", [16]uint8{}, 0, 0, make([]byte, 16))
					capture := address == "10.0.0.1" || tcp && proto == consts.L4ProtoType_TCP
					bypass := address == "10.0.0.1" && port == 8081 && proto == consts.L4ProtoType_TCP
					if err != nil || (got == 2) != (capture && !bypass) {
						t.Fatalf("%s:%d/%v got=%v err=%v", address, port, proto, got, err)
					}
				}
			}
		}
	}
}
