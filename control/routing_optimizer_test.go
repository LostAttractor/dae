package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestRoutingOptimizationPreservesNegatedAlternatives(t *testing.T) {
	prepared := prepareFlowRulesForTest(t, "", `
!dport(80) -> proxy(mark: 37)
!dport(443) -> proxy(mark: 37)`)
	matcher, _ := routingMatcherForTest(t, prepared)
	ip := netip.MustParseAddr("192.0.2.1").As16()
	for _, port := range []uint16{22, 53, 80, 443} {
		// At least one original rule matches every port. Combining their
		// negated argument lists would wrongly exclude both 80 and 443.
		outbound, mark, must, err := matcher.Match(ip[:], ip[:], 32000, port,
			consts.IpVersion_4, consts.L4ProtoType_TCP, "", [16]byte{}, 0, 0, make([]byte, 16))
		if err != nil || outbound != consts.OutboundUserDefinedMin || mark != 37 || must {
			t.Fatalf("port %d: got=(%v,%d,%v), err=%v", port, outbound, mark, must, err)
		}
	}
}
