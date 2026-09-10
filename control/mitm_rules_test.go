// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestMITMPlanRoutingPrioritySurvivesReconstruction(t *testing.T) {
	for _, test := range []struct {
		name, userRules string
		want            consts.OutboundIndex
		mark            uint32
	}{
		{"plugin default", "", consts.OutboundDirect, 0},
		{"explicit block", "domain(full: service.example) -> block(mark:37)", consts.OutboundBlock, 37},
		{"explicit proxy", "domain(full: service.example) -> proxy(mark:37)", consts.OutboundUserDefinedMin, 37},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := mitmRoutingPlugin("service.example").Plan()
			plan.Routes = prepareFlowRulesForTest(t, "", "domain(full: service.example) -> direct").routing
			plan.EarlyRoutes = prepareFlowRulesForTest(t, "", "domain(full: rejected.example) -> block").routing
			prepared := prepareFlowRulesForTest(t, "", test.userRules+"\ndomain(full: rejected.example) -> direct")
			prepared.enableMITMPlan(plan)
			matcher, _ := routingMatcherForTest(t, prepared)
			for _, proto := range []consts.L4ProtoType{consts.L4ProtoType_TCP, consts.L4ProtoType_UDP} {
				outbound, mark, must := matchTestRoute(t, matcher, "service.example", proto)
				if outbound != test.want || mark != test.mark || must {
					t.Fatalf("plugin route overrode user policy: %v/%d/%v", outbound, mark, must)
				}
				bitmap := matcher.domainMatcher.MatchDomainBitmap("service.example")
				address := make([]byte, 16)
				outbound, mark, must, err := matcher.Match(address, address, 12345, 443, consts.IpVersion_4, proto, "different.example", [16]uint8{}, 0, 0, address, bitmap, bitmap)
				if err != nil || outbound != test.want || mark != test.mark || must {
					t.Fatalf("DNS route reconstruction changed policy: %v/%d/%v, %v", outbound, mark, must, err)
				}
				outbound, _, _ = matchTestRoute(t, matcher, "rejected.example", proto)
				if outbound != consts.OutboundBlock {
					t.Fatalf("early route lost priority over explicit direct: %v", outbound)
				}
			}
		})
	}
}
