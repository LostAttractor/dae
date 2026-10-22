// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestRoutePlanEvidenceAndCapture(t *testing.T) {
	for _, test := range []struct {
		name  string
		facts routeFacts
		want  routePlan
	}{
		{"terminal HTTP capture skips sniffing", routeFacts{outbound: consts.OutboundDirect, capture: captureHTTP, mode: consts.RerouteMode_Force, verified: predicateUnknown, dialOverride: true}, routePlan{preserve: true}},
		{"captured block stays terminal", routeFacts{outbound: consts.OutboundBlock, capture: captureHTTP, verified: predicateUnknown}, routePlan{preserve: true}},
		{"destination invalidates direct", routeFacts{outbound: consts.OutboundDirect, capture: captureDestination}, routePlan{action: routeTarget, target: true}},
		{"explicit target invalidates block", routeFacts{outbound: consts.OutboundBlock, destination: true}, routePlan{action: routeTarget, target: true}},
		{"HTTP request reroutes target", routeFacts{capture: captureHTTPRequest, verified: predicateMatch, dialOverride: true}, routePlan{action: routeTarget, target: true, override: true}},
		{"untrusted ambiguous capture uses kernel evidence", routeFacts{outbound: consts.OutboundControlPlaneRouting, capture: captureHTTP}, routePlan{action: routeMatch}},
		{"trusted ambiguous capture reroutes", routeFacts{outbound: consts.OutboundControlPlaneRouting, capture: captureHTTP, verified: predicateMatch}, routePlan{action: routeMatch}},
		{"reserved handoff always reroutes", routeFacts{outbound: consts.OutboundControlPlaneRouting}, routePlan{action: routeMatch}},
		{"force reroutes ordinary proxy", routeFacts{outbound: 2, mode: consts.RerouteMode_Force}, routePlan{action: routeMatch}},
		{"trusted hostname reroutes", routeFacts{outbound: 2, mode: consts.RerouteMode_WhileNeed, verified: predicateMatch}, routePlan{action: routeMatch}},
		{"untrusted hostname keeps the kernel decision", routeFacts{outbound: 2, mode: consts.RerouteMode_WhileNeed}, routePlan{}},
		{"none keeps the kernel decision", routeFacts{outbound: 2, mode: consts.RerouteMode_None, verified: predicateMatch}, routePlan{}},
		{"unknown trust decides a reroute", routeFacts{outbound: 2, mode: consts.RerouteMode_WhileNeed, verified: predicateUnknown}, routePlan{action: routeUnknown}},
		{"unknown trust needed by target", routeFacts{destination: true, verified: predicateUnknown}, routePlan{action: routeUnknown, target: true}},
		{"unknown trust needed by override", routeFacts{outbound: 2, verified: predicateUnknown, dialOverride: true}, routePlan{action: routeUnknown}},
		{"unused unknown trust is irrelevant", routeFacts{outbound: 2, verified: predicateUnknown}, routePlan{}},
		{"kept direct route needs no trust", routeFacts{outbound: consts.OutboundDirect, mode: consts.RerouteMode_None, verified: predicateUnknown, dialOverride: true}, routePlan{}},
		{"kept direct route dials the client address", routeFacts{outbound: consts.OutboundDirect, mode: consts.RerouteMode_None, verified: predicateMatch, dialOverride: true}, routePlan{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := planRoute(test.facts); got != test.want {
				t.Fatalf("plan = %+v, want %+v", got, test.want)
			}
		})
	}
}
