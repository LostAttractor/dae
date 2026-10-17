// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"net/netip"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/consts"
)

// The classifier applies the published connectivity state only to ordinary
// non-DNS, uncaptured proxy handoffs. Reuse the publisher's state encoding.
func (c *ControlPlane) diagnosticHandoffState(input routingInput, evaluation routingEvaluation, available bool) uint32 {
	if !input.kernel || input.dst.Port() == 53 || evaluation.captureFlags != 0 || evaluation.outbound < consts.OutboundUserDefinedMin || evaluation.outbound >= consts.OutboundMustRules {
		return outboundConnectivityAlive
	}
	return encodeOutboundConnectivity(available, c.noConnectivityTrySniff, c.noConnectivityOutbound)
}

// Sample evidence without running the resolver or refreshing DNS retention.
// planRoute owns the decision; this adapter only describes what is known.
func (c *ControlPlane) diagnosticRoutePlan(request api.ExplainRequest, s *diagnosticState, ingress netip.AddrPort, hostname string, noSniff bool, missing map[string]bool, facts routeFacts) (routePlan, bool, []string) {
	verified := hostname != "" && c.sniffVerifyMode == consts.SniffVerifyMode_None
	verificationKnown := true
	key := hostname + "."
	if hostname != "" && c.sniffVerifyMode != consts.SniffVerifyMode_None {
		verified = s.registered[key] && (c.sniffVerifyMode == consts.SniffVerifyMode_Loose || s.paired[key][ingress.Addr()].Paired)
		if c.sniffVerifyMode == consts.SniffVerifyMode_Loose && !s.registered[key] {
			verified, verificationKnown = s.verifiedName, s.verifiedName
		}
	}
	if request.Context.Origin == "daemon" {
		verified, verificationKnown = hostname != "", true
	}
	covered := s.paired[key][ingress.Addr()].KernelCovered
	facts.shouldReroute = routingTruth(hostname != "" && !covered)
	facts.verified = routingTruth(verified)
	if !verificationKnown {
		facts.verified = predicateUnknown
	}
	hostnameMissing := request.Context.Origin != "daemon" && missing["hostname"] && !noSniff
	if hostnameMissing {
		facts.verified, facts.shouldReroute = predicateUnknown, predicateUnknown
	}
	plan := planRoute(facts)
	switch plan.action {
	case routeUnknown:
		if hostnameMissing {
			return plan, false, []string{"hostname"}
		}
		return plan, false, []string{"hostname_verification"}
	case routeUntrusted:
		return plan, false, []string{"trusted_hostname"}
	}
	return plan, verified, nil
}
