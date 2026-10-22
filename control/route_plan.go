// SPDX-License-Identifier: AGPL-3.0-only

package control

import "github.com/daeuniverse/dae/common/consts"

type routeAction uint8

const (
	routeKeep routeAction = iota
	routeMatch
	routeTarget
	routeUnknown
)

// Routing facts contain no I/O. Diagnostics can leave sniffing or verification
// unknown; the live path supplies definite results after verifySniff.
type routeFacts struct {
	outbound     consts.OutboundIndex
	capture      uint8
	destination  bool
	mode         consts.RerouteMode
	verified     predicateResult
	dialOverride bool
}

type routePlan struct {
	action   routeAction
	target   bool
	preserve bool // Terminal capture shortcut, before hostname verification.
	override bool
}

func routingTruth(value bool) predicateResult {
	if value {
		return predicateMatch
	}
	return predicateMiss
}

func planRoute(f routeFacts) routePlan {
	p := routePlan{target: f.destination || f.capture&(captureDestination|captureHTTPRequest) != 0}
	valid := f.outbound < consts.OutboundMustRules
	if !p.target && f.capture != 0 && valid && (f.outbound == consts.OutboundDirect || f.outbound == consts.OutboundBlock) {
		p.preserve = true
		return p
	}
	// A kernel decision changes only with a trusted hostname: without one,
	// userspace has no evidence beyond the kernel's. With one, routing it is
	// exact whatever evidence the kernel held when the flow arrived.
	reroute := predicateMiss
	switch {
	case p.target, !valid:
		reroute = predicateMatch
	case f.mode == consts.RerouteMode_WhileNeed, f.mode == consts.RerouteMode_WhilePossible:
		reroute = f.verified
	}
	// A direct flow that keeps its route dials the client's address, so only a
	// reroute or a proxy's dial target needs the hostname verified.
	override := f.dialOverride && (reroute == predicateMatch || f.outbound != consts.OutboundDirect)
	if reroute == predicateUnknown || f.verified == predicateUnknown && (reroute == predicateMatch || override) {
		p.action = routeUnknown
		return p
	}
	p.override = override && f.verified == predicateMatch
	if reroute == predicateMatch {
		p.action = routeMatch
		if p.target {
			p.action = routeTarget
		}
	}
	return p
}
