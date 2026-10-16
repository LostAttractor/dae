// SPDX-License-Identifier: AGPL-3.0-only

package control

import "github.com/daeuniverse/dae/common/consts"

type routeAction uint8

const (
	routeKeep routeAction = iota
	routeMatch
	routeTarget
	routeUntrusted
	routeUnknown
)

// Routing facts contain no I/O. Diagnostics can leave sniffing or verification
// unknown; the live path supplies definite results after verifySniff.
type routeFacts struct {
	outbound      consts.OutboundIndex
	capture       uint8
	destination   bool
	mode          consts.RerouteMode
	verified      predicateResult
	shouldReroute predicateResult
	dialOverride  bool
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
	reroute := predicateMiss
	switch {
	case p.target, !valid, f.mode == consts.RerouteMode_Force:
		reroute = predicateMatch
	case f.mode == consts.RerouteMode_WhileNeed:
		reroute = f.shouldReroute
	}
	if reroute == predicateUnknown || f.verified == predicateUnknown && (reroute == predicateMatch || f.dialOverride) {
		p.action = routeUnknown
		return p
	}
	p.override = f.dialOverride && f.verified == predicateMatch
	if reroute == predicateMatch {
		switch {
		case p.target:
			p.action = routeTarget
		case f.capture != 0 && f.verified != predicateMatch:
			p.action = routeUntrusted
		default:
			p.action = routeMatch
		}
	}
	return p
}
