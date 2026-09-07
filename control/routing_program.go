// SPDX-License-Identifier: AGPL-3.0-only

package control

import "net/netip"

// The compiled predicate keeps only its target IPs, not the source configuration.
type destinationPredicate struct {
	start, end int
	domain     bool
	targets    []netip.Addr
}

// DestinationProgram prepares targets before FlowProgram. Its kernel range
// captures DNAT/Host and deferred HTTP candidates before old-target routing.
// Its userspace predicates select the first exact IP target; HTTP middleware
// determines request targets separately. Later programs see the effective target.
type DestinationProgram struct {
	start, end int
	predicates []destinationPredicate
}

// FlowProgram accumulates controls after destination matching and before
// ordinary routing. end includes FlowEnd, which resolves the controls.
type FlowProgram struct {
	start, end int
}

// RoutingProgram selects outbound and mark using the effective destination and
// the original source, interface, process and policy identity.
type RoutingProgram struct {
	start, end int
}
