// SPDX-License-Identifier: AGPL-3.0-only

package control

import "net/netip"

// The compiled predicate keeps only its target IPs, not the source configuration.
type destinationPredicate struct {
	span    routingSpan
	domain  bool
	targets []netip.Addr
	port    uint16
}

// DestinationProgram belongs to one policy. Its userspace predicates select
// the first exact IP target, with policy rules before shared plugin rules.
// The policy's ingress spans capture candidates before old-target routing.
type DestinationProgram struct {
	predicates []destinationPredicate
}

// RoutingProgram bounds the physical kernel instruction pool. Policy spans
// determine execution order and phases; userspace destination predicates follow.
type RoutingProgram struct {
	end int
}
