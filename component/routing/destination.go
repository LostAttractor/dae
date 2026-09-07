// SPDX-License-Identifier: AGPL-3.0-only

package routing

import (
	"github.com/daeuniverse/dae/pkg/config_parser"
	"net/netip"
)

// DestinationRewrite changes the destination before flow controls and routing,
// keeping the original port. The mapping applies to direct and proxy outbounds.
// Filter uses ordinary routing predicates; To contains at least one target IP.
type DestinationRewrite struct {
	Filter []*config_parser.Function
	To     []netip.Addr
}

// DestinationRewrites is ordered: the first matching predicate wins.
// The rewritten target is routed without recursively evaluating destination rules.
type DestinationRewrites []DestinationRewrite
