// SPDX-License-Identifier: AGPL-3.0-only

package routing

import (
	"github.com/daeuniverse/dae/pkg/config_parser"
	"net/netip"
)

// DestinationRewrite changes the dial address after policy selection, keeping
// the original port. Proxy also applies the mapping to proxy outbounds.
// Filter uses ordinary routing predicates; To contains at least one target IP.
type DestinationRewrite struct {
	Filter []*config_parser.Function
	To     []netip.Addr
	Proxy  bool
}

// DestinationRewrites is ordered: the first matching predicate wins, even when
// its direct-only action does not apply to the selected outbound.
type DestinationRewrites []DestinationRewrite
