// SPDX-License-Identifier: AGPL-3.0-only

package routing

import (
	"math/rand/v2"
	"net/netip"
)

// DestinationRewrite changes the final dial address after policy selection.
// Proxy enables the rewrite for proxy outbounds as well as direct traffic.
// Callers supply normalized IPs and at least one target.
type DestinationRewrite struct {
	From  netip.Addr
	To    []netip.Addr
	Proxy bool
}

// DestinationRewrites is ordered: the first matching rule wins, including
// when that rule disables rewriting for the selected outbound.
type DestinationRewrites []DestinationRewrite

func (rules DestinationRewrites) Lookup(ip netip.Addr) *DestinationRewrite {
	ip = ip.Unmap()
	for i := range rules {
		if rules[i].From == ip {
			return &rules[i]
		}
	}
	return nil
}

// Rewrite selects once per connection/association and preserves the port.
func (rules DestinationRewrites) Rewrite(dst netip.AddrPort, proxy bool) (netip.AddrPort, bool) {
	rule := rules.Lookup(dst.Addr())
	if rule == nil || proxy && !rule.Proxy {
		return dst, false
	}
	return netip.AddrPortFrom(rule.To[rand.IntN(len(rule.To))], dst.Port()), true
}
