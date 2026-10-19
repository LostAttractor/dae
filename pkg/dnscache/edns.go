// SPDX-License-Identifier: AGPL-3.0-only

package dnscache

import (
	"slices"

	dns "github.com/miekg/dns"
)

// EDNS validates the OPT envelope, independently of option replay policy.
// Absence is valid. Callers must decide how to handle the returned options.
func EDNS(m *dns.Msg) (*dns.OPT, bool) {
	if m == nil {
		return nil, false
	}
	var result *dns.OPT
	for _, rr := range m.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			if result != nil || opt.Hdr.Name != "." || opt.Version() != 0 {
				return nil, false
			}
			result = opt
		}
	}
	return result, true
}

// StripOPT removes transaction control data from an owned response before storage.
func StripOPT(m *dns.Msg) {
	m.Extra = slices.DeleteFunc(m.Extra, func(rr dns.RR) bool { return rr.Header().Rrtype == dns.TypeOPT })
}

// Replay restores the current query's identity and ordinary EDNS negotiation in
// an owned, aged response. The caller must have excluded EDNS options requiring
// additional semantics. It never retains control data from the cached response.
func Replay(response, query *dns.Msg) {
	response.Id, response.Question = query.Id, slices.Clone(query.Question)
	StripOPT(response)
	if opt := query.IsEdns0(); opt != nil {
		response.SetEdns0(opt.UDPSize(), opt.Do())
	}
}
