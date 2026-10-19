// SPDX-License-Identifier: AGPL-3.0-only

// Package dnscache supplies DNS response cache rules and bounded storage
// independently of transport and client policy. Callers validate wire messages
// and correlate replies before caching, and keep upstream and policy identities
// in their cache keys.
package dnscache

import dns "github.com/miekg/dns"

// Query is a comparable DNS identity. Ordinary queries need no wire encoding;
// Options is populated only for EDNS options and says nothing about replay safety.
type Query struct {
	Question  dns.Question
	Header    dns.MsgHdr
	HasEDNS   bool
	UDPSize   uint16
	EDNSFlags uint32
	Options   string
}

// QueryKey identifies an ordinary IN query, excluding its ID and name casing.
// Flags and EDNS options remain part of the key. Callers decide which options
// they can safely replay; identity alone does not establish cache eligibility.
func QueryKey(m *dns.Msg) (Query, bool) {
	if m == nil || m.Response || m.Opcode != dns.OpcodeQuery || len(m.Question) != 1 ||
		m.Question[0].Qclass != dns.ClassINET || len(m.Answer) != 0 || len(m.Ns) != 0 || m.Truncated || m.Rcode != 0 {
		return Query{}, false
	}
	switch m.Question[0].Qtype {
	case dns.TypeAXFR, dns.TypeIXFR, dns.TypeTKEY:
		return Query{}, false
	}
	if _, ok := dns.IsDomainName(m.Question[0].Name); !ok {
		return Query{}, false
	}
	for _, rr := range m.Extra {
		if _, ok := rr.(*dns.OPT); !ok {
			return Query{}, false
		}
	}
	opt, ok := EDNS(m)
	if !ok {
		return Query{}, false
	}
	key := Query{Question: m.Question[0], Header: m.MsgHdr}
	key.Question.Name = dns.CanonicalName(key.Question.Name)
	key.Header.Id = 0
	if opt != nil {
		key.HasEDNS, key.UDPSize, key.EDNSFlags = true, opt.UDPSize(), opt.Hdr.Ttl
		if len(opt.Option) != 0 {
			if dns.Len(opt) > 4096 {
				return Query{}, false
			}
			wire := make([]byte, dns.Len(opt))
			// PackRR updates Rdlength; the caller's OPT remains immutable.
			owned := *opt
			n, err := dns.PackRR(&owned, wire, 0, nil, false)
			if err != nil {
				return Query{}, false
			}
			key.Options = string(wire[:n])
		}
	}
	return key, true
}

// Signed includes DNSSEC signatures as well as transaction signatures. These
// responses require additional validation and are conservatively left uncached.
func Signed(m *dns.Msg) bool {
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			switch rr.Header().Rrtype {
			case dns.TypeRRSIG, dns.TypeTSIG, dns.TypeSIG:
				return true
			}
		}
	}
	return false
}

// Prepare returns the cache lifetime in seconds, or zero if m is not cacheable.
// The caller owns m: negative SOA TTLs are clamped to their caching lifetime so
// replay cannot restart SOA MINIMUM (RFC 2308). CNAME and other RR TTLs also bound
// the lifetime. High-bit TTLs are treated as zero (RFC 2181).
// EDNS option eligibility and OPT removal belong to the caller's replay policy.
func Prepare(qtype uint16, m *dns.Msg) uint32 {
	if m == nil || !m.Response || m.Truncated || Signed(m) ||
		(m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError) {
		return 0
	}
	ttl := ^uint32(0)
	negative := true
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == qtype || qtype == dns.TypeANY {
			negative = false
		}
	}
	negative = negative || m.Rcode == dns.RcodeNameError
	soa := false
	if negative {
		for _, rr := range m.Ns {
			if record, ok := rr.(*dns.SOA); ok {
				if record.Minttl >= 1<<31 {
					return 0
				}
				ttl = min(ttl, record.Minttl)
				soa = true
			}
		}
	}
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if rr.Header().Ttl >= 1<<31 {
				return 0
			}
			ttl = min(ttl, rr.Header().Ttl)
		}
	}
	if ttl == ^uint32(0) || ttl == 0 || negative && !soa {
		return 0
	}
	if negative {
		for _, rr := range m.Ns {
			if record, ok := rr.(*dns.SOA); ok {
				record.Hdr.Ttl = min(record.Hdr.Ttl, ttl)
			}
		}
	}
	return ttl
}

// Age decrements ordinary RR TTLs in an owned message, saturating at zero.
// OPT has flags and an extended RCODE in that field, not a TTL.
func Age(m *dns.Msg, elapsed uint32) {
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != dns.TypeOPT {
				rr.Header().Ttl -= min(rr.Header().Ttl, elapsed)
			}
		}
	}
}
