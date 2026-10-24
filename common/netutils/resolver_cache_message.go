// SPDX-License-Identifier: AGPL-3.0-only

package netutils

import (
	"time"

	"github.com/daeuniverse/dae/pkg/dnscache"
	dns "github.com/miekg/dns"
)

// resolverCacheExchange owns the DNS semantics of one internal exchange. The
// connection adapter supplies complete wire messages and serializes access;
// this type owns neither transport framing nor connection lifecycle.
type resolverCacheExchange struct {
	cache *dnscache.Cache
	scope string
	query *dns.Msg
	key   dnscache.Key
	// lifetime, if set, receives this exchange's outcome exactly once.
	lifetime *addressLifetime
}

func (x *resolverCacheExchange) settle(expires time.Time, neutral bool) {
	x.lifetime.settle(expires, neutral)
	x.lifetime = nil
}

// Internal queries only cache ordinary EDNS negotiation. Option-specific
// semantics stay outside this resolver, including ECS, Cookies and NSID.
func internalCacheEDNS(m *dns.Msg) bool {
	opt, valid := dnscache.EDNS(m)
	return valid && (opt == nil || len(opt.Option) == 0)
}

func (x *resolverCacheExchange) lookup(wire []byte, datagram bool) []byte {
	query := new(dns.Msg)
	if UnpackDnsMessage(wire, query) != nil || !internalCacheEDNS(query) {
		return nil
	}
	key, ok := dnscache.QueryKey(query)
	if !ok {
		return nil
	}
	x.query, x.key = query, dnscache.Key{Namespace: x.scope, Query: key}
	response, expires, hit := x.cache.Get(x.key, time.Now())
	if !hit {
		return nil
	}
	dnscache.Replay(response, query)
	response.Compress = true
	reply, err := response.Pack()
	limit := 65535
	if datagram {
		limit = 512
		if opt := query.IsEdns0(); opt != nil {
			limit = max(limit, int(opt.UDPSize()))
		}
	}
	if err != nil || len(reply) > limit {
		return nil
	}
	x.query = nil
	x.settle(expires, false)
	return reply
}

// observe ignores malformed or unrelated packets without normalizing them.
// A correlated reply completes observation even when its policy forbids caching.
func (x *resolverCacheExchange) observe(wire []byte, datagram bool) bool {
	response := new(dns.Msg)
	if UnpackDnsMessage(wire, response) != nil || ValidateDnsResponse(x.query, response, x.query.Id) != nil {
		return false
	}
	var expires time.Time
	if internalCacheEDNS(response) {
		dnscache.StripOPT(response)
		expires = x.cache.Put(x.key, x.query.Question[0].Qtype, response, time.Now())
	}
	// net.Resolver retries a truncated datagram over TCP, which settles the answer.
	x.settle(expires, datagram && response.Truncated)
	x.query = nil
	return true
}
