// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/dnscache"
	"github.com/miekg/dns"
)

const maxDNSScriptCacheEntries = 4096

// Only address results are cached. Scripts see the domain, not DNS wire fields;
// each hit constructs a fresh reply for the current ID, flags and question type.
// Results are reused only within the same effective scope and plugin chain.
type dnsScriptCacheKey struct {
	script     *Script
	domain     string
	chain      uint64
	scope      ScriptScope
	generation uint64
}

type dnsScriptCache struct {
	store *dnscache.Store[dnsScriptCacheKey, []netip.Addr]
}

func newDNSScriptCache() *dnsScriptCache {
	return &dnsScriptCache{store: dnscache.NewStore[dnsScriptCacheKey, []netip.Addr](maxDNSScriptCacheEntries, 0)}
}

func dnsScriptKey(script *Script, request *plugin.DNSExchange) dnsScriptCacheKey {
	question, _ := request.Question()
	return dnsScriptCacheKey{script: script, domain: dns.CanonicalName(question.Name), chain: request.Chain}
}

func (c *dnsScriptCache) get(key dnsScriptCacheKey, request *plugin.DNSExchange) *plugin.DNSResponse {
	if !key.scope.valid() {
		return nil
	}
	entry, ok := c.store.Get(key, time.Now())
	if !ok {
		return nil
	}
	response := hostAddressResponse(request, entry.Value, uint32(max(time.Until(entry.Expires), 0)/time.Second))
	response.Cached, response.ReceivedAt = true, entry.ReceivedAt
	return response
}

func (c *dnsScriptCache) put(key dnsScriptCacheKey, addresses []netip.Addr, ttl uint32, received time.Time) {
	if !key.scope.valid() || ttl == 0 || ttl > 1<<31-1 || len(addresses) == 0 {
		return
	}
	bytes := 16*len(addresses) + len(key.domain) + 512
	c.store.Put(key, dnscache.Record[[]netip.Addr]{Value: addresses, ReceivedAt: received, Expires: received.Add(time.Duration(ttl) * time.Second)}, bytes)
}
