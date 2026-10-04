// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/miekg/dns"
)

const maxDNSScriptCacheEntries = 4096

// Only address results are cached. Scripts see the domain, not DNS wire fields;
// each hit constructs a fresh reply for the current ID, flags and question type.
// Routed HTTP calls can depend on the captured identity, which must stay isolated.
type dnsScriptCacheKey struct {
	script                        *Script
	domain, context, network      string
	source, destination, original netip.AddrPort
	iface                         uint32
	assigned                      bool
}

type dnsScriptCacheEntry struct {
	addresses         []netip.Addr
	received, expires time.Time
}

type dnsScriptCache struct {
	mu      sync.Mutex
	entries map[dnsScriptCacheKey]dnsScriptCacheEntry
}

func dnsScriptKey(script *Script, request *plugin.DNSExchange) dnsScriptCacheKey {
	return dnsScriptCacheKey{script: script, domain: dns.CanonicalName(request.MessageCopy().Question[0].Name),
		context: request.ContextKey, network: request.Network, source: request.Source,
		destination: request.Destination, original: request.OriginalDestination, iface: request.Interface, assigned: request.ServerAssigned}
}

func (c *dnsScriptCache) get(key dnsScriptCacheKey, request *plugin.DNSExchange) *plugin.DNSResponse {
	c.mu.Lock()
	entry, ok := c.entries[key]
	if ok && !time.Now().Before(entry.expires) {
		delete(c.entries, key)
		ok = false
	}
	c.mu.Unlock()
	if !ok {
		return nil
	}
	response := hostAddressResponse(request, entry.addresses, uint32(max(time.Until(entry.expires), 0)/time.Second))
	response.Cached, response.ReceivedAt = true, entry.received
	return response
}

func (c *dnsScriptCache) put(key dnsScriptCacheKey, addresses []netip.Addr, ttl uint32, received time.Time) {
	if ttl == 0 || ttl > 1<<31-1 || len(addresses) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[dnsScriptCacheKey]dnsScriptCacheEntry)
	}
	if len(c.entries) >= maxDNSScriptCacheEntries {
		var earliest dnsScriptCacheKey
		var expires time.Time
		for key, entry := range c.entries {
			if !received.Before(entry.expires) {
				delete(c.entries, key)
			} else if expires.IsZero() || entry.expires.Before(expires) {
				earliest, expires = key, entry.expires
			}
		}
		if len(c.entries) >= maxDNSScriptCacheEntries {
			delete(c.entries, earliest)
		}
	}
	c.entries[key] = dnsScriptCacheEntry{addresses: addresses, received: received, expires: received.Add(time.Duration(ttl) * time.Second)}
}
