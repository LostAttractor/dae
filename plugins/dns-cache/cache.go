// SPDX-License-Identifier: AGPL-3.0-only

// Package dnscache provides bounded DNS response caching independently of
// upstream selection. Only raw upstream responses enter this cache.
package dnscache

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/plugin"
	cachepolicy "github.com/daeuniverse/dae/pkg/dnscache"
	dns "github.com/miekg/dns"
)

var Plugin = plugin.Definition{Configure: Configure}

type settings struct {
	Size        int
	MemoryLimit int
	FixedTTL    []string
}

type key struct {
	upstream plugin.DNSUpstreamKey
	query    cachepolicy.Query
}
type Cache struct {
	store    *cachepolicy.Store[key, *plugin.DNSResponse]
	fixed    map[string]uint32
	bypasses atomic.Uint64
}

func Configure(spec plugin.Spec) (plugin.Factory, error) {
	conf, fixed, err := parseSettings(spec)
	if err != nil {
		return nil, err
	}
	return func(_ context.Context, services plugin.Services) (plugin.Plugin, error) {
		c := &Cache{store: cachepolicy.NewStore[key, *plugin.DNSResponse](conf.Size, conf.MemoryLimit), fixed: fixed}
		if services.Metrics != nil {
			if err := services.Metrics.Register(c); err != nil {
				return nil, fmt.Errorf("cache metrics: %w", err)
			}
		}
		return c, nil
	}, nil
}

func parseSettings(spec plugin.Spec) (settings, map[string]uint32, error) {
	conf := settings{Size: 32768, MemoryLimit: 67108864}
	if err := plugin.DecodeSettingsFields(spec.Config, map[string]any{
		"size": &conf.Size, "memory_limit": &conf.MemoryLimit,
		"fixed_domain_ttl": &conf.FixedTTL,
	}); err != nil {
		return conf, nil, err
	}
	if conf.Size < 1 || conf.MemoryLimit < 65536 {
		return conf, nil, fmt.Errorf("size must be positive; memory_limit must be at least 65536")
	}
	fixed := make(map[string]uint32)
	for _, item := range conf.FixedTTL {
		name, value, ok := strings.Cut(string(item), ":")
		ttl, err := strconv.ParseUint(strings.TrimSpace(value), 0, 31)
		if !ok || err != nil {
			return conf, nil, fmt.Errorf("invalid value in fixed_domain_ttl; expected domain:ttl")
		}
		fixed[dns.CanonicalName(strings.TrimSpace(name))] = uint32(ttl)
	}
	return conf, fixed, nil
}

func (*Cache) Plan() plugin.Plan { return plugin.Plan{DNS: []plugin.DNSScope{{}}} }

func cacheKey(request *plugin.DNSExchange) (key, bool) {
	query, ok := queryKey(request)
	// An answer is attributable only to a known resolver and egress.
	if !ok || request.Egress == "" || request.Upstream == "" {
		return key{}, false
	}
	return key{upstream: request.UpstreamKey(), query: query}, true
}

func queryKey(request *plugin.DNSExchange) (cachepolicy.Query, bool) {
	message := request.MessageCopy()
	if !clientCacheEDNS(message) {
		return cachepolicy.Query{}, false
	}
	return cachepolicy.QueryKey(message)
}

// Until the client cache implements each option's response semantics, option
// queries and replies pass through. Exact query matching alone cannot establish
// ECS scope or make NSID, Cookies and other transaction data replayable.
func clientCacheEDNS(m *dns.Msg) bool {
	opt, valid := cachepolicy.EDNS(m)
	return valid && (opt == nil || len(opt.Option) == 0)
}

func (c *Cache) LookupDNSUpstream(request *plugin.DNSExchange) *plugin.DNSResponse {
	k, ok := cacheKey(request)
	if !ok {
		return nil
	}
	now := time.Now()
	if entry, hit := c.store.Lookup(k, now); hit {
		return replayResponse(entry, request.MessageCopy(), now)
	}
	return nil
}

// RecordDNSUpstream counts once per upstream query; queries outside the cache's
// key semantics bypass it. The query is not bound to an upstream candidate.
func (c *Cache) RecordDNSUpstream(request *plugin.DNSExchange, hit bool) {
	// Only a query within the key semantics can hit.
	if !hit {
		if _, ok := queryKey(request); !ok {
			c.bypasses.Add(1)
			return
		}
	}
	c.store.Record(hit)
}

func replayResponse(entry cachepolicy.Record[*plugin.DNSResponse], query *dns.Msg, now time.Time) *plugin.DNSResponse {
	response := entry.Value.Copy()
	elapsed := uint32(max(0, now.Sub(entry.ReceivedAt)/time.Second))
	message := response.MessageCopy()
	cachepolicy.Age(message, elapsed)
	cachepolicy.Replay(message, query)
	response.DNSPacket = plugin.DNSMessage(message)
	response.Cached = true
	return response
}

func (c *Cache) StoreDNSUpstream(request *plugin.DNSExchange, response *plugin.DNSResponse) *plugin.DNSResponse {
	k, ok := cacheKey(request)
	if !ok {
		return response
	}
	if response.ReceivedAt.IsZero() {
		response = response.Copy()
		response.ReceivedAt = time.Now()
	}
	query := request.MessageCopy()
	// Wire is authoritative. Never repair an opaque/malformed packet by
	// unpacking loosely and then discarding the original bytes.
	m := response.MessageCopy()
	if !clientCacheEDNS(m) || netutils.ValidateDnsResponse(query, m, query.Id) != nil {
		return response
	}
	ttl, fixed := c.fixed[dns.CanonicalName(query.Question[0].Name)]
	if fixed && !cachepolicy.Signed(m) {
		for _, rr := range m.Answer {
			rr.Header().Ttl = ttl
		}
		m.AuthenticatedData = false
		response = response.Copy()
		response.DNSPacket = plugin.DNSMessage(m)
	}
	if fixed && ttl == 0 {
		return response
	}
	if ttl = cachepolicy.Prepare(query.Question[0].Qtype, m); ttl == 0 {
		return response
	}
	cachepolicy.StripOPT(m)
	at := response.ReceivedAt
	expires := at.Add(time.Duration(ttl) * time.Second)
	if !time.Now().Before(expires) {
		return response
	}
	wire, err := m.Pack()
	if err != nil {
		return response
	}
	bytes := 4*len(wire) + len(k.upstream.Endpoint) + len(k.upstream.Egress) + len(k.query.Question.Name) + len(k.query.Options) + 512
	owned := response.Copy()
	owned.DNSPacket = plugin.DNSMessage(m)
	c.store.Put(k, cachepolicy.Record[*plugin.DNSResponse]{Value: owned, ReceivedAt: at, Expires: expires}, bytes)
	return response
}

func (c *Cache) Run(ctx context.Context, _ *http.Client) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			c.store.Expire(now)
		}
	}
}

func (c *Cache) Report() any {
	s := c.store.Snapshot()
	return map[string]any{"entries": s.Entries, "limit": s.Limit, "bytes": s.Bytes, "memory_limit": s.MemoryLimit, "hits": s.Hits, "misses": s.Misses}
}
