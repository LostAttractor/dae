// SPDX-License-Identifier: AGPL-3.0-only

package dnscache

import (
	"context"
	"fmt"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
	cachepolicy "github.com/daeuniverse/dae/pkg/dnscache"
)

// Explain peeks at the exact cache key without moving its LRU position,
// removing expired entries, extending TTL or incrementing any counter.
func (c *Cache) Explain(ctx context.Context, input api.ExplainRequest) plugin.Explanation {
	step := api.ExplainStep{ID: "cache", Stage: "dns_cache", Expression: "policy + actual upstream + transport + canonical query", Status: "evaluated", Match: "unknown", Reason: "cache_lookup_after_upstream_routing"}
	result := plugin.Explanation{Steps: []api.ExplainStep{step}}
	request, ok := plugin.DiagnosticDNSRequest(ctx)
	if !ok || request.Upstream == "" || !request.PolicyKey.Routed {
		return result
	}
	k, cacheable := cacheKey(&plugin.DNSExchange{DNSRequest: request})
	result.Complete = true
	if !cacheable {
		result.Steps[0].Match, result.Steps[0].Reason = "miss", "query_not_cacheable"
		return result
	}
	type observation struct {
		present bool
		entry   cachepolicy.Record[*plugin.DNSResponse]
		at      time.Time
	}
	sample := plugin.SamplesForDiagnostics(ctx).Sample(struct {
		cache *Cache
		key   key
	}{c, k}, func() observation {
		value := observation{at: time.Now()}
		value.entry, value.present = c.store.Peek(k)
		return value
	})
	if sample.present {
		entry := sample.entry
		if !sample.at.Before(entry.Expires) {
			result.Steps[0].Match, result.Steps[0].Reason = "miss", "cache_expired"
			return result
		}
		result.CacheHit = true
		result.Steps[0].Match, result.Steps[0].Status, result.Steps[0].Reason = "match", "selected", fmt.Sprintf("cache_hit; remaining_ttl=%s", entry.Expires.Sub(sample.at).Round(time.Second))
		return result
	}
	result.Steps[0].Match, result.Steps[0].Reason = "miss", "cache_key_absent"
	return result
}
