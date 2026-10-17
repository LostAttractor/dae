// SPDX-License-Identifier: AGPL-3.0-only

package dnscache

import (
	"context"
	"fmt"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

// Explain peeks at the exact cache key without moving its LRU position,
// removing expired entries, extending TTL or incrementing any counter.
func (c *Cache) Explain(ctx context.Context, input api.ExplainRequest) plugin.Explanation {
	step := api.ExplainStep{ID: "cache", Stage: "dns_cache", Expression: "context + transport + destination + canonical query", Status: "evaluated", Match: "unknown", Reason: "missing_exact_dns_context"}
	result := plugin.Explanation{Steps: []api.ExplainStep{step}, Complete: false}
	request, ok := plugin.DiagnosticDNSRequest(ctx)
	if !ok || request.ContextKey == "" {
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
		entry   entry
		at      time.Time
	}
	sample := plugin.SamplesForDiagnostics(ctx).Sample(struct {
		cache *Cache
		key   key
	}{c, k}, func() observation {
		c.mu.Lock()
		defer c.mu.Unlock()
		value := observation{at: time.Now()}
		if elem := c.entries[k]; elem != nil {
			value.present, value.entry = true, *elem.Value.(*entry)
		}
		return value
	})
	if sample.present {
		entry := sample.entry
		if !sample.at.Before(entry.expires) {
			result.Steps[0].Match, result.Steps[0].Reason = "miss", "cache_expired"
			return result
		}
		result.Terminal = true
		result.Steps[0].Match, result.Steps[0].Status, result.Steps[0].Reason = "match", "selected", fmt.Sprintf("cache_hit; remaining_ttl=%s", entry.expires.Sub(sample.at).Round(time.Second))
		result.DNS = entry.response.MessageCopy()
		return result
	}
	result.Steps[0].Match, result.Steps[0].Reason = "miss", "cache_key_absent"
	return result
}
