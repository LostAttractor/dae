// SPDX-License-Identifier: AGPL-3.0-only

package dnscache

import (
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

func TestExplainDoesNotTouchCacheLifetimeOrLRU(t *testing.T) {
	c := testCache(t, "")
	request := testRequest()
	c.ObserveDNS(t.Context(), request, testResponse(request))
	other := request.Copy()
	other.ContextKey = "other"
	c.ObserveDNS(t.Context(), other, testResponse(other))
	front := c.lru.Front()
	hits, misses, expired := c.hits, c.misses, c.expired
	ctx := plugin.WithDiagnosticDNSRequest(t.Context(), request.DNSRequest)
	input := api.ExplainRequest{Kind: "dns", DNS: &api.DiagnosticDNS{Name: "test.example.", Type: "A"}}
	result := c.Explain(ctx, input)
	if !result.Complete || !result.Terminal || !strings.HasPrefix(result.Steps[0].Reason, "cache_hit") {
		t.Fatalf("%+v", result)
	}
	if c.lru.Front() != front || c.hits != hits || c.misses != misses || c.expired != expired {
		t.Fatal("explanation touched live cache state")
	}
	k, _ := cacheKey(request)
	c.entries[k].Value.(*entry).expires = time.Now().Add(-time.Second)
	result = c.Explain(ctx, input)
	if !result.Complete || result.Terminal || result.Steps[0].Reason != "cache_expired" || c.entries[k] == nil || c.expired != expired {
		t.Fatal("expired peek mutated cache", result)
	}
	if result := c.Explain(t.Context(), input); result.Complete {
		t.Fatal("missing cache context reported as a miss")
	}
	pinned := plugin.WithDiagnosticSamples(ctx)
	first := c.Explain(pinned, input)
	c.entries[k].Value.(*entry).expires = time.Now().Add(time.Hour)
	second := c.Explain(pinned, input)
	if first.Steps[0].Reason != second.Steps[0].Reason || second.Terminal {
		t.Fatal("comparison resampled a live cache entry")
	}
}
