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
	c.storeResponse(request, testResponse(request))
	other := request.Copy()
	other.PolicyKey = plugin.DNSPolicyKey{Generation: 2}
	c.storeResponse(other, testResponse(other))
	before := c.store.Snapshot()
	ctx := plugin.WithDiagnosticDNSRequest(t.Context(), request.DNSRequest)
	input := api.ExplainRequest{Kind: "dns", DNS: &api.DiagnosticDNS{Name: "test.example.", Type: "A"}}
	result := c.Explain(ctx, input)
	if !result.Complete || result.Terminal || !strings.HasPrefix(result.Steps[0].Reason, "cache_hit") {
		t.Fatalf("%+v", result)
	}
	if c.store.Snapshot() != before {
		t.Fatal("explanation touched live cache state")
	}
	k, _ := cacheKey(request)
	entry, _ := c.store.Peek(k)
	entry.Expires = time.Now().Add(-time.Second)
	c.store.Put(k, entry, 512)
	before = c.store.Snapshot()
	result = c.Explain(ctx, input)
	if !result.Complete || result.Terminal || result.Steps[0].Reason != "cache_expired" || c.store.Snapshot() != before {
		t.Fatal("expired peek mutated cache", result)
	}
	if result := c.Explain(t.Context(), input); result.Complete || result.Steps[0].Match != "unknown" {
		t.Fatal("missing upstream reported as a miss")
	}
	pinned := plugin.WithDiagnosticSamples(ctx)
	first := c.Explain(pinned, input)
	entry.Expires = time.Now().Add(time.Hour)
	c.store.Put(k, entry, 512)
	second := c.Explain(pinned, input)
	if first.Steps[0].Reason != second.Steps[0].Reason || second.Terminal {
		t.Fatal("comparison resampled a live cache entry")
	}
}

func TestExplainKnownQuestionWithoutIdentityStaysUnknown(t *testing.T) {
	c := testCache(t, "")
	request := testRequest()
	request.PolicyKey = plugin.DNSPolicyKey{}
	ctx := plugin.WithDiagnosticDNSRequest(t.Context(), request.DNSRequest)
	if result := c.Explain(ctx, api.ExplainRequest{Kind: "dns"}); result.Complete || result.Steps[0].Reason != "cache_lookup_after_upstream_routing" {
		t.Fatalf("incomplete identity became a cache miss: %+v", result)
	}
}
