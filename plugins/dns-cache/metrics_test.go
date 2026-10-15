// SPDX-License-Identifier: AGPL-3.0-only

package dnscache

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/prometheus/client_golang/prometheus"
)

func cacheMetric(t *testing.T, registry *prometheus.Registry, name, label string) float64 {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			if label != "" && (len(metric.Label) != 1 || metric.Label[0].GetValue() != label) {
				continue
			}
			if metric.Counter != nil {
				return metric.GetCounter().GetValue()
			}
			return metric.GetGauge().GetValue()
		}
	}
	t.Fatalf("missing metric %s %s", name, label)
	return 0
}

func TestCacheMetricsTrackAuthoritativeState(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	sections, err := config_parser.Parse("cache { size: 1 }")
	if err != nil {
		t.Fatal(err)
	}
	factory, err := Configure(plugin.Spec{Config: sections[0]})
	if err != nil {
		t.Fatal(err)
	}
	p, err := factory(t.Context(), plugin.Services{Metrics: registry})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Cache)
	request := testRequest()
	handler := c.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) { return nil, nil })
	_, _ = handler(t.Context(), request) // miss
	c.ObserveDNS(t.Context(), request, testResponse(request))
	_, _ = handler(t.Context(), request)                      // hit
	c.ObserveDNS(t.Context(), request, testResponse(request)) // replacement, not eviction
	other := request.Copy()
	other.ContextKey = "other"
	c.ObserveDNS(t.Context(), other, testResponse(other)) // capacity eviction
	c.expire(time.Now().Add(time.Minute))                 // worker expiration
	c.ObserveDNS(t.Context(), request, testResponse(request))
	c.mu.Lock()
	for _, elem := range c.entries {
		elem.Value.(*entry).expires = time.Now().Add(-time.Second)
	}
	c.mu.Unlock()
	_, _ = handler(t.Context(), request) // lazy expiration and miss
	invalid := request.Copy()
	invalid.DNSPacket = plugin.DNSPacket{}
	_, _ = handler(t.Context(), invalid) // bypass
	for _, test := range []struct {
		name, label string
		want        float64
	}{
		{"dns_cache_lookups_total", "hit", 1}, {"dns_cache_lookups_total", "miss", 2}, {"dns_cache_lookups_total", "bypass", 1},
		{"dns_cache_evictions_total", "capacity", 1}, {"dns_cache_evictions_total", "expired", 2},
		{"dns_cache_entries", "", 0}, {"dns_cache_capacity_entries", "", 1}, {"dns_cache_memory_bytes", "", 0}, {"dns_cache_memory_limit_bytes", "", 67108864},
	} {
		if got := cacheMetric(t, registry, test.name, test.label); got != test.want {
			t.Errorf("%s %s = %v, want %v", test.name, test.label, got, test.want)
		}
	}
	status := c.Report().(map[string]any)
	if status["hits"] != uint64(1) || status["misses"] != uint64(2) {
		t.Fatalf("status diverged: %v", status)
	}
}

func TestCacheMetricsConcurrentCollection(t *testing.T) {
	c := testCache(t, "")
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(c)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			request := testRequest()
			handler := c.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) { return nil, nil })
			for range 50 {
				c.ObserveDNS(t.Context(), request, testResponse(request))
				_, _ = handler(t.Context(), request)
				if _, err := registry.Gather(); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	if got := cacheMetric(t, registry, "dns_cache_lookups_total", "hit"); got != 200 {
		t.Fatalf("hits = %v", got)
	}
}
