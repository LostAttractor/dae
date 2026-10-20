// SPDX-License-Identifier: AGPL-3.0-only

package dnscache

import "github.com/prometheus/client_golang/prometheus"

var (
	lookupsDesc     = prometheus.NewDesc("dns_cache_lookups_total", "Cache lookups by result. Unsupported query keys bypass lookup.", []string{"result"}, nil)
	entriesDesc     = prometheus.NewDesc("dns_cache_entries", "Currently retained cache entries, including entries awaiting expiration cleanup.", nil, nil)
	capacityDesc    = prometheus.NewDesc("dns_cache_capacity_entries", "Maximum retained cache entries.", nil, nil)
	memoryDesc      = prometheus.NewDesc("dns_cache_memory_bytes", "Conservatively accounted cache bytes, not process RSS.", nil, nil)
	memoryLimitDesc = prometheus.NewDesc("dns_cache_memory_limit_bytes", "Maximum accounted cache bytes.", nil, nil)
	evictionsDesc   = prometheus.NewDesc("dns_cache_evictions_total", "Entries removed by expiration or entry/byte capacity pressure; replacements are excluded.", []string{"reason"}, nil)
)

func (*Cache) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{lookupsDesc, entriesDesc, capacityDesc, memoryDesc, memoryLimitDesc, evictionsDesc} {
		ch <- desc
	}
}

// Snapshot the same authoritative state used by Report. Never hold the cache
// lock while sending to the collector channel.
func (c *Cache) Collect(ch chan<- prometheus.Metric) {
	s := c.store.Snapshot()
	ch <- prometheus.MustNewConstMetric(entriesDesc, prometheus.GaugeValue, float64(s.Entries))
	ch <- prometheus.MustNewConstMetric(capacityDesc, prometheus.GaugeValue, float64(s.Limit))
	ch <- prometheus.MustNewConstMetric(memoryDesc, prometheus.GaugeValue, float64(s.Bytes))
	ch <- prometheus.MustNewConstMetric(memoryLimitDesc, prometheus.GaugeValue, float64(s.MemoryLimit))
	ch <- prometheus.MustNewConstMetric(lookupsDesc, prometheus.CounterValue, float64(s.Hits), "hit")
	ch <- prometheus.MustNewConstMetric(lookupsDesc, prometheus.CounterValue, float64(s.Misses), "miss")
	ch <- prometheus.MustNewConstMetric(lookupsDesc, prometheus.CounterValue, float64(c.bypasses.Load()), "bypass")
	ch <- prometheus.MustNewConstMetric(evictionsDesc, prometheus.CounterValue, float64(s.Expired), "expired")
	ch <- prometheus.MustNewConstMetric(evictionsDesc, prometheus.CounterValue, float64(s.Evicted), "capacity")
}
