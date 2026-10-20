# dae DNS cache plugin

Independent bounded, memory-only response cache for dae's `component/plugin` API.
It caches raw upstream responses after server selection and routing admission,
before response policies. Request policies and response rewrites run on every
request, including cache hits. Local plugin answers do not enter this cache.

Query identity, negative TTLs, TTL aging, ordinary OPT reconstruction and bounded
LRU storage use the shared `pkg/dnscache` library. The same storage implementation
serves dae's internal resolver and Surge DNS script address results. This plugin
owns EDNS option eligibility, upstream/policy namespaces, response metadata,
fixed TTL settings and diagnostics. The three entry sources retain separate
instances and budgets; internal resolution never enters the client plugin chain.

## Build and test

This plugin shares dae's root Go module and release version. From the repository
root, copy `plugins.cfg.example` to `plugins.cfg` if needed and uncomment
`dns-cache:github.com/daeuniverse/dae/plugins/dns-cache`, then build:

```sh
make
```

Instances and middleware order are configured at runtime:

```text
plugins {
  dns-cache {
    size: 32768
    memory_limit: 67108864
    fixed_domain_ttl { ddns.example.org: 0 }
  }
  # surge { ... }
  # dns-router { ... }
}
```

Its position in the plugin list does not affect upstream caching. `size` limits entry
count; `memory_limit` is a conservative accounted byte budget, not an RSS limit.
LRU eviction and periodic expiration bound retained state. Cache keys include
the routing generation, plugin chain, selected outbound/mark, actual endpoint
(including encrypted protocol and HTTP path/query), destination IP, TCP/UDP and
query flags. Client IPs and source ports are not keys. Hits preserve
original receipt time, restore the caller's ID/question and age RR TTLs. Negative
responses require an SOA and use its minimum TTL. Truncated, zero-TTL, signed and
transaction-specific responses are not replayed. `fixed_domain_ttl: 0` disables
storage for that name; fixed TTL never changes signed answers.

The cache stores ordinary answers without OPT control records and reconstructs
OPT from the current query on every hit. Queries or replies with EDNS options,
including ECS, NSID, Padding and Cookies, pass through without caching or fixed
TTL rewriting. Their option-specific response semantics are not implemented;
exact query matching alone does not make them replayable. The internal resolver
cache makes its own eligibility decision and uses the same ordinary OPT helper.

High-bit TTLs are treated as zero and are not cached (RFC 2181). Negative replay
ages the SOA TTL from the negative caching lifetime (RFC 2308), so clients cannot
restart a full SOA MINIMUM interval on each hit. Fixed TTL changes require strict
wire parsing and request correlation; malformed or unrelated packets pass through
unchanged and cannot be repaired into cacheable answers.

Cache hits retain their original receipt time and are marked as replays. On
successful client delivery, dae independently refreshes DomainRegistry retention
using the delivered TTL and `global.dns_retention_window`; this does not renew the
cached response's own TTL or receipt time.
TTL aging uses the response's `ReceivedAt`; the cache supplies the receipt time
when the transport omits it. A validated upstream response can be cached even
if response policy rejects it or client delivery fails. Only delivered answers
contribute to DomainRegistry.
Unchanged instances retain their cache and counters across reload. The host's
policy namespace separates answers when the ordered plugin instances or core
routing generation change;
draining hosts can still use their old answers. Old entries remain subject to
the same expiration and capacity limits. Domain evidence persists independently.
`dae plugins dns-cache status` reports entry count, byte usage, hits and misses.
Static diagnostics evaluate middleware and route policy before peeking at the
cache. A known single endpoint can report a raw cache hit even when its outbound
has no available node. Missing query/routing data, multiple candidates and
runtime-dependent policies remain uncertain. Peeks do not change counters or LRU
order, and a raw hit never bypasses response policies.

## Prometheus metrics

Enable dae's `global.metrics_port` and scrape `/metrics` on that localhost port.
This plugin registers through `plugin.Services.Metrics`. All metrics carry the
host's `plugin_type` and `plugin_instance` labels and the `dae_plugin_` prefix:

| Local name | Type | Meaning |
| --- | --- | --- |
| `dns_cache_lookups_total{result}` | Counter | `hit`, `miss`, `bypass` |
| `dns_cache_entries` | Gauge | Retained entries |
| `dns_cache_capacity_entries` | Gauge | Entry limit |
| `dns_cache_memory_bytes` | Gauge | Accounted bytes, not RSS |
| `dns_cache_memory_limit_bytes` | Gauge | Accounted byte limit |
| `dns_cache_evictions_total{reason}` | Counter | `expired`, `capacity` |

Lookup and capacity metrics read the same state as status. Unsupported query
keys bypass lookup; eligible keys without an entry are misses even when the
response cannot be stored. Expiration includes lazy and worker cleanup, capacity
includes entry and byte pressure, and replacing a key is not an eviction.
Entries awaiting expiration cleanup remain included in the gauges.
Counters reset when the cache instance is reconstructed. Failed candidate preparation preserves
the active instance's metrics; closing an instance removes its series.

Run `go test ./plugins/dns-cache/...` from the repository root.

License: AGPL-3.0-only.
