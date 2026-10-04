# Plugin Prometheus metrics

Enable the existing process metrics listener:

```text
global {
    metrics_port: 9091
}
```

Scrape `http://localhost:9091/metrics`. Core and active plugin metrics share this
listener. Plugin metrics carry `plugin_type` and `plugin_instance`; Prometheus's
own `instance` label continues to identify the scrape target. Plugins must be
compiled in and enabled to produce metrics.

Plugin collectors are prepared privately and published on activation. Failed
preparation preserves the current metrics. Reload reconstructs plugin instances,
resetting their counters and histogram observations. Closing an instance removes
its series from subsequent scrapes. `dae_plugin_instance_start_time_seconds`
records activation time. Changing or disabling the listener does not reset
running plugin state. Use `rate` or `increase` for counters across resets.

All metric names below have the **`dae_plugin_`** prefix. Histograms expose
`_bucket`, `_sum` and `_count`; durations use seconds and memory uses bytes.
Bounded counter vectors may appear when their first event occurs. Collection
uses in-memory state and does not depend on log level.

## DNS cache

| Name | Type | Additional labels / meaning |
| --- | --- | --- |
| `dns_cache_lookups_total` | Counter | `result`: `hit`, `miss`, `bypass` |
| `dns_cache_entries` | Gauge | Retained entries, including entries awaiting expiry cleanup |
| `dns_cache_capacity_entries` | Gauge | Entry limit |
| `dns_cache_memory_bytes` | Gauge | Conservative accounted bytes, not RSS |
| `dns_cache_memory_limit_bytes` | Gauge | Accounted byte limit |
| `dns_cache_evictions_total` | Counter | `reason`: `expired`, `capacity` |

Hits/misses and capacity state share the authoritative counters used by plugin
status. Unsupported query keys bypass lookup. An eligible query without an entry
is a miss even if storage is disabled by a fixed zero TTL or its response proves
uncacheable. Both lazy and worker expiration count as `expired`; entry and byte
pressure count as `capacity`. Replacing the same key is not an eviction.

## DNS router

| Name | Type | Additional labels |
| --- | --- | --- |
| `dns_router_requests_total` | Counter | `entrypoint`, `result` |
| `dns_router_request_duration_seconds` | Histogram | `entrypoint` |
| `dns_router_upstream_attempts_total` | Counter | `upstream`, `transport`, `purpose`, `result` |
| `dns_router_upstream_attempt_duration_seconds` | Histogram | `upstream`, `transport`, `purpose` |
| `dns_router_policy_decisions_total` | Counter | `stage`, `action`, `purpose` |
| `dns_router_family_suppressions_total` | Counter | `family`: `ipv4`, `ipv6` (the suppressed family) |

- `entrypoint`: `middleware` or cross-plugin explicit `resolver` invocation.
  Request duration includes downstream middleware and joined auxiliary work.
- Request `result`: `success`, `bypass`, `error`, `timeout`, `canceled`.
  Success means no returned error; DNS error rcodes and policy rejections count
  as success. Unsupported operations and earlier server assignments bypass
  router policy; a returned downstream error takes precedence over bypass.
- `upstream`: configured tag, or `explicit` for dynamically assigned servers.
- `transport`: `udp`, `tcp`, `tls`, `https`, `quic`, `h3`.
- `purpose`: `query`, `probe`, `explicit`. Family probes do not add client
  request invocations. Explicit resolver races share one invocation while each
  server's transport exchange is observed, including canceled losers.
- Attempt `result`: `success`, `truncated`, `error`, `timeout`, `canceled`.
  Address and UDP/TCP fallback generate separate attempts. One attempt is one
  `transport.Exchange` call, including any internal TCP reconnect. Endpoint
  hostname bootstrap is outside attempts; its failures still affect requests.
  The standalone `Exchange` helper has no owning plugin and exports no metrics.
- Policy `stage`: `request` or `response`; actions are `asis`, `upstream`,
  `reject` for requests and `accept`, `reject`, `reroute` for responses.
  Policy decisions use `query` or `probe` purpose.

## Surge

| Name | Type | Additional labels / meaning |
| --- | --- | --- |
| `surge_modules` | Gauge | Loaded module count |
| `surge_rules` | Gauge | `kind`: `script`, `url_rewrite`, `header_rewrite`, `body_rewrite`, `map_local`, `dns_host`, `destination`, `route` |
| `surge_scripts_total` | Counter | `phase`, `result` |
| `surge_script_duration_seconds` | Histogram | `phase`; runtime execution only |
| `surge_execution_wait_duration_seconds` | Histogram | `kind`; slot acquisition including failed waits |
| `surge_execution_slots_in_use` | Gauge | Occupied slots, including body processing and DNS script continuations |
| `surge_execution_slots_limit` | Gauge | Shared execution-slot capacity |
| `surge_rule_matches_total` | Counter | `kind`: `url_rewrite`, `header_rewrite`, `body_rewrite`, `map_local`, `dns_host` |
| `surge_processing_skips_total` | Counter | `stage`, `reason` |

Script `phase` is `http-request`, `http-response`, `dns`, `cron` or `generic`; slot-wait `kind`
also includes `body_rewrite`. Script results are `unchanged`, `success`,
`synthetic`, `abort`, `failed`, `skipped`. A matched script can be skipped before
execution. Runtime histograms exclude those skips, slot waits, body buffering
and result application. HTTP script failures followed by transparent forwarding
still count as failed scripts. DNS resolver failures after a valid script result
do not retroactively count as script failures.

Cron and generic use the same execution slots. A task that cannot acquire a slot
within its budget counts as skipped; overlapping timer ticks increment
`surge_processing_skips_total{stage="cron",reason="overlap"}` without starting
another invocation. Task success means runtime completion, not business success.

Rule matches count actual HTTP/DNS processing, with DNS alias hops counted
separately. A match need not modify the request or response. Skip stages are the
script phases, `body_rewrite` and `map_local`. Reasons use bounded categories
such as `body_limit`, `buffer_memory_limit`, `timeout`, `canceled`, `read_failed`,
`decode_failed` and `error`. Body preparation failures count once per rewrite
pass; individual failing body rules each count a skipped operation.

## PromQL examples

Cache hit ratio among eligible lookups:

```promql
sum by (instance, plugin_instance) (
  rate(dae_plugin_dns_cache_lookups_total{result="hit"}[5m])
)
/
sum by (instance, plugin_instance) (
  rate(dae_plugin_dns_cache_lookups_total{result=~"hit|miss"}[5m])
)
```

P95 main-query upstream attempt latency:

```promql
histogram_quantile(0.95,
  sum by (instance, plugin_instance, upstream, transport, le) (
    rate(dae_plugin_dns_router_upstream_attempt_duration_seconds_bucket{purpose="query"}[5m])
  )
)
```

HTTP/DNS/cron/generic script failure rate, including HTTP failures followed by forwarding:

```promql
sum by (instance, plugin_instance, phase) (
  rate(dae_plugin_surge_scripts_total{result="failed"}[5m])
)
```

See the [plugin registration API](../../../component/plugin/README.md#prometheus-metrics)
to instrument another plugin.
