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
preparation preserves the current metrics. Reload preserves unchanged instances
and their statistics; rebuilt instances reset counters and histogram observations.
Closing an instance removes
its series from subsequent scrapes. `dae_plugin_instance_start_time_seconds`
records activation time. Changing or disabling the listener does not reset
running plugin state. Use `rate` or `increase` for counters across resets.

## Core traffic statistics

`dae_process_connections_total{network}` and `dae_process_traffic_bytes_total{network,direction}`
retain process-lifetime totals from the same source as global status. Retiring
detailed counters does not reduce these totals.
`dae_group_connections_total{outbound,network}` and `dae_group_traffic_bytes_total{outbound,network,direction}`
accumulate by outbound group name for the process lifetime, including retired
paths, and share the totals shown by status. Replacing nodes does not reduce them.
Removing a group hides its series; re-adding it resumes its previous totals,
including connections that drained while the group was absent.

Path-level connection, traffic, dial-duration and error series retain nodes in the
current configuration. Removed paths are retired once their connections end and
their last minute of history expires. Returning paths start new detailed counters;
use `rate` or `increase` for historical trends. Device identities are not exported
as Prometheus labels. Listener changes prepare the required sockets before
publication; a binding failure rejects the configuration and preserves the running
service.

## UDP packet drops

`dae_udp_packet_drops_total{direction,reason}` is a core metric; its name has
no `dae_plugin_` prefix. It is counted by the layer that drops a datagram, for
the process lifetime; reload does not reset it. Every combination is exported
as 0 before its first drop. `direction` is `upload` (LAN to internet) or
`download`. Callers told of a drop do not count it again. Each combination
logs at most one warning a minute, except `route_missing`, `filtered` and
`closed_stream`, which occur in normal operation and are only counted.

| `reason` | `direction` | Meaning |
| --- | --- | --- |
| `socket_overflow` | `upload` | The tproxy UDP socket's receive queue overflowed; reported with the next queued datagram |
| `truncated` | `upload` | Truncated datagram |
| `route_missing` | `upload` | The kernel routing record is gone, or the endpoint was removed while the datagram queued |
| `source_queue_full`, `task_limit`, `source_limit` | `upload` | Per-source queue, global task or backlogged source limit reached |
| `packet_memory_limit` | both | Shared datagram memory (8 MiB) exhausted |
| `expired` | `upload` | Not sent by its deadline, including queueing, setup, sniffing that timed out and blocked writes; datagrams canceled by a configuration change are not counted |
| `setup_capacity` | `upload` | Shared slow-operation capacity exhausted while initializing an association or opening a destination socket |
| `setup_failed` | `upload` | Opening an association failed (routing, sniffing, MITM or the outbound dial), counting every datagram buffered for its sniffing; also datagrams left unsent when replaying them fails |
| `slow_write_capacity` | `upload` | Shared slow-operation capacity exhausted before a blocking UDP write |
| `endpoint_limit` | `upload` | UDP source endpoint limit reached |
| `packet_resource_limit` | `upload` | No UDP association or socket could be opened: the process-wide packet resource limit or a source's socket limit is reached |
| `dns_admission` | `upload` | Concurrent DNS query limit reached |
| `mitm_bridge_full` | both | MITM HTTP/3 bridge queue full |
| `filtered` | both | A request-routed MITM source sent to another destination; a rewritten destination socket received from another source |
| `flow_queue_full` | `upload` | A smux stream queued more than 64 KiB of datagrams; its oldest droppable datagram is evicted |
| `carrier_queue_full` | `upload` | A smux session exceeded 256 KiB of datagrams and evicted the oldest droppable datagram of its fattest stream, or a QUIC DATAGRAM send queue was full |
| `codel` | `upload` | Dropped from the head of a smux stream by CoDel: its datagrams waited over 5 ms for over 100 ms, beyond its rate- and active-flow-based delay estimate |
| `socket_full` | `upload` | A UDP socket's send buffer was full: direct, Shadowsocks, SSR, SOCKS5 and juicity UDP drop the datagram instead of waiting |
| `too_large` | `upload` | QUIC datagram larger than any packet it can be sent in |
| `transport_receive_full` | `download` | hysteria2, TUIC or QUIC datagram receive queue, or fragment reassembly table, full |
| `carrier_queue_full` | `download` | Port-hopping receive queue full; it holds the QUIC packets carrying hysteria2, which QUIC may retransmit |
| `unauthenticated` | `download` | juicity UDP datagram that does not authenticate; its socket is unconnected, so anyone may send to it |
| `closed_stream` | `download` | Reply for an association dae has closed or is closing. Data smux receives for a stream dae has closed is not counted: the session no longer knows whether the stream carried datagrams |
| `reply_queue_full` | `download` | Pushed reply backlog full |
| `reply_socket_full` | `download` | The client's reply socket's send buffer was full: the reply is dropped instead of waiting |
| `reply_send_failed` | `download` | Sending a reply to the client failed, for example its reply socket could not be created; the association goes on |

Ingress datagrams keep their original deadline across control-plane handoff,
sniffing replay and the MITM bridge. An expired packet is discarded before
forwarding or bridge delivery, without refreshing its deadline at each queue.
This does not impose a delivery deadline on transport-internal or kernel queues.

The shared 8 MiB packet-memory budget covers ingress, pending sniffing packets,
MITM bridge queues, pushed reply backlogs and smux send queues across control-plane generations.
Moving an owned packet transfers its allocation and reservation without another
payload copy. Admitted smux requests are protected from eviction, but admission
never exceeds this budget. Private parser reassembly, DNS request copies, other transport-internal
buffers, idle pool storage and kernel buffers are separate.

TUIC native UDP and Hysteria2 use nonblocking QUIC DATAGRAM admission. A full
carrier queue drops the application datagram instead of retaining a shared UDP
worker. `TryWriteTo` reports `ErrPacketDropped`; ordinary `WriteTo` reports it as
written, like a lossy link. If a fragmented datagram encounters a full queue,
its remaining fragments are not queued and the protocol counts one
`carrier_queue_full` drop. Previously accepted fragments cannot be retracted.
TUIC QUIC relay mode and other reliable-stream transports retain backpressure.

Association initialization, destination socket creation and blocking UDP writes
share 32 slow-operation permits per control plane, leaving capacity in the
128-worker pool for unrelated ready sources. Nested setup and writes on one
worker use one permit. Admission never waits or starts another packet worker;
a refused datagram is counted once without closing the existing association.
Nonblocking sends do not consume these permits. Waiting for another sniffing
packet releases the worker and its permit.

`dae_udp_queue_delay_seconds{transport}` is the histogram of how long the
datagrams a transport sent had waited in its send queue, for the process
lifetime, with buckets from 1 ms to 1 s. `transport` is `smux`.
`dae_mux_lane_placements_total{lane,result}` counts the user streams a
multiplexed node placed by `lane` (`interactive`, `bulk_datagram`, `stream`)
and `result`: `own` on a session of its lane, `spare` on the spare session,
`fallback` on another lane's session.

## Plugin metric names

Plugin metric names below omit the **`dae_plugin_`** prefix. Histograms expose
`_bucket`, `_sum` and `_count`; durations use seconds and memory uses bytes.
Bounded counter vectors may appear when their first event occurs. Collection
uses in-memory state and does not depend on log level.

## DNS cache

| Name | Type | Additional labels / meaning |
| --- | --- | --- |
| `dns_cache_lookups_total` | Counter | `result`: `hit`, `miss`, `bypass`; once per upstream query |
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
| `surge_runtime_info` | Gauge | `backend`: `quickjs` or `nodejs`; value 1 |
| `surge_nodejs_workers` | Gauge | `state`: `active`, `idle` |
| `surge_nodejs_worker_limit` | Gauge | Maximum workers for this instance |
| `surge_nodejs_worker_starts_total` | Counter | Successfully spawned application workers |
| `surge_nodejs_worker_start_failures_total` | Counter | Failed application worker spawns |
| `surge_nodejs_worker_reuses_total` | Counter | Leases acquired from idle workers |
| `surge_nodejs_worker_retirements_total` | Counter | `reason`: `idle`, `failed` (including cancellation) |
| `surge_nodejs_cgroup_memory_bytes` | Gauge | Cached pool memory.current; includes kernel charges and differs from RSS/PSS |
| `surge_nodejs_cgroup_memory_peak_bytes` | Gauge | Kernel pool memory.peak |
| `surge_nodejs_cgroup_memory_limit_bytes` | Gauge | Pool memory.max |
| `surge_nodejs_cgroup_oom_kills_total` | Counter | Kernel memory.events oom_kill for the pool and its workers; includes ancestor/host OOM victims, not proof of a worker-limit violation or the worker retirement count |
| `surge_nodejs_cgroup_sample_timestamp_seconds` | Gauge | Last successful cgroup sample, or 0 when unavailable |
| `surge_nodejs_idle_timeout_seconds` | Gauge | Excess idle worker timeout |
| `surge_nodejs_rss_bytes` | Gauge | Sum of sampled worker RSS; shared pages can be counted more than once |
| `surge_nodejs_pss_bytes` | Gauge | Sum of sampled worker PSS, proportionally accounting for shared pages |
| `surge_nodejs_memory_sampled_workers` | Gauge | Current workers included in the memory sums |
| `surge_nodejs_memory_sample_timestamp_seconds` | Gauge | Oldest included memory sample, or 0 when none |

Node.js metrics exist only for the Node.js build. One active worker belongs to
one invocation, including while it waits for host HTTP or timers. Instances with
scripts prewarm one worker during preparation, counted as an application start;
additional workers start on demand. Excess workers idle for 60 seconds are
reclaimed by maintenance every 5 seconds, keeping the most recently returned
idle worker warm. Active leases are never reclaimed by idle maintenance.
Preflight probes use disposable pools and do not count as application starts or
retirements. Instance shutdown does not count as a retirement. Instances without
scripts create no runtime workers.

Memory is sampled from Linux `smaps_rollup` in the background every 5 seconds;
scrapes and status queries read cached values. Check sampled-worker coverage
against active plus idle workers, and use the sample timestamp to assess age.
New or unreadable workers are excluded from the sums. Zero samples does not
mean live workers use zero memory. RSS/PSS include more than the V8 old-generation
heap limited by `memory_limit`.

`dae plugins surge status` and `dae plugins status --verbose` show the pool
counters, memory sums, coverage and age from the same underlying statistics.
`dae status` and `dae status --recent` show core daemon state without expanding
plugin runtime reports. `/api/status` and `dae status --json` retain these values
in each Surge report's `runtimes` field; plugin JSON commands also include them.
QuickJS reports its backend without Node.js process metrics.

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
