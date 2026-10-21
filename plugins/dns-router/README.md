# dae DNS router plugin

Optional advanced DNS policy/transports for dae's `component/plugin` API.
This module owns request/response routing, family preference, UDP/TCP, DoT,
DoH, DoQ and HTTP/3. It contains **no DNS response cache**.

## Build and test

This plugin shares dae's root Go module and release version. From the repository
root, copy `plugins.cfg.example` to `plugins.cfg` if needed and uncomment
`dns-router:github.com/daeuniverse/dae/plugins/dns-router`, then build:

```sh
make
```

Instances and middleware order are configured at runtime:

```text
plugins {
  dns-router {
    upstream { local: 'udp://192.0.2.53:53' secure: 'https://dns.example/dns-query' }
    routing {
      request { qname(suffix: lan) -> local fallback: secure }
      response { upstream(secure) -> accept fallback: accept }
    }
    # ipversion_prefer: 4
  }
}
```

Request predicates: `qname`, `qtype`, `dip`, `sip`, `interface`. Response predicates:
`qname`, `qtype`, `ip`, `upstream`. Interface-name rules track Linux link changes.
Upstream scheme may be `udp`, `tcp`, `tcp+udp`, `tls`, `https`, `quic`, `h3` or
`http3`. Upstream tags must be unique and cannot be `asis`, `accept`, `reject`,
`<OR>` or `<AND>`. HTTPS/H3 preserve custom paths (including escaped separators) and
query parameters, replacing only the `dns` parameter with the current query.
Defaults are request `asis`, response
`accept`; `reject` produces an empty response. Response rerouting is depth-bounded.

The router supplies `DNSResolver` for Surge encrypted/multiple-server assignments.
Endpoint hostnames use the daemon's internal resolver and its DNS TTL cache;
resolved addresses are refreshed on each exchange instead of pinned to the plugin.
Upstream sockets go through
dae's request-bound dial services, retaining client identity and applying target
routing, marks, accounting and route/policy lifetimes. `transport.Exchange` owns
one query and its sockets; connections are scoped to that exchange. Plain TCP
can retry an interrupted query on one new connection; it never retransmits on
a live stream.
Cancellation ends the exchange budget even if an outbound's `Close` is blocked.

Dial services receive both the selected IP:port and the configured endpoint
hostname. `domain()` rules match that hostname, not the client's DNS question;
connections still dial the selected IP. Auxiliary family probes have an independent
budget and TCP connection so probe cancellation cannot close the client's stream.
Address discovery and staggered attempts share dae's Happy Eyeballs scheduler:
IPv6 is preferred, slow DNS answers do not hold up the other family, and the first
successful DNS response wins. Remaining attempts are canceled and joined.
Short deadlines separately reserve time for UDP-to-TCP fallback on each address.

HTTPS/H3 subtract HTTP `Age` from effective DNS TTLs. Negative answers first
limit the SOA TTL to SOA MINIMUM, leaving the SOA record data unchanged; high-bit
TTLs are treated as zero before subtraction. Expired responses remain usable
for the current exchange but cannot acquire a fresh lifetime in the cache.

`asis` preserves invalid or uncorrelated wire without letting it drive response
policy or family suppression. Correlated header-only errors use the original
question for policy matching while keeping the accepted response wire unchanged.
Configuration preflight checks literal rules and upstream references before any
plugin setup; geodata contents and interface subscriptions are prepared afterwards.

Recommended ordering: `dns-cache`, `surge`, `dns-router`. An earlier explicit plain
server assignment bypasses general router policy. Unsupported operations and
transaction-signed messages pass to the next handler unchanged.

## Prometheus metrics

Enable dae's `global.metrics_port` and scrape `/metrics` on that localhost port.
Collectors register through `plugin.Services.Metrics`. All metrics have the
`dae_plugin_` prefix and `plugin_type` / `plugin_instance` labels:

| Local name | Type | Additional labels |
| --- | --- | --- |
| `dns_router_requests_total` | Counter | `entrypoint`, `result` |
| `dns_router_request_duration_seconds` | Histogram | `entrypoint` |
| `dns_router_upstream_attempts_total` | Counter | `upstream`, `transport`, `purpose`, `result` |
| `dns_router_upstream_attempt_duration_seconds` | Histogram | `upstream`, `transport`, `purpose` |
| `dns_router_policy_decisions_total` | Counter | `stage`, `action`, `purpose` |
| `dns_router_family_suppressions_total` | Counter | suppressed `family`: `ipv4`, `ipv6` |

`entrypoint` is `middleware` or `resolver`; full invocation duration includes
downstream work and joining auxiliary queries. Results are `success`, `bypass`,
`error`, `timeout`, `canceled`; success includes DNS error rcodes and policy
rejection. Attempts also distinguish `truncated`. `upstream` is a configured tag
or `explicit` for dynamically assigned servers. `transport` is `udp`, `tcp`,
`tls`, `https`, `quic` or `h3`; `purpose` is `query`, `probe` or `explicit`.

Each address/transport fallback is a separate `transport.Exchange` attempt,
including that call's internal TCP reconnect. Bootstrap is excluded from attempts
but its failures affect invocation results. Family probes do not add client
invocations; explicit-server races have one invocation with separate attempts,
including canceled losers. The standalone `Exchange` helper has no owning
instance and exports no metrics. Request policy actions are `asis`, `upstream`,
`reject`; response actions are `accept`, `reject`, `reroute`.

Counters and histograms reset on instance reconstruction. Failed candidate
preparation preserves active metrics; closing an instance removes its series.
Collection uses in-memory counters and does not depend on log level.

Run tests from the repository root. The default suite includes composition with
the cache and Surge plugins:

```sh
go test -race ./plugins/dns-router/...
```

License: AGPL-3.0-only. The policy and transport implementations were extracted
from dae; their original copyright notices are retained.
