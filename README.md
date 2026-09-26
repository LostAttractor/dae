# dae DNS router plugin

Optional advanced DNS policy/transports for dae's `component/plugin` API.
This module owns request/response routing, family preference, UDP/TCP, DoT,
DoH, DoQ and HTTP/3. It contains **no DNS response cache**.

## Local build

Keep this repository next to the compatible dae checkout. In dae:

```sh
go work init . # only when no workspace exists
go work use ../dae-plugin-dns-router
go work edit -replace=github.com/daeuniverse/dae@v0.0.0=.
```

Add `dns-router:github.com/daeuniverse/dae-plugin-dns-router` to `plugins.cfg`,
then `make`. The development `v0.0.0` dependency is a workspace placeholder.

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
`http3`. HTTPS/H3 preserve custom paths (including escaped separators) and
query parameters, replacing only the `dns` parameter with the current query.
Defaults are request `asis`, response
`accept`; `reject` produces an empty response. Response rerouting is depth-bounded.

The router supplies `DNSResolver` for Surge encrypted/multiple-server assignments.
Endpoint hostname bootstrap uses the system resolver. Upstream sockets go through
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
Short deadlines reserve time for `tcp+udp` fallback and for answer delivery.

`asis` preserves invalid or uncorrelated wire without letting it drive response
policy or family suppression. Correlated header-only errors use the original
question for policy matching while keeping the accepted response wire unchanged.
Configuration preflight checks literal rules and upstream references before any
plugin setup; geodata contents and interface subscriptions are prepared afterwards.

Recommended ordering: `dns-cache`, `surge`, `dns-router`. An earlier explicit plain
server assignment bypasses general router policy. Unsupported operations and
transaction-signed messages pass to the next handler unchanged.

Run `go test ../dae-plugin-dns-router/...` from the dae workspace. Optional
composition tests also use the sibling `dae-plugin-dns-cache` from the workspace:

```sh
go work use ../dae-plugin-dns-cache
go test -race -tags=dns_plugins_integration ../dae-plugin-dns-router
```

License: AGPL-3.0-only. The policy and transport implementations were extracted
from dae; their original copyright notices are retained.
