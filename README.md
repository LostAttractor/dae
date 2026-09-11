# dae DNS cache plugin

Independent bounded, memory-only response cache for dae's `component/plugin` API.
It has no upstream selection or resolver transport. It caches final responses
from both relayed servers and local DNS plugins, including Surge `[Host]`.

## Local build

Keep this repository beside a compatible dae checkout. In dae:

```sh
go work init . # only when no workspace exists
go work use ../dae-plugin-dns-cache
go work edit -replace=github.com/daeuniverse/dae@v0.0.0=.
```

Add `dns-cache:github.com/daeuniverse/dae-plugin-dns-cache` to `plugins.cfg`, then
`make`. The development `v0.0.0` dependency is a workspace placeholder.

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

Place cache first to replay final local and upstream answers. `size` limits entry
count; `memory_limit` is a conservative accounted byte budget, not an RSS limit.
LRU eviction and periodic expiration bound retained state. Cache keys include
client/policy context, destination, TCP/UDP and query flags/EDNS data. Hits preserve
original receipt time, restore the caller's ID/question and age RR TTLs. Negative
responses require an SOA and use its minimum TTL. Truncated, zero-TTL, signed and
transaction-specific responses are not replayed. `fixed_domain_ttl: 0` disables
storage for that name; fixed TTL never changes signed answers.

High-bit TTLs are treated as zero and are not cached (RFC 2181). Negative replay
ages the SOA TTL from the negative caching lifetime (RFC 2308), so clients cannot
restart a full SOA MINIMUM interval on each hit. Fixed TTL changes require strict
wire parsing and request correlation; malformed or unrelated packets pass through
unchanged and cannot be repaired into cacheable answers.

Cache hits retain their original receipt time and are marked as replays. On
successful client delivery, dae independently refreshes DomainRegistry retention
using the delivered TTL and `global.dns_retention_window`; this does not renew the
cached response's own TTL or receipt time.
Reload creates a fresh response cache; domain evidence persists independently.
`dae plugins dns-cache status` reports entry count, byte usage, hits and misses.

Run `go test ../dae-plugin-dns-cache/...` from the dae workspace.

License: AGPL-3.0-only.
