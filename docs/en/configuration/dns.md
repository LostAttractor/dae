# DNS relay, evidence retention and plugins

Core transparently relays captured **TCP/UDP destination port 53** and observes
successfully delivered DNS replies. `DomainRegistry` supplies evidence for sniff
verification, domain routing and domain-based MITM/DNAT capture. Complete response
caching and advanced resolution belong to optional plugins.

## Transparent relay and system resolution

DNS follows ordinary destination routing. Core does not select upstreams, retry,
switch transports or edit upstream TTLs, AD, EDNS or TC. Malformed frames remain
transparent but cannot publish evidence. Explicit `block` still blocks DNS;
`must` skips automatic DNS handling. Exact TCP management API bypasses remain
kernel direct.

TCP uses a 30-second idle timeout refreshed by both requests and delivered
responses, including AXFR/IXFR continuation frames. Upstream closure drains
received responses before closing the client connection. A uniquely correlated
header-only DNS error completes its exchange without publishing evidence.
UDP plugin admission and local replies obey device route epochs and cancellation,
including cache hits under `route_change_behavior: close`.

Native DNAT runs once before plugins. An original port-53 flow remains DNS even
after changing its destination port:

```dae
rules {
    dip(192.0.2.53) && dport(53) -> dnat('198.51.100.53:1053')
}
```

Replies preserve the original server address/port. Plugin-selected servers receive
fresh target routing with the original client, interface, process and profile.

dae's internal lookups use Go's standard library. With `global.dns_resolver`
omitted, `/etc/resolv.conf` and `/etc/hosts` supply the system configuration; no
DNS plugin is required. Marked Go resolver sockets avoid recapture. libc-only
NSS modules and macOS split-DNS are not emulated.

### Internal DNS server override

```dae
global {
    dns_resolver: '1.1.1.1:53'
}
routing {
    dip(1.1.1.1) && dport(53) -> proxy
    fallback: direct
}
```

Replace `proxy` with an existing node or group. Accepts an IPv4/IPv6 literal
with an optional port (default 53), for example `1.1.1.1`,
`2001:4860:4860::8888` or `[2001:4860:4860::8888]:53`. Go handles UDP queries and
TCP retries after truncation; address lookups still consult `/etc/hosts`.

- **Startup preparation:** contact the configured server directly for
  subscriptions, checks and plugin preparation.
- **After listener readiness:** select each internal DNS transport through the
  current destination, flow and routing rules. Match the DNS server's IP/port,
  actual UDP/TCP transport and daemon process identity, with no client/interface.
  Proxy selection, mark, DNAT, block and configured connectivity fallback apply.
  The question name is not the routing hostname of this transport.
- **Proxy bootstrap:** physical proxy-chain connections and QUIC server names
  use a separate direct resolver, also pointed at the configured server. This
  breaks the DNS/proxy establishment dependency cycle. The server must be
  directly reachable for bootstrap.
- **Reload:** candidate preparation uses the current resolver policy; rejection
  leaves it active. Commit selects the new server in direct bootstrap mode;
  listener readiness enables the new routing callback. An in-flight dial keeps
  its original policy snapshot.

This is an internal server override, applied from the first lookup. Routed
failures do not add a system-DNS fallback or bypass block. An omitted setting
keeps standard-library system resolution. The setting does not change client
DNS servers, enter the client DNS plugin chain or publish internal answers to
the client-evidence Registry. Use DNS plugins for client query policy.

## Sliding retention window

DNS TTL expiry cannot prove that an application has stopped using an address.
Applications may ignore TTLs or retain resolved IPs outside their DNS cache.

```dae
global {
    dns_retention_window: 168h
}
```

The default is seven days; the duration must be positive. This is a **retention
policy assumption**, not a measured client cache lifetime or a maximum record age.
Longer TTLs win, and subsequent traffic can keep extending retention.

Each `(domain, IP)` registration stores an absolute `retain_until`. The DNS type
is checked when accepting evidence; it is not stored because the normalized IP
determines its address family. `Verify.Registered` still requires evidence in the
destination's address family, while `Verify.Paired` requires the exact pair. With
window `W`:

| Observation | Update |
| --- | --- |
| Valid DNS reply successfully delivered | `max(retain_until, delivered_at + max(ttl, W))` |
| Actual connection/traffic activity | `max(retain_until, observed_at + W)` |
| GC | Delete due pairs, recompute affected IPs, and adjust kernel residency |

Use the final delivered TTL; a CNAME alias uses the shortest TTL along its path
to the address RRset. A TTL with its high bit set means zero (RFC 2181), only for
the retention calculation; forwarded bytes are unchanged. Updates never shorten an existing deadline. GC runs on
updates and on a one-minute check, so quiet entries may be collected up to one
sweep later. The Registry tracks the earliest possible expiry and skips full
collection scans before that time. The first implementation has **no userspace entry or memory limit**.
Kernel capacity eviction leaves userspace evidence intact; time GC removes both
verification evidence and kernel contributions. `Verify` itself never refreshes
retention. Once collected, a pair needs a new valid DNS observation to return.

`retain_until` is a collection deadline, not a new DNS trust-validity deadline.
Activity arriving before actual collection can still refresh an existing pair.
Evidence is shared across clients; any client's activity can refresh that pair.

### DNS evidence

Only correlated, successful, complete ordinary IN A/AAAA replies contribute.
Validate ID, opcode and questions, follow bounded reachable CNAME chains, and
reject cycles, unrelated answers, errors, TC responses and malformed frames.

Upstream, local and **cached replies all refresh retention after delivery**:
the client has just received an answer it may retain anew. This does not change
cache TTL aging or the original `ReceivedAt`. Failed delivery publishes nothing.

RRSIG time checks still apply when accepting a reply; dae does not authenticate
DNSSEC. Once accepted, historical retention is independent of signature expiry.
Keeping a mapping does not claim its signature is still valid.

### Traffic refresh

- With a sniffed domain, refresh only the existing exact domain/original-IP pair.
- Without a sniffed domain, refresh every existing pair for that IP.
- An unknown sniffed pair creates no evidence and does not refresh other names.
- Use the client's original destination and name, not a plugin-rewritten target
  or dae's own background hostname resolution.

Observe TCP/UDP ingress and continued userspace I/O, including MITM. Captured TCP
connections subsequently using sockmap/splice reuse existing byte-counter growth
for refresh, with approximately one-second polling granularity. Idle connections
do not refresh. Observed client attempts count even if upstream dialing fails.

Connection entry, the first activity for a new UDP destination, and DNS evidence
registration are synchronous. The initial route decision still precedes any
capacity promotion caused by that first activity. Continued I/O is coalesced by
`(original IP, canonical domain or empty string)`, retaining the latest
`observed_at` for each key in a single queue. Enqueue briefly holds the queue
lock. The existing Registry worker attempts to apply a batch
every second. Processing time never replaces observation time; an empty batch
cannot renew an idle connection. Splice counter polling is followed by this
batch application too.

GC, DNS registration and snapshot copying first apply already queued activity.
The consumer swaps two reusable buffers under the queue lock, establishing one
observation boundary, then releases the lock. Later enqueues belong to the next
batch. Pair updates and kernel writes run without the queue lock.
Earlier unknown-pair activity is therefore consumed before subsequent DNS
registration, rather than applied to newly created evidence. Status and
verification read applied evidence without consuming the queue. Continued-I/O
deadline changes and capacity promotions become visible when a batch is applied.
Synchronous operations may apply it earlier, while a busy worker can delay it
beyond the next one-second check.

Surviving connections use a shared activity handle redirected on reload. Closing
the old Registry atomically detaches its final activity batch, applies the old
window and saves it. Handoff activity accepted after retirement uses the new
window and is applied before the successor's GC. Taking the maximum deadline is
order-independent, so replay needs no sorting. Reload preserves existing
deadlines and rebuilds bitmaps with current rules. Ordinary shutdown rejects
further activity.

## Kernel AND/OR projection

Userspace keeps one evidence object per domain–IP pair. The domain and IP indexes
reference the same pair, with one `retain_until`. Each domain owns one bitmap;
each IP node stores its associated domains and their aggregate. Named activity
looks up the exact pair, while IP-only activity visits only that IP's domains. Kernel
capacity is counted in **IPs**, with two bitmaps published together in one atomic
map value:

```text
bump     = OR(all retained pairs' bitmaps for this IP)
routing  = AND(all retained pairs' bitmaps for this IP)
priority = max(retain_until of pairs with nonzero bitmaps)
```

Bits represent domain predicates in routing, MITM, DNAT, `bump` and `must` controls.
An AND hit is definite for all registered names; an OR-only hit is ambiguous and
the complete rule determines whether userspace hostname inspection is needed.

**Zero-bit pairs must still participate in AND.** If a targeted name and an
unrelated name share a CDN IP, their bits are 1 and 0: OR=1, AND=0. Discarding the
unrelated pair would turn ambiguity into an incorrect definite match.

IPs whose whole OR bitmap is zero need no kernel slot. Rank other complete IP
states by descending `priority`, breaking ties by IP, and keep as many as the
actual map capacity permits. Zero-bit pairs affect AND but not priority. Updates,
activity, GC and reload reconsider omitted candidates and fill free slots. Delete
evicted entries before inserting replacements into the non-LRU map.

Pair additions and deletions recompute only the affected IPs, reusing their bitmap
buffers. Query names, aliases and addresses from one DNS response are registered
as a batch, publishing each affected IP's complete aggregate once. Deadline
extensions update only the pair deadline and IP priority. Raising a resident
IP's priority leaves the resident set unchanged and needs no bitmap write.

Capacity selection reads the cached IP aggregates. When all possible new
candidates fit, only changed IPs need processing; capacity competition triggers
reselection, with sorting only when candidates outnumber slots. Retained index
and aggregate memory grows with the evidence, and capacity selection cost grows
with the IP count. Queued activity uses space per distinct observation key in a
batch, and reusable maps retain their allocated capacity. Applying observations
advances the monotonic watermark and checks for due collection. See
the [DNS architecture](../../zh/design/project-structure.md#dns) for component
responsibilities and lifecycle.

### CDN tradeoff and observation gaps

Refreshing every pair on unnamed traffic is conservative: traffic to an active
CDN IP can indefinitely retain obsolete names, including their capture ambiguity.
The policy prioritizes avoiding missing mappings and cannot simultaneously
guarantee prompt removal of all obsolete CDN names.

**Uncaptured kernel-direct traffic does not refresh retention in this version.**
Domain routing and domain-based MITM/DNAT capture need resident evidence. Missing,
collected or capacity-omitted IPs follow ordinary routing semantics. Retained
userspace evidence alone cannot make an uncaptured connection undergo sniffing.
Capture is never broadened to all traffic to compensate. SSH, unrelated HTTPS
and ordinary direct connections without evidence remain in the kernel.
Encrypted DNS not handled by a plugin cannot supply passive core observations.

## Persistence and diagnostics

Dirty state is saved every 60 seconds and once on clean close to
`$DAE_LOCATION_CACHE/domain-registry.json.gz` (default
`/var/lib/dae/domain-registry.json.gz`), mode 0600. The file contains **gzip-compressed
JSON**. Writes stream JSON through gzip at its fastest compression level to a
temporary file, finish the compressed stream, then use file fsync, atomic rename
and directory fsync. Save failures are logged, including the final save; they do
not prevent safe retirement or in-memory registry adoption during reload. View
it with:

```sh
zcat /var/lib/dae/domain-registry.json.gz | jq .
```

The JSON groups addresses by domain: `domain → IP → retain_until`. Each domain
is stored once, while each IP keeps its own absolute deadline, including separate
IPv4 and IPv6 deadlines. An empty snapshot is `{}`.

```json
{
  "example.com.": {
    "192.0.2.1": "2026-09-19T00:00:00Z",
    "2001:db8::1": "2026-09-20T00:00:00Z"
  }
}
```

There is no version envelope or migration layer. Duplicate domain keys and
duplicate IPs within a domain are rejected. The whole stream, including the gzip
checksum and trailer, is validated before any evidence is published.

Cold restore loads the validated records directly, preserves their deadlines,
collects expired records and recomputes current-rule bitmaps before interface
attachment. There is no snapshot entry/size cap; format, address/name, duplicate
and trailing-data checks remain.

Status schema **10** reports:

- `domain-registry`: `used` counts domain-IP pairs; `limit: 0` means unbounded.
  `breakdown.domains` counts names; `breakdown.ips` counts distinct addresses across
  all names. `breakdown.ipv4` and `ipv6` count distinct addresses by family and sum
  to `ips`. A shared IP counts once even when it belongs to several pairs.
- `breakdown.gc` counts time-collected pairs (carried across reload, reset on cold
  startup). Status reads count currently retained records without running GC or
  refreshing deadlines.
- `domain-kernel`: `used` counts resident IPs, `limit` is capacity, and `candidates`
  counts IPs with nonzero domain-rule bitmaps; `candidates - used` counts IPs omitted
  by capacity. Registry IP totals also include zero-bitmap addresses that need no
  kernel entry, so they differ from candidate counts.

The CLI shows `USED (IPs)`, `CANDIDATES` and `OMITTED` for the kernel table, followed
by `PAIRS / DOMAINS / IPs / IPv4 / IPv6 / GC (PAIRS)` in the
`domain-registry (unlimited)` detail table.

Startup logs state the window and observation coverage. Capacity exclusions emit
rate-limited summaries. Unobserved direct flows cannot receive per-flow omission
diagnostics.

## Build-time capacities

```sh
make MAX_DOMAIN_ROUTING_NUM=131072 MAX_UDP_ROUTING_CACHE_NUM=131072
```

Userspace reads the actual map capacity. See [BPF map capacities](../user-guide/build-by-yourself.md#bpf-map-capacities)
for the supported rule-scale and traffic-state parameters. Rebuild and restart to create maps with new
sizes; configuration reload does not resize them. `MAX_MATCH_SET_LEN` changes
bitmap width and therefore per-IP memory cost.

## Optional plugins and migration

Use sibling modules through `go.work` and add their entries to `plugins.cfg`:

```text
dns-cache:github.com/daeuniverse/dae-plugin-dns-cache
dns-router:github.com/daeuniverse/dae-plugin-dns-router
```

Recommended order: **cache → Surge Host → router → core relay**. Omit unused
instances:

```dae
plugins {
    dns-cache {
        size: 32768
        memory_limit: 67108864
        fixed_domain_ttl { ddns.example.org: 0 }
    }
    surge { module { hosts: 'file:modules/hosts.sgmodule' } }
    dns-router {
        upstream { local: 'udp://192.0.2.53:53' remote: 'https://dns.example/dns-query' }
        routing {
            request { qname(suffix: lan) -> local fallback: remote }
            response { fallback: accept }
        }
    }
}
```

Router owns request/response policy, family preference, UDP/TCP, DoT/DoH/DoQ/HTTP3
and transport fallback. `asis` invokes the next handler; Surge explicit server
assignments take precedence over later general routing. Cache is a separate
bounded LRU for full, aged responses, SOA negative caching and fixed TTLs;
signed and transaction-specific replies are conservatively excluded.

The former `global.fallback_resolver` and top-level `dns {}` are removed. Use
`global.dns_resolver` to override the internal server from the first lookup;
the old failure-fallback behavior is not retained. Move
`dns.upstream`, `dns.routing` and `dns.ipversion_prefer` into router,
`fixed_domain_ttl` into cache, and `mitm.<instance>` into `plugins {}`. Use
`dae plugins status` and the generic `plugins` status field.

## TODO

- Observe uncaptured kernel-direct activity while preserving kernel forwarding
  performance, source addresses and connection lifetimes.
- Introduce provenance-aware sniff-only pairs; **sniff-only evidence must not
  satisfy verify**.
- Design userspace memory/entry limits and their interaction with verification.
- Optimize aggregation, ranking, locking and persistence based on measurements,
  retaining complete shared-IP AND/OR invariants.
- Improve obsolete CDN retention under unnamed activity while accounting for
  the cost of missing mappings.
