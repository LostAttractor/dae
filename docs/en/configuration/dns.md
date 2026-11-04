# DNS relay, evidence retention and plugins

Core transparently relays captured **TCP/UDP destination port 53** and observes
the DNS replies it delivers. `DomainRegistry` supplies evidence for sniff
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
routing {
    rules {
        dip(192.0.2.53) && dport(53) -> dnat('198.51.100.53:1053')
    }
    fallback: direct
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

### Internal lookup cache

The default application resolver and each proxy bootstrap resolver cache ordinary
DNS responses without requiring the `dns-cache` plugin. The cache wraps the Go
resolver's DNS transport, covering ordinary queries such as A, AAAA and TXT. A
hit opens no upstream DNS socket. Go still owns hosts-file and search-domain
handling, in-flight lookup sharing, address sorting and TCP dial fallback.

All internal resolvers share a bounded **4096-entry, 8 MiB** LRU budget. The byte
budget is conservative accounting, not process RSS. Entries are memory-only;
there is no additional maintenance goroutine. Expiration is checked on lookup,
and capacity bounds all retained entries.

- The shortest RR TTL, including CNAMEs, bounds lifetime. NXDOMAIN/NODATA require
  an SOA and also respect its TTL and MINIMUM. Hits age TTLs without renewing them.
- Zero/high-bit TTLs, truncated replies, errors such as SERVFAIL, signatures and
  unsafe replay cases are not cached. Transport failures, timeouts and
  cancellations are not negative DNS answers.
- Resolver instance, DNS server, TCP/UDP, query type and flags separate entries.
  Node resolver instances also separate mark/interface policies. Application and
  direct bootstrap answers stay independent. Replacing internal resolver policy
  or its routing callback creates a fresh namespace; old transactions cannot
  populate the replacement namespace.
- Internal caching accepts ordinary EDNS negotiation without options and builds
  a new OPT on each hit. ECS, Cookies, NSID and other options retain the original
  query path. Go still decides TCP retries after UDP truncation; the transports
  have separate cache entries.

Proxy entry dialers also keep the addresses a node name resolves to until the
earliest expiry among the DNS answers that produced them; hits do not renew it.
A hit skips the Go resolver entirely, including its address sorting, which opens
a UDP socket per address. Addresses are kept only when every DNS exchange of the
lookup ended in a cached answer, counting a truncated UDP reply through its TCP
retry: hosts-file answers, failures, timeouts and uncacheable replies are not
kept. Entry paths with the same DNS server, mark and interface share these
addresses; idle paths keep them when woken, and resource refreshes keep them.
Every `dae reload` drops them, also when the configuration is unchanged, so a
hosts-file or resolv.conf change for a cached node name applies after its DNS
TTL or at the next reload. Go rereads these files at most every five seconds:
addresses resolved in the first five seconds after a reload are kept only until
then.

The optional `dns-cache` plugin caches raw upstream answers after request policy,
server selection, routing and node selection. Response policy runs on every
request, including hits. Keys include the egress, the resolver identity and the
query; client addresses and source ports are excluded. The egress is the selected
node's physical path, or direct traffic with its effective mark. Outbound groups
only choose an egress and are not part of the key: groups selecting the same node
share answers, and a failover or reload that changes the node stops using the
previous node's answers. A `random` group picks a node per connection, so its
traffic may leave through any member: its egress is the set of member paths, the
group shares its answers, and a membership change stops using them. The resolver identity excludes resolved addresses: plain
DNS is `dns://host:port` for UDP and TCP alike, other protocols keep their full
URL. Different client-selected servers stay separate unless policy redirects them
to the same upstream and egress. Without a selectable node the egress is unknown
and no cached answer applies. Each upstream query counts one lookup per cache,
however many addresses or transports it races. The IP version preference's
probe of the other family, an upstream chosen by a response rule and each
server of a Surge multi-server race are upstream queries of their own.

Static diagnostics check caches after upstream selection, routing and the sampled
node selection, including the no-connectivity fallback. Missing query or routing
data, candidates with different egresses and runtime-dependent policies remain
uncertain; diagnostics do not dial or change
cache counters and LRU order.

The internal resolver, `dns-cache` and Surge DNS script results reuse the bounded
LRU storage in `pkg/dnscache`, while retaining their own entries and budgets.
The response caches also share query identity, TTL handling and ordinary OPT
reconstruction. Client queries or responses carrying EDNS options bypass caching
and fixed TTL rewriting until their option-specific semantics are implemented.

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
| Valid DNS reply registered just before delivery to the client | `max(retain_until, registered_at + max(ttl, W))` |
| Actual connection/traffic activity | `max(retain_until, observed_at + W)` |
| GC | Delete due pairs, recompute affected IPs, and adjust kernel residency |

Use the final delivered TTL; a CNAME alias uses the shortest TTL along its path
to the address RRset. A TTL with its high bit set means zero (RFC 2181), only for
the retention calculation; forwarded bytes are unchanged. Updates never shorten an existing deadline. GC runs on
updates and on a one-minute check, so quiet entries may be collected up to one
sweep later. Each domain keeps a lower bound on its address deadlines in a
min-heap, so collection visits only domains whose bound has passed. The first implementation has **no userspace entry or memory limit**.
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

Upstream, local and **cached replies are all registered before delivery**, so
the kernel holds a reply's domain evidence before the client can connect to an
answered address. Failed delivery keeps the evidence: the reply is valid, and
retention collects it as usual. Plugin DNS observers run after successful
delivery. A cached reply refreshes retention because the client has just received
an answer it may retain anew. This does not change cache TTL aging or the
original `ReceivedAt`.

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
connections using standard-library splice reuse kernel byte-counter growth
for refresh, with approximately five-second polling granularity. Collection waits
one more polling interval, so activity before a deadline that is sampled later
still renews the evidence. Idle connections
do not refresh. Observed client attempts count even if upstream dialing fails.

Connection entry, the first activity for a new UDP destination, and DNS evidence
registration are synchronous. The initial route decision still precedes any
capacity promotion caused by that first activity. Continued I/O is queued at
most once per second per connection (per destination for UDP), so renewal can
trail the latest I/O by up to one second. Queued observations are coalesced by
`(original IP, canonical domain or empty string)`, retaining the latest
`observed_at` for each key in a single queue. Enqueue briefly holds the queue
lock. The existing Registry worker attempts to apply a batch
every second. Processing time never replaces observation time; an empty batch
cannot renew an idle connection. Splice counter polling is followed by this
batch application too.

GC, DNS registration, the end of a renewal window and reload copying first
apply already queued activity.
The consumer swaps two reusable buffers under the queue lock, establishing one
observation boundary, then releases the lock. Later enqueues belong to the next
batch. Pair updates and kernel writes run without the queue lock.
Earlier unknown-pair activity is therefore consumed before subsequent DNS
registration, rather than applied to newly created evidence. Status and
verification read applied evidence without consuming the queue. Continued-I/O
deadline changes and capacity promotions become visible when a batch is applied.
Synchronous operations may apply it earlier, while a busy worker can delay it
beyond the next one-second check.

Surviving connections use a shared activity handle redirected when a new
configuration is published. Reload joins the old background worker and any
journal write in progress, applies its pending activity, and copies evidence
into an independent kernel projection.
Activity after the handoff uses the new window; pending events are applied
before GC. Delivered DNS observations reach both configurations while the old
one drains, using each configuration's own rules. Reload preserves existing
deadlines; ordinary shutdown rejects further activity.

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

Evidence is stored in two binary files under `$DAE_LOCATION_CACHE` (default
`/var/lib/dae`), mode 0600:

- `domain-registry.base`: the baseline. It lists every pair with its exact
  deadline (nanoseconds), grouped by domain, followed by a CRC32C checksum. A
  pair's ordinal is its position in the baseline.
- `domain-registry.journal`: changes since the baseline. Each frame carries a
  length and a CRC32C that binds the baseline's epoch and the frame's offset.

The writes follow from the registry's data structure: a renewal only moves a
deadline forward to renewal time plus the window, and pairs are deleted only by
expiry.

- **New pairs**: the change that creates pairs, for example registering one DNS
  response, tries to append a frame with their domains, IPs and exact deadlines,
  without per-record fdatasync. If another writer or compaction holds the write
  lock, the pairs are queued for that writer or the background worker; the
  creator does not wait for disk I/O. A process crash can lose queued pairs not
  yet written, and a power loss can also lose unsynced writes. The next renewal
  window's sync makes the preceding new-pair frames durable.
- **Renewals**: are batched in a 10-minute window. A window ends 10 minutes after
  it opened, also across reloads. Its frame lists each pair renewed during it
  once and is followed by fdatasync, which also makes earlier new-pair frames
  durable. Recovery sets the deadlines of listed pairs to window start + 10
  minutes + retention window, at most 10 minutes later than in memory. A pair
  whose final deadline in the window lies outside that range, such as a TTL
  longer than the retention window or activity applied after the window was
  due, is recorded with that exact deadline.
- **Deletions**: are not written. Recovery collects expired pairs by deadline.
- **Crashes**: lose the renewals of the current window (at most 10 minutes).
  Those pairs recover their last persisted deadline and expire earlier: by at
  most 10 minutes if they were also renewed in the previous window, otherwise
  by up to one retention window. A renewal by a DNS TTL longer than the
  retention window can lose up to that TTL. A clean close appends a final
  renewal frame and fdatasyncs it.

The journal is extended in zero-filled 64 KiB chunks, so appended frames
overwrite allocated blocks without changing the file size and fdatasync writes
only data. Once the journal reaches the baseline's size (at least one chunk) it
is compacted: memory is written as a new baseline with a new epoch, followed by
an empty journal. The baseline is written to `domain-registry.base.tmp`, synced,
renamed and its directory synced, then the new journal is published the same
way. Interrupted at any step, the directory holds the old baseline and journal,
the new baseline with an ignored old journal, or the new pair. If the published
baseline is unreadable but a complete temporary baseline exists, startup adopts
the temporary one.

Renewal frames are written at the valid journal tail, not back into baseline
records selected by ordinal. Ordinals are replay-time memory indexes, not disk
offsets; each batch sorts and delta-encodes them. New pairs take ordinals in
creation order. Compaction renumbers whole domain groups, putting those with
renewals marked in the current or just-closed window first; renewed pairs also
lead within each group. This linear partition reuses the renewal marks and
snapshot buffer, with no frequency counter or additional compaction. Ordering
within each class is unspecified, and cold restore starts without renewal marks.
Clustering shortens ordinal deltas without moving records on each renewal.
Reordering can also change adjacent deadline deltas in the baseline, but does
not eliminate random in-place writes: this path already appends sequentially.
The 64 KiB chunk is a growth unit, not a fixed write size for each renewal. Encoding-layout measurements are described in the
[testing guide](../../zh/development/testing-and-performance.md).

Restore validates the whole baseline, then replays journal frames of its epoch in
order up to the first invalid frame; later writes start at that position. There
is no baseline entry or size cap; format, address/name, duplicate, trailing-data
and checksum checks remain. Cold restore loads the records before interface
attachment, collects expired ones and recomputes current-rule bitmaps. Evidence
is written only after activation; before it, startup at most publishes an
adopted temporary baseline. If the journal is missing or of another epoch, the
first write after activation rewrites the baseline. On reload the new
configuration takes over the in-memory evidence and both files.

Write failures are logged and switch to rewriting the baseline, retried when
each renewal window ends and on clean close. They do not prevent safe retirement or in-memory registry adoption
during reload.

### Inspect persisted records

`dae registry dump [directory]` exports the published baseline and its valid
journal prefix without writing. The directory defaults to `$DAE_LOCATION_CACHE`
or `/var/lib/dae`. It needs read access to the files, but no running daemon, API
socket or configuration file. Output is indented JSON sorted by domain and IP:

```sh
dae registry dump
dae registry dump /path/to/registry | jq '.records[] | select(.domain == "example.org.")'
dae registry dump | jq -r '.records[] | [.domain, .ip, .retain_until] | @tsv'
```

Each `records` entry is a domain-IP pair. `retain_until` is its replayed UTC
retention deadline, not a DNS RR TTL or live kernel routing state. Inspection
includes expired records and cannot see in-memory renewals not yet journaled.
`epoch` is a hexadecimal string to avoid JSON number precision loss.
`baseline_bytes` and `journal_bytes` count the bytes read, including the journal's
reserved zero tail; `journal_valid_bytes` counts the replayed prefix including
its header. Valid checksums do not prove fdatasync completed: reads can see
unsynced page-cache data.

Missing journals, mismatched headers or epochs, and truncated or corrupt tails
are reported in `warnings`. Normal zero padding is not an error. An unreadable
journal or a missing or invalid baseline fails the command. Inspection never
truncates journals, adopts `.tmp` baselines, deletes old files, renews evidence
or triggers compaction. A detected baseline replacement during the read asks
the caller to retry.

### Runtime statistics

`dae status` / `/api/status` reports:

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

The CLI retains `PAIRS / DOMAINS / IPs / IPv4 / IPv6 / GC (PAIRS)` in the
`domain-registry (unlimited)` detail table. `domain-kernel` appears in the compact
`Kernel tables` group with `USED`, `LIMIT`, `USAGE%` and `ON FULL` (`omit`), plus
`CANDIDATES`, `OMITTED` and `PENDING` in a note. Pending projection changes await
kernel retry. A nonempty table `error` makes usage and omissions unavailable,
not zero. Ordinary and `--recent` views share these statistics.

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

## Optional plugins

DNS plugins live in this repository's `plugins/` directory and share its Go
module. Copy `plugins.cfg.example` to a local `plugins.cfg` if needed, uncomment
the following entries, and run `make`:

```text
dns-cache:github.com/daeuniverse/dae/plugins/dns-cache
dns-router:github.com/daeuniverse/dae/plugins/dns-router
```

Request order: **Surge Host → router → core relay**. Cache wraps actual upstream
exchanges regardless of its declaration position. Omit unused instances:

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

`global.dns_resolver` selects the internal resolver from the first lookup.
Configure upstreams, routing and family preference in the router plugin and
`fixed_domain_ttl` in the cache plugin. Inspect instances with `dae plugins status`
or the API's `plugins` status field.

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
