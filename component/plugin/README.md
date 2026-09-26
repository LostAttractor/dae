# Go plugins

Implement an independent Go module importing
`github.com/daeuniverse/dae/component/plugin` and export:

```go
var Plugin = plugin.Definition{Configure: Configure, Commands: Commands}

func Configure(spec plugin.Spec) (plugin.Factory, error) {
    conf, err := parseConfig(spec.Config) // defaults and validation, no I/O
    if err != nil {
        return nil, err
    }
    return func(ctx context.Context, services plugin.Services) (plugin.Plugin, error) {
        return prepare(ctx, conf, services)
    }, nil
}
```

Decode settings in `Configure` (`DecodeSettings` handles scalar fields), implement
`Plan` and optional protocol interfaces, add `type:Go/import/path` to
[plugins.cfg](../../plugins.cfg), then run `make`.
See the [build guide](../../docs/en/user-guide/build-by-yourself.md#external-plugins)
for dependencies and multiple plugins.

## Configuration preflight and preparation

`Configure` is required; `Commands` is optional. `mitm.Configure(definitions, specs)`
first checks that **all enabled plugin types are compiled in**, then parses every
instance once, collecting configuration errors without preparing resources.
The daemon calls it before subscriptions, eBPF preparation, connectivity checks
or module downloads, and before ejecting BPF ownership on reload. Disabled
instances are skipped.

`Configure` must be deterministic, perform no I/O, start no workers and leave
`Spec.Config` unchanged. Return a factory capturing the validated configuration.
Remote module contents, certificates and other resource-dependent errors belong
to the factory. It releases partial resources on error and returns a non-nil
plugin on success. Factories must not mutate their captured configuration.

Pass the returned `*mitm.Configuration` through preparation, then call
`configured.Load(ctx, options, services)`. Load invokes factories in declaration
order with instance-local services, without parsing again; failure closes already
prepared instances. Configuration objects own no runtime resources. Direct plugin
callers use `Configure(spec)` followed by the returned factory.

## DNS contract

`Plugin` requires only `Plan() Plan`. `HTTPPlugin` adds `Wrap`; `DNSPlugin`
adds `WrapDNS`. A DNS-only plugin contributes `Plan.DNS` and requires no HTTP
scope, CA or client MITM switch. All captured TCP/UDP port-53 flows can enter
the DNS chain; DNS scopes do not expand HTTP capture.

`DNSRequest` contains a `DNSPacket`, transport, source, original/effective
destination, interface and an opaque policy `ContextKey`. `DNSExchange` embeds
that data and adds invocation-scoped `DialContext`, `ListenPacket`, `Resolve` and
`Client`. Handlers receive `*DNSExchange`; `Copy()` isolates query/routing changes
while retaining the same services.

`DNSPacket` is immutable and shared safely by copies. `DNSWire(bytes)` copies an
exact received packet, including malformed/opaque bytes. `DNSMessage(message)`
copies a local message. `MessageCopy()` returns an owned editable message, or nil
when strict decoding fails; assign `exchange.DNSPacket = plugin.DNSMessage(m)` to
publish an edit. There is no separate Wire field to synchronize. `Wire()` returns
read-only bytes or a local encoding error; `IsWire()` identifies exact packets.

Use exchange-bound `DialContext`/`ListenPacket` for literal IP:port targets; these
preserve client identity and route the selected target, with marks, accounting
and connection lifetimes. Close every owned connection before returning.
Use the system resolver to bootstrap upstream hostnames.

DNS dial callbacks take `(ctx, network, address, hostname)` for connections and
`(ctx, address, hostname)` for packet sockets. `address` is the selected IP:port;
`hostname` is the trusted upstream endpoint hostname, or empty for a literal IP.
The hostname participates in route selection while the connection retains its
selected IP. Do not pass the client's question name as the endpoint hostname.
Use `exchange.Fork()` for auxiliary queries (such as family probes): the
core gives them a separate TCP lifetime and never delivers their unsolicited
frames to the client. Bound their context so the original response can be delivered
before the invocation deadline.

`DNSExchange.Client` provides auxiliary HTTP with the original client's source,
interface, process and routing policy. Each invocation owns separate policy-keyed
pools. Use the invocation context for requests, finish HTTP work and close response
bodies before returning; do not retain the client for background work. The host's
daemon HTTP client belongs to background workers, not intercepted DNS requests.

Middleware order is request A → B → relay, response B → A. Call next synchronously.
Responses embed `DNSPacket`; core only packs/truncates locally constructed
messages. Set `ReceivedAt` once. Cache hits set `Cached` and retain original receipt
time. Successful delivery, including replay, refreshes DomainRegistry retention
using the final TTL and the configured sliding window. Errors do not implicitly retry or
select a different resolver. Unsupported operations should pass through unchanged.

`DNSObserver` receives isolated copies of final correlated responses, including
local answers, while host admission remains held. `DNSResolver` supplies an
optional cross-plugin explicit-server service. `ServerAssigned` marks a preceding
plugin's authoritative server choice. `DNSAddressPolicy` can retain an already
selected DNS IP for direct/proxy dialing; it never captures additional traffic.
`UseDNSAddress(host, proxy)` returns `(use, applicable)`; the first applicable
instance wins even when `use` is false, matching Host answer precedence.

See [DNS configuration](../../docs/en/configuration/dns.md) for persistence,
middleware ordering and the independent router/cache modules.

## HTTP contract

`Plan` declares immutable scopes and routing rules; the host takes ownership
without copying. Scope rules match the incoming authority admitted before
middleware, first match wins,
unmatched hosts are denied, and separate scopes are ORed:

```go
scope := plugin.Scope{
    {Host: "private.example.com", Ports: []uint16{443}, Exclude: true},
    {Host: "*.example.com", Ports: []uint16{80, 443}},
}
plan := plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: scope}}}
```

Host globs support `*` and `?`, ignore case and contain no port or exclusion
prefix. Empty `Ports` matches every nonzero port. Plugins validate their own input.

The host compiles positive scope hosts and their associated ports into TCP/UDP
capture predicates. Domains use the same DNS-derived IP maps as ordinary
`domain()` routing; literal IPs use destination-IP predicates. Missing DNS
evidence must not cause an implicit all-TCP/UDP or ports-only capture fallback:
unrelated `direct` traffic must remain entirely in eBPF. Connections already
forwarded to userspace by another rule can still match their actual SNI/Host.
Shared IPs and positive globs can produce extra candidates; ordered exclusions
and client selection are enforced against the actual connection in userspace.
Host/DNAT plans likewise retain their complete filters during kernel capture.
`DestinationProgram` runs first, capturing candidates in the kernel and selecting
the exact target in userspace. `FlowProgram` then accumulates must, bump and HTTP
capture effects, followed by outbound and mark selection in `RoutingProgram`.
Destination predicates match the original connection. A kernel destination
candidate hands off before flow controls or routing can commit the old target.
Userspace selects the target first; FlowProgram and RoutingProgram then match
the rewritten destination and original source/interface/process/policy identity.
IP rewrites preserve Host/SNI. Exact destination predicates stay in userspace
and share domain/LPM resources with their kernel capture predicates.

Each `Plan.Scopes` entry combines its ordered `Scope` with `PreserveRoute`.
The default processes HTTP before choosing a final route, covering scripts,
URL changes and local responses. Set `PreserveRoute: true` only when the plugin
preserves the target and always forwards upstream. This keeps pure inspection
on its valid kernel decision. Certificate selection is entirely local and does
not contact the upstream. Effects cannot expand their associated scope, and
request processing takes precedence when several matching scopes overlap.
Request candidates hand off before old-target block, mark or must decisions.
Client exclusions still follow ordinary connection routing.

`Wrap(flow, next)` builds middleware separately for each HTTP/1, HTTP/2 or
HTTP/3 connection and each admitted H2/H3 authority, in configuration order: requests A → B →
upstream, responses B → A. Call `next` synchronously. Success returns a valid
response with non-nil Header and Body, transferring body ownership; failure closes
owned bodies and returns `nil, err`. Compiled plugins must honor this contract.
The host associates the response returned by `next` with `Exchange.Request`,
including local responses produced by downstream plugins.
`HTTPError` requires an underlying error and a valid HTTP error status.

An admitted HTTPS/H2 or HTTPS/H3 connection may carry another incoming authority
on the original port, including names outside the downstream certificate. The
original network/TLS ingress stays fixed. Scope is not an authority allowlist:
an out-of-scope request bypasses all plugin middleware, including response hooks,
and forwards normally (including its Alt-Svc). Middleware
is selected for that incoming authority, before rewrites; changing URL/Host in a
plugin does not activate another scope. `Flow.Host` identifies this admitted
authority, while `Flow.Source` and `Flow.Destination` remain the original captured
tuple. The original middleware chain is retained; up to 32 additional authority
chains are cached per connection, with further names built per invocation.
The business authority does not trigger DNS or route selection. Only an explicit
URL scheme/host/port rewrite changes the network target; path/query and Host-only
changes retain the original ingress. Scheme mismatch, invalid authority,
port changes, and cross-host HTTP/1 requests receive 421. Kernel capture and client
admission continue to use the declared host/port predicates.

The host issues a local single-host leaf for the intercepted TLS/QUIC ingress,
independently of scope and routing effects. The signing cache has 256 LRU entries;
leaves expire within 24 hours and no later than the local CA. There is no upstream
certificate probe or SAN mirror. Forwarding authenticates the actual ingress
(or rewritten target) with normal upstream TLS verification. This authenticates
the ingress, not each fronted business origin; `Flow.Host` is not independent
proof of service identity. Downstream session tickets and 0-RTT remain disabled. See the
[certificate design and tradeoffs](../../docs/zh/configuration/mitm-certificates.md).

HTTP/3 uses the same plugin contract and CA. `ServePacketConn` requires the
original source and destination addresses and serves a fixed UDP association; `DialPacketContext` opens its upstream packet sockets through the
planned outbound. HTTP/3 requests stay on HTTP/3 upstream, while
`Exchange.Client` uses HTTP/1 or HTTP/2 with a separate TCP route plan.
Only QUIC ClientHellos advertising `h3` enter this path; other UDP is relayed.
The host disables 0-RTT, preserves per-connection middleware and supports multiple
QUIC connection IDs for the same source, destination and handshake hostname.
Cross-tuple migration is not supported; request authorities can differ
from that handshake hostname.

Unrewritten forwarding binds the transport URL to the original ingress while
preserving the HTTP Host; plugins retain their business URL, including in
`Response.Request`. Its original plan is selected lazily once per downstream
connection and retains the intercepted IP, node, outbound and mark. Local
responses do not choose an upstream. `Exchange.Client` and explicit URL target
rewrites resolve/route their own URLs through the system resolver. Destination
rules determine the effective IP while preserving client identity. Block applies
to the network target, not each fronted business authority. Pure inspection
reuses its valid route. Pools are isolated per client connection and keyed by
the full dial plan: addresses, nodes, outbounds, marks and transport/TLS authority.
Pinned plans also validate their policy lifetime before pool reuse: a revoked
original plan terminates its downstream even if the first upstream dial failed.
TCP dial failures can try the next address before writing HTTP data. Before
upstream forwarding, the host enables transport-controlled safe retries for
request bodies by sharing complete snapshots, or recording up to 64 KiB of
streaming input under the shared memory budget. This does not delay forwarding;
incomplete, oversized or budget-denied recordings cannot be replayed. Recording ownership
ends when RoundTrip returns, even if the response is still streaming. Traffic
belongs to actual upstream connections.
Host HTTP entry points require an `UpstreamPlanner`; there is no separate
dial-only execution path. Daemon downloads use the same candidate iterator,
consuming addresses lazily until one connects. HTTP/3 pools use the final UDP
route; retiring a pool waits for its active responses before closing QUIC.
`SetReadDeadline`, when non-nil,
bounds request-body reads and is reset by the host before forwarding.
[Body helpers](body.go) provide bounded snapshots and replacement with correct
framing and trailers; plugins handle decompression and protocol-specific semantics.
`SnapshotBody` returns an immutable `membuffer.View` and reuses untouched
snapshots. Close the view after use; forwarding owns the replay reader. Supply
the factory's `Services.BodyMemory` to share the MITM budget across instances and
overlapping hosts. Embedders may supply a process-owned budget in
`mitm.Options.BodyMemory`; the host injects the same budget into every factory.
Direct factory callers must supply a budget when the plugin processes bodies.
`membuffer.ErrBudgetExhausted` never waits: a failed snapshot restores the
consumed prefix and unread tail for forwarding.

`SetRequestBody` and `SetResponseBody` transfer an independent body cursor;
callers still close their own views. Replacing a request clears its old `GetBody`.
The host prepares retry ownership from the final body immediately before
RoundTrip and releases it when that call returns. Rewritten bodies and read-only
snapshots use the same path, without retaining retry storage throughout a long
response. The transport closes upload cursors separately, including uploads that
outlive response headers. The host closes the final request body after forwarding
or a local response. There is no Exchange-owned retry state or cleanup API.
Lifetime is explicit; garbage collection does not release budget reservations.
Arbitrary plugin allocations and interpreter heaps are outside this budget.

[`pkg/membuffer`](../../pkg/membuffer) owns admission, buffer growth and shared
immutable storage. `Read`, `Copy` and `Buffer.Write` reserve capacity before
allocation. `Read` returns consumed bytes even on failure; close that view or
transfer it to replay storage. `Snapshot` borrows an untouched reader's complete
buffer without reading input. `View.Clone` and `View.Open` share bytes without
copying, and each owner must be closed. Components outside MITM provide their own
`NewBudget`; the package has no protocol dependency or global budget. The plugin
package adds HTTP snapshot restoration, body replacement, framing and trailers.
The host owns transport retries and their lifetime.

## Lifecycle

The configured factory prepares a non-nil plugin using the instance logger, base directory and
`PrepareClient`; release partial resources on error. Optional methods are:

- `Run(ctx, client)`: background work after activation. Set task deadlines, honor
  cancellation and join goroutines before returning. Errors are logged.
- `Close()`: release resources after execution exits, or during setup rollback.
- `Report()`: a concurrent, JSON-serializable snapshot without credentials for
  the status API's `details`.

HTTP handlers may run concurrently. Workers run once; queues, retries, caches and
waiting belong to the plugin. Copy needed exchange data for background work.
Reload cancels workers and drains requests; after 5 seconds it cancels requests
and closes connections, then closes plugins after execution exits.

See [configuration](../../docs/zh/configuration/mitm-plugins.md) and
[status fields](../../docs/en/configuration/api.md).

## Persistent storage

`Services.Storage` provides instance-scoped `Get(key)`, `Put(key, []byte)` and
`Delete(key)` operations for small persistent state. The daemon supplies it
automatically through `Configuration.Load` when `Services.BaseDir` is nonempty. Direct
factory callers can leave it nil for memory-only operation or inject a store
implementing the same contract. Backend construction and lifetime belong to the
host; `Configuration.Load` derives each instance's store from its base directory, type and
ID rather than sharing an incoming `Services.Storage` across instances.

```go
// Restore after activation (Run, or a synchronized first invocation).
raw, err := services.Storage.Get("state.json")
if errors.Is(err, fs.ErrNotExist) {
    // No state saved yet.
} else if err != nil {
    // Handle a storage failure without logging secret values.
} else {
    // Decode and validate the plugin's versioned state.
    _ = raw
}
// Serialize related fields as one value for atomic replacement.
err = services.Storage.Put("state.json", encodedState)
// Removing a missing key succeeds.
err = services.Storage.Delete("state.json")
```

Keys contain 1–128 ASCII letters, digits, `.`, `_` or `-`, starting with a letter
or digit. Values are opaque bytes, limited to 8 MiB on reads and writes. Invalid
keys and oversized values return errors matching `fs.ErrInvalid`.
`Get` returns caller-owned bytes. Operations are concurrency-safe and writes
atomically replace whole values, including across
separately opened handles. There are no multi-key transactions or atomic
read/modify/write operations; concurrent writes to one key are last-commit-wins.
The caller must not mutate a value while `Put` is running.

The disk layout is `BaseDir/plugins/state/<namespace>/<key>`. The namespace is
`<type>` when the instance ID equals the type, otherwise `<type>@<instance>`.
For example, the default bilijump instance uses `plugins/state/bilijump/`, and
an instance named `personal` uses `plugins/state/bilijump@personal/`. Paths are
independent of instance count, so adding another instance does not move state.
Type and instance names are separately URL-path-escaped, including `@`, `.` and
`..`, to avoid namespace collisions. The daemon base is `DAE_LOCATION_CACHE`,
defaulting to `/var/lib/dae`. Keeping the type and instance ID stable preserves
state through reload/restart; changing type selects a different namespace.
Renaming, disabling or removing an instance does not delete its files. Reads and
deletes do not create directories; writes create directories with mode `0700`
and files with `0600`, sync the temporary file, rename it, then sync the directory.
Values are stored unencrypted. Storage has no open resources between calls and
requires no `Close`.

Plugins own schemas, validation, migrations, TTLs, limits and error policy.
Retain original timestamps when restoring expiring state. Coalesce frequent
writes in a worker and flush in `Close` after requests/workers have drained;
`Report` must not perform storage I/O. Preparation may overlap the active old
generation: the factory must not write state, and a failed/abandoned preparation's
`Close` must not flush an unactivated snapshot. Restore mutable runtime state
after activation so the old generation's final flush and invalidations are seen.
The daemon closes the old host before starting the successor. Direct embedders
must preserve that ordering or coordinate concurrent writers themselves.

## Prometheus metrics

`Services.Metrics` is a standard `prometheus.Registerer` scoped to the instance.
Register collectors in the factory, return registration errors, and retain the
metric handles on the instance. The host adds the `dae_plugin_` prefix and
constant `plugin_type` / `plugin_instance` labels. Use a plugin-specific local
namespace such as `dns_cache_lookups_total`; reserve the host labels and the
`instance_start_time_seconds` name.

```go
requests := prometheus.NewCounter(prometheus.CounterOpts{
    Name: "example_requests_total",
    Help: "Requests processed by this example instance.",
})
if services.Metrics != nil {
    if err := services.Metrics.Register(requests); err != nil {
        return nil, err
    }
}
```

`Configuration.Load` supplies a non-nil registerer even when `metrics_port` is zero.
Direct factory callers may leave it nil. Each host generation owns a private
registry: preparation registers collectors, `Start` publishes them, and `Close`
removes them and joins in-flight collection before closing plugin resources.
Failed preparation leaves the active generation intact. Counters and histogram
observations reset on reconstruction, including reload; listener changes alone
preserve them. The host exports `dae_plugin_instance_start_time_seconds` with
each activated instance's start time.

Custom collectors must describe their fixed metric schema, support concurrent
collection, finish promptly and perform no I/O. Copy authoritative state under
its lock, then release the lock before sending metrics. Metric help, types and
label names must agree across instances. Use bounded result/reason categories
and configuration-defined identifiers for labels. Query names, request URLs,
client addresses and raw error messages are unsuitable label values.

Embedders pass a process-owned `*mitm.Metrics` in `mitm.Options.Metrics` and
aggregate it with their other gatherers. The daemon already does this on its
existing metrics listener. See [metrics and PromQL examples](../../docs/en/configuration/metrics.md).

## Commands

`Definition.Commands` returns fresh `[]*cobra.Command` using `plugin.CommandServices`.
The host mounts them under `dae plugins <type>` and supplies `--instance <ID>`.
The factory must not load runtime configuration, initialize workers, query the
daemon or fetch remote resources. Perform command work in `RunE`, using Cobra's
context and input/output streams.

`services.Status(cmd.Context())` reads the running daemon's reports, already
filtered by plugin type and `--instance`. `services.BaseDir` is the local cache
base directory for commands such as Surge's interactive module configurator.
A plugin can define its own `status`; otherwise the host provides generic status.
`dae plugins status [--instance ID]` shows an overview. `--verbose` (`-v`) runs
each active type's `status` command with defaults against the same daemon snapshot,
preserving its Cobra lifecycle, context and instance selection. Status commands
must be read-only. Types without a status renderer fall back to full JSON reports;
a renderer failure also shows its raw reports and does not hide other types.
`--json` prints the complete snapshot directly, including when combined with `-v`.
These commands use the local Unix status socket and do not require `api_port`.
See Surge's [command implementation](../mitm/surge/command_configure.go).

Create human-readable tables with [`clitable.New()`](../../pkg/clitable/table.go)
from `github.com/daeuniverse/dae/pkg/clitable` to share the host CLI style:
no borders, two spaces between columns, left-aligned text, right-aligned numbers,
and no trailing spaces. Use uppercase column headers and column overrides for
identifiers or formatted numbers.

For composite metrics, use `clitable.Parts` with single-line fields in the same
order across rows. Keep units with their numbers; padding follows each field:

```go
rows := []table.Row{
    {"tcp4", clitable.Parts("47", "/", "89296")},
    {"tcp6", clitable.Parts("8", "/", "402")},
}
writer.AppendRows(clitable.AlignRows(rows)) // 47/89296 and "8 /402  "
```

Pass all data rows to `AlignRows` together. Use empty strings for absent middle
fields. `cell.Decorate` applies width-preserving ANSI styling; `cell.String()`
returns the compact form for summaries.

Keep errors and warnings outside tables, with
one blank line before each section. Short diagnostics use `instance/module: detail`,
one per line, without extra blank lines after headings or between entries. Use
additional lines when task details need them, without indentation. Preserve full
data in JSON output.

For runtime logs, use the instance logger supplied to the factory in
`plugin.Services.Logger`; it carries `plugin_instance` so messages do not need a
repeated plugin-name prefix. In plain-text logs the instance appears first after
the optional timestamp, before severity and message.
