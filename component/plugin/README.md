# Go plugins

Implement an independent Go module importing
`github.com/daeuniverse/dae/component/plugin` and export:

```go
var Plugin = plugin.Definition{Setup: Setup, Validate: Validate, Commands: Commands}

func Validate(plugin.Spec) error // optional, static configuration checks only
func Setup(context.Context, plugin.Spec, plugin.Services) (plugin.Plugin, error)
```

Decode settings in `Setup` (`DecodeSettings` handles scalar fields), implement
`Plan` and optional protocol interfaces, add `type:Go/import/path` to
[plugins.cfg](../../plugins.cfg), then run `make`.
See the [build guide](../../docs/en/user-guide/build-by-yourself.md#external-plugins)
for dependencies and multiple plugins.

## Configuration preflight and preparation

`Validate` and `Commands` are optional. Startup and reload first check that **all
enabled plugin types are compiled in**, then run every available `Validate` hook
before subscriptions, eBPF preparation, connectivity checks or module downloads.
Disabled instances are skipped. Reload rejects a failed preflight before handing
over the running control plane's BPF ownership.

`Validate` must be deterministic, perform no I/O, start no workers and leave
`Spec.Config` unchanged. Share a parser between `Validate` and `Setup` so checks
stay consistent; `Setup` still validates when called directly. Type checks apply
even to plugins without this optional hook, whose specific settings are checked
during setup. Remote module contents, certificates and other resource-dependent
errors are diagnosed during preparation.

Pass the complete `map[string]plugin.Definition` to daemon/host loaders instead
of discarding validators into a setup-only table. `mitm.Load` also preflights the
whole instance list before the first `Setup`; setup still runs in declaration
order with the routed preparation client, and failures close prepared instances.

## DNS contract

`Plugin` requires only `Plan() Plan`. `HTTPPlugin` adds `Wrap`; `DNSPlugin`
adds `WrapDNS`. A DNS-only plugin contributes `Plan.DNS` and requires no HTTP
scope, CA or client MITM switch. All captured TCP/UDP port-53 flows can enter
the DNS chain; DNS scopes do not expand HTTP capture.

`DNSRequest` carries exact `Wire`, parsed `Message` when valid, transport, source,
original/effective destination, interface and an opaque policy `ContextKey`.
Copy before modifying or retaining it. After changing Message, replace Wire too.
Use request-bound `DialContext`/`ListenPacket` for literal IP:port targets; these
preserve client identity and route the selected target, with marks, accounting
and connection lifetimes. Close every owned connection before returning.
Use the system resolver to bootstrap upstream hostnames.

DNS dial callbacks take `(ctx, network, address, hostname)` for connections and
`(ctx, address, hostname)` for packet sockets. `address` is the selected IP:port;
`hostname` is the trusted upstream endpoint hostname, or empty for a literal IP.
The hostname participates in route selection while the connection retains its
selected IP. Do not pass the client's question name as the endpoint hostname.
Set `DNSRequest.Independent` on auxiliary queries (such as family probes): the
core gives them a separate TCP lifetime and never delivers their unsolicited
frames to the client. Bound their context so the original response can be delivered
before the invocation deadline.

`DNSRequest.Client` provides auxiliary HTTP with the original client's source,
interface, process and routing policy. Each invocation owns separate policy-keyed
pools. Use the invocation context for requests, finish HTTP work and close response
bodies before returning; do not retain the client for background work. The host's
daemon HTTP client belongs to background workers, not intercepted DNS requests.

Middleware order is request A → B → relay, response B → A. Call next synchronously.
Responses may carry exact Wire or a local Message; core only packs/truncates local
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
without copying. Scope rules match the original host and port, first match wins,
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
on its valid kernel decision. Effects cannot expand their associated scope, and
request processing takes precedence when several matching scopes overlap.
Request candidates hand off before old-target block, mark or must decisions.
Client exclusions still follow ordinary connection routing.

`Wrap(flow, next)` builds middleware separately for each HTTP/1, HTTP/2 or
HTTP/3 connection, in configuration order: requests A → B →
upstream, responses B → A. Call `next` synchronously. Success returns a valid
response with non-nil Header and Body, transferring body ownership; failure closes
owned bodies and returns `nil, err`. Compiled plugins must honor this contract.
The host associates the response returned by `next` with `Exchange.Request`,
including local responses produced by downstream plugins.
`HTTPError` requires an underlying error and a valid HTTP error status.

HTTP/3 uses the same plugin contract and CA. `ServePacketConn` requires the
original source and destination addresses and serves a fixed UDP association; `DialPacketContext` opens its upstream packet sockets through the
planned outbound. HTTP/3 requests stay on HTTP/3 upstream, while
`Exchange.Client` uses HTTP/1 or HTTP/2 with a separate TCP route plan.
Only QUIC ClientHellos advertising `h3` enter this path; other UDP is relayed.
The host disables 0-RTT, preserves per-connection middleware and supports multiple
QUIC connection IDs for the same source, destination and hostname. Cross-tuple
migration and cross-host connection reuse are not supported.

`Exchange.Client` and upstream forwarding share request routing. Deferred scopes
route the final target after middleware and before pool lookup; local responses
do not choose an upstream. The original authority uses the intercepted IP; other
authorities resolve through the system resolver. Destination rules determine the effective
IP while preserving client identity. Pure inspection reuses its valid route for
the original authority. Pools are isolated per client connection and keyed by
the full dial plan: addresses, nodes, outbounds, marks and transport/TLS authority.
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
`plugin.BodyMemory` to share the MITM budget across instances and overlapping
hosts. `membuffer.ErrBudgetExhausted` never waits: a failed snapshot restores the
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

`Setup` prepares a non-nil plugin using the instance logger, base directory and
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

For runtime logs, use the instance logger supplied to `Setup` in
`plugin.Services.Logger`; it carries `plugin_instance` so messages do not need a
repeated plugin-name prefix. In plain-text logs the instance appears first after
the optional timestamp, before severity and message.
