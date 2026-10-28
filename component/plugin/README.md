# Go plugins

First-party implementations live under `plugins/` and share the root Go module.
External plugins may use an independent Go module. Import
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

Decode settings in `Configure`. Declare scalar configuration names and defaults
on struct fields with `mapstructure:"name"` and `default:"value"` tags, then pass
the struct pointer to `DecodeSettings`. It applies defaults before user values,
so explicit `false`, `0` and empty strings override defaults. Fields without a
`default` tag retain their initial values. Use `mapstructure:"_"` for fields parsed
separately, such as module sections; keep conditional defaults and validation in
the plugin.

`DecodeSettings` delegates to `DecodeSettingsFields`, which also accepts explicit
field bindings for nested sections and plugin-specific expressions: scalar
pointers receive values, section and parameter callbacks decode custom syntax,
and a `_` rule-slice entry receives routing rules. `DecodeStringList` reads keyed
or unkeyed string lists. Set defaults before calling `DecodeSettingsFields`.
Both entry points reject duplicate and unknown settings. Decoder callbacks and
validation errors must omit raw configuration values, which may contain
credentials.

Implement `Plan` and optional protocol interfaces. Copy
[plugins.cfg.example](../../plugins.cfg.example) to local `plugins.cfg`, add
`type:Go/import/path`, then run `make`. The local selection and generated registry
are ignored by Git.
See the [build guide](../../docs/en/user-guide/build-by-yourself.md#external-plugins)
for dependencies and multiple plugins.

The example enables Surge and lists optional first-party plugins as comments.
Uncomment those entries in local `plugins.cfg` to include them in the build.
Plugin API changes and first-party implementations are tested and released
together. Host packages depend on this contract, not on concrete plugins.

## Configuration preflight and preparation

`pluginhost.Configure` checks all enabled types before any I/O, then calls each
required `Definition.Configure`. It must leave `Spec.Config` unchanged and return
a factory capturing validated configuration. Disabled instances are skipped;
`Commands` is optional.

`Definition.Preflight` optionally checks local runtime dependencies with a
cancelable context. After validating all enabled instances, the daemon runs these
checks before kernel setup or subscription/module downloads. Reload checks the
candidate before refreshing resources; suspension reuses the active runtime.
Probes must release their resources and leave persistent state unchanged.

Plugins reading files or remote resources implement `Definition.Resources`:

| Result | Meaning |
| --- | --- |
| `Key` | Identity of all validated external contents, including dependencies |
| `Value` | Immutable prepared data passed to the factory as `Services.Prepared` |
| `Config` | Optional parsed/defaulted configuration; otherwise compare `Spec.Config` |

Resource preparation starts no workers, owns no closable handles and does not
publish storage or metrics changes. Refresh errors reject the candidate unless a
complete validated cache fallback is available.

Pass the configuration and previous host to `mitm.Load`. Equal type, ID and inputs
retain the instance; only replacements invoke factories. Factories return a
non-nil plugin, release partial resources on error and keep captured inputs
immutable. [`Configuration.Prepare`](../pluginhost/configure.go) injects scoped
logging, storage and metrics. The daemon owns activation and cleanup.

## DNS contract

`Plugin` requires only `Plan() Plan`. `HTTPPlugin` adds `Wrap`; `DNSPlugin`
adds `WrapDNS`. A DNS-only plugin contributes `Plan.DNS` and requires no HTTP
scope, CA or client MITM switch. All captured TCP/UDP port-53 flows can enter
the DNS chain; DNS scopes do not expand HTTP capture.

`DNSRequest` contains a `DNSPacket`, transport, source, original/effective
destination, interface, plugin chain and upstream binding. `DNSExchange` embeds
that data and adds invocation-scoped `DialContext`, `ListenPacket`, `Resolve` and
`Client`. Handlers receive `*DNSExchange`; `Copy()` isolates query/routing changes
while retaining the same services.

During DNS handling and observation, the host sets `Chain` to its ordered plugin
instances. An unchanged chain keeps its value across reload; replacing or
reordering instances creates a new one. Caches of results derived by plugins,
such as Surge script results, isolate the chain; draining hosts keep their own.
Preserve `Chain` in derived requests. It never contains client IP/port.

`DNSPacket` is immutable and shared safely by copies. `DNSWire(bytes)` copies an
exact received packet, including malformed/opaque bytes. `DNSMessage(message)`
copies a local message. `MessageCopy()` returns an owned editable message, or nil
when strict decoding fails; assign `exchange.DNSPacket = plugin.DNSMessage(m)` to
publish an edit. There is no separate Wire field to synchronize. `Wire()` returns
read-only bytes or a local encoding error; `IsWire()` identifies exact packets.
The core compresses unsigned local replies and truncates them to the client's UDP
limit when needed. Local replies with TSIG or SIG(0) retain their compression
choice and are not truncated after signing. Use `DNSWire` when exact preservation
of a received signed packet is required.

Resolver transports call `exchange.ExchangeUpstream(ctx, upstream, transport)`
for a single candidate, after request policy and before response policy. Pass the
concrete network, address and trusted hostname, plus the resolver identity in
`Endpoint`: `dns://host:port` for plain DNS over UDP or TCP alike, otherwise the
full URL including HTTP path/query. Before any cache lookup the core checks access,
routes the candidate and selects its node, sets `Egress` to the selected node's
physical path (the member paths of a group that picks a node per connection, or
direct traffic with its effective mark), and installs dial callbacks bound to
that selection. Groups only choose an egress and never enter
it. Dial accounting happens only on misses. Use the prepared exchange inside
`transport`. `DNSRequest.Upstream` and `Egress` are set at this boundary.

A query with several candidates (addresses, transports, fallbacks) uses one
`exchange.UpstreamQuery()`. `Prepare(ctx, upstream)` routes one candidate and
returns a `PreparedDNSExchange`; prepare a candidate again after network I/O, so
intervening policy and node changes take effect. `Exchange(ctx, transport)`
replays a cached answer for the candidate, or runs the attempt and offers its raw
answer to the caches; `Lookup()` only replays, e.g. to answer before resolving a
hostname upstream. `Finish(response)` records at most one outcome per consulted
cache for the whole query: a replay is a hit in its cache and a miss in caches
consulted before it.

`DNSUpstreamCache` stores only raw upstream answers; local answers and response
policy remain outside it. Its key `DNSRequest.UpstreamKey()` combines the egress
with the resolver identity, independently of the resolved address and the
plain-DNS transport. An empty egress is unknown and must not be cached. A reload
that keeps the node keeps its answers.

Diagnostics evaluate request middleware before upstream caches. Once the
endpoint and every candidate's route are known, the control layer derives each
candidate's egress from the shared route evaluator and its sampled node selection,
and asks the host to explain the cache without I/O, LRU changes or counters.
Candidates with different egresses, scripts, unresolved endpoints and unknown
response policies remain explicitly uncertain.

Use exchange-bound `DialContext`/`ListenPacket` for literal IP:port targets; these
preserve client identity and route the selected target, with marks, accounting
and connection lifetimes. A prepared exchange dials the node selected for it. Close every owned connection before returning.
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
plugin's authoritative server choice. Direct connections always dial the client's
address; `DNSAddressPolicy` decides whether a proxied connection dials its DNS IP
instead of sending the sniffed name, and never captures additional traffic.
`UseDNSAddress(host)` returns `(use, applicable)`; the first applicable instance
wins even when `use` is false, matching Host answer precedence.

See [DNS configuration](../../docs/en/configuration/dns.md) for persistence,
middleware ordering and the router/cache plugins.

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

`Wrap(flow, next)` builds middleware for each HTTP/1, HTTP/2 or HTTP/3 connection
and each admitted H2/H3 authority, in order: requests A → B → upstream, responses
B → A. Call `next` synchronously:

```go
type Handler func(*Exchange) (*Response, error)
```

Success returns a valid managed `Response` and transfers body ownership; close
any previously owned response before replacing it or returning an error. Failure
returns `nil, err`. `Head.Header` and the private body must be non-nil; use
`http.NoBody` for an empty body. The host associates `Response.Head.Request` with
`Exchange.Request.Head`, including local responses produced by downstream plugins.
`HTTPError` requires an underlying error and a valid HTTP error status.

An admitted HTTPS/H2 or HTTPS/H3 connection may carry another incoming authority
on the original port, including names outside the downstream certificate. The
original network/TLS ingress stays fixed. Scope is not an authority allowlist:
an out-of-scope request bypasses all plugin middleware, including response hooks,
and forwards normally (including its Alt-Svc). Middleware
is selected for that incoming authority, before rewrites; changing URL/Host in a
plugin does not activate another scope. `Flow.Host` identifies this admitted
authority, while `Flow.Source` and `Flow.Destination` remain the original captured
tuple. The original middleware chain is retained; the 32 most recently used
additional authority chains are cached per connection. Chain construction for
one authority does not block requests for other authorities.
The business authority does not trigger DNS or route selection. Only an explicit
URL scheme/host/port rewrite changes the network target; path/query and Host-only
changes retain the original ingress. An explicit URL scheme mismatch, invalid authority,
port changes, and cross-host HTTP/1 requests receive 421. Kernel capture and client
admission continue to use the declared host/port predicates.

The host's [HTTP/2 adapter](../../internal/http2/README.md) preserves the original
`:scheme` in the request URL. Explicit schemes in HTTP/2, HTTP/3 and HTTP/1
absolute-form requests are checked during admission. A mismatch with the ingress
connection returns 421 before plugin execution or upstream selection; `:scheme=http`
over TLS is not normalized to HTTPS. Default ports follow the admitted scheme,
with 443 for HTTPS; explicit ports must still match the ingress port.
HTTP/1 origin-form derives its scheme from the ingress connection; h2c is unsupported.

The host issues a local single-host leaf for the intercepted TLS/QUIC ingress,
independently of scope and routing effects. The signing cache has 256 LRU entries;
leaves expire within 24 hours and no later than the local CA. There is no upstream
certificate probe or SAN mirror. Forwarding authenticates the actual ingress
(or rewritten target) with normal upstream TLS verification. This authenticates
the ingress, not each fronted business origin; `Flow.Host` is not independent
proof of service identity. Downstream session tickets and 0-RTT remain disabled. See the
[certificate design and tradeoffs](../../docs/zh/design/mitm-http.md).

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
`Response.Head.Request`. Its original plan is selected lazily once per downstream
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

### Messages, bodies and ownership

`Request.Head` / `Response.Head` reuse standard-library metadata; do not replace the
Head pointer or write to `Head.Body` / `Head.GetBody`. `Head.ContentLength` is the
sole source of logical length, and bodies are accessed only through `Body()`.
When non-nil, `SetReadDeadline` bounds request reads; the host resets it before
passing the request to the next layer.

- `NewRequest(raw, budget)` takes ownership of the request body while preserving
  the lifetime reference held by the HTTP server's original request.
- `Exchange.NewResponse(raw)` takes ownership of a local response or an auxiliary
  response explicitly transferred downstream, inheriting the current budget and
  observation association.
- `NewResponse(raw, budget)` is for independent auxiliary responses; it does not
  automatically associate them with the current exchange. After ownership is
  transferred, do not use or close raw's body.
- The host uses `Request.Forward()` to lend an upload cursor and
  `Response.TakeHTTP()` to consume the final response and its delivery policy.
  The latter closes forbidden bodies without reading them and removes trailers
  and transfer framing for HEAD, 204, 304 and non-upgrade informational responses.
  HEAD emits a known representation length from `Head.ContentLength`, except for
  304: that status may retain an explicit Content-Length, normalized from the same
  field, but does not synthesize one. 204 and informational responses have no Content-Length. A 101
  response retains its duplex body. This normalization happens after all plugin edits.
  Plugins must not export and rewrap messages to bypass body operations. After
  forwarding, body installation and changes to committed metadata are forbidden,
  but reading the request Head and stopping observations remain allowed.

The budget is bound once when constructing a message; the host injects the same
budget into messages and `Services.BodyMemory`. Embedders may supply
`mitm.Options.BodyMemory`; direct factory callers must supply a body budget.
Protocol decoding/transformation workspaces also use this budget; arbitrary Go
allocations and interpreter heaps are not included.

| Operation | Read and failure semantics | Representation and delivery |
| --- | --- | --- |
| `Observe(limit, complete)` | No read-ahead; bounded observation during consumption. Exceeding the limit, budget exhaustion or an incomplete read only suppresses the callback | Preserves bytes, original n/error, length and policy |
| `Snapshot(limit)` | Reads eagerly; lends an immutable `membuffer.View` on success, restores the prefix, tail and actual error on failure | Replaces only the read backing, not the representation |
| `Replace(view)` | Acquires an independent reference before closing the old body; the caller still closes the view | Updates framing, clears invalid representation fields and restores default delivery |
| `Transform(install)` | Installation must not read/close input or start background work; failure leaves the original message unchanged, success transfers input ownership to the output | Unknown length, metadata cleanup and default delivery |

Observe completes when a positive Content-Length has been read in full; nonpositive
lengths require EOF. The callback runs at most once and borrows a read-only slice;
it must not retain the slice, perform I/O or reenter stop/Close. `stop()` is
idempotent and synchronizes with an already-started callback, so results can be
read after it returns. It neither waits for a blocked source Read nor closes the
upload. An invalid limit or nil callback installs no observation.

Snapshot can share a complete, unconsumed snapshot but does not bypass pending
observers. Closing the borrowed view does not affect the forwarding cursor.
`membuffer.ErrBudgetExhausted` does not wait for memory. `Body.Close()` can
concurrently interrupt a blocked Snapshot; after cancellation, no replay cursor
is published, and the operation releases its buffer before returning. Except for
Close/observation stop, body installation and eager reads must be serialized.

A reader returned by Transform must unblock, close its input and release its own
resources on Close. Actual protocol work runs during consumption, not before
Handler returns. Delivered bytes cannot be rolled back; protocol plugins own
authentication and failure replay for uncommitted units. A 101 upgrade preserves
read/write and half-close capabilities and cannot accept ordinary body transforms;
Observe installs no observer or callback for it, and its returned stop does not
affect the connection.

`Response.SetDelivery(plugin.DeliveryStreaming)` asks the host to flush promptly,
regardless of length. Transparent Observe/Snapshot operations preserve the policy;
Replace/Transform create a new representation and automatically restore
`DeliveryDefault`. Redeclare streaming delivery after installation if needed.
Response delivery uses only the final message's policy and does not affect
concurrent requests. A cold path can simply declare Streaming while retaining the
original Content-Length/ETag; it need not pretend the length is unknown.

Replacement/transformation clears Content-Encoding, length, transfer framing,
digests, validators and range declarations; valid protocol trailers are retained.
Responses synchronize the final Trailer map after the transformer completes and
before returning EOF to the consumer, including when n>0 and EOF are returned
together. Close and read errors do not publish unconfirmed final trailers.
[`component/plugin/codec`](codec) provides opt-in generic HTTP content decoding
and gRPC message framing; protocol recognition, Protobuf, RPC success criteria and
business semantics such as UMP remain the plugin's responsibility.

Returning from `next` does not mean the upload has ended. The transport closes
upload cursors separately; the host closes the final request body when request
handling ends. Retry references are retained only during the actual upstream
RoundTrip, not throughout a long response; complete, unconsumed snapshots can
still be shared for retries. Response bodies may continue executing after Handler
returns and must not retain the entire Exchange. Every view, body and retry
reference has an explicit owner; budget reclamation does not rely on GC.

[`pkg/membuffer`](../../pkg/membuffer) owns admission, buffer growth and shared
immutable storage. `Read`, `Copy` and `Buffer.Write` reserve capacity before
allocation. `Read` returns consumed bytes even on failure; close that view or
transfer it to replay storage. `Snapshot` borrows an untouched reader's complete
buffer without reading input. `View.Clone` and `View.Open` share bytes without
copying, and each owner must be closed. Components outside MITM provide their own
`NewBudget`; the package has no protocol dependency or global budget. The plugin
package adds HTTP snapshot restoration, body replacement, framing and trailers.
The host owns transport retries and their lifetime.

`membuffer.ReadExact(reader, size, budget)` admits the known length in one step
before reading, without probing subsequent bytes. On a read failure, a non-nil
returned View still owns the consumed prefix and must be closed or transferred by
the caller; admission failure consumes no input. `Buffer.Grow(n)` reserves capacity
for the next n bytes without changing length; failure preserves existing bytes and
capacity. `GRPCFrame`, whose final length is known, admits the entire frame before
writing.

### Opt-in HTTP and gRPC codecs

The host does not automatically decompress content or parse gRPC. HTTP/1 chunked
encoding, HTTP/2 DATA, HTTP/3, cancellation and trailers remain the transport's
responsibility. Plugins use
`codec.New(ctx, budget, codec.Limits{Wire: ..., Decoded: ...})` to bind the current
exchange's shared budget and processing limits once, without adding configuration
options or another body access path.

- `HTTPView(view, encoding)` consumes the input View and closes it even on failure;
  identity returns the original View directly. The input must use the same budget
  as the Codec. `HTTPReader(source, encoding)` performs no read-ahead on installation;
  decoding starts on the first Read. Both support identity, gzip, deflate (zlib/raw)
  and br. Join multiple `Content-Encoding` lines with
  `strings.Join(head.Header.Values("Content-Encoding"), ",")`; stacked encodings are
  decoded in reverse order, with at most four non-identity layers. A streaming
  reader reserves at most 40 MiB of decoder workspace; either limit returns
  `ErrUnsupported`. View decoding releases each layer's workspace before the next.
- `GRPCDecoder(source, grpcEncoding)` returns a complete `Message` from `Next()`;
  `Wire()` is the original frame and `Payload()` is the decompressed, read-only
  payload. Slices are valid only until Message is closed; callers must explicitly
  call `Message.Close()`. `Decoder.Close()` does not close previously returned
  Messages. flag=1 supports only explicitly declared gzip; a missing declaration
  must not be guessed to mean gzip.
- Constructors returning a reader/Decoder do not take ownership of source on
  failure. On success, the returned value owns source closure; Close can interrupt
  blocked reads. Once `HTTPReader` starts delivery, decoding, limit and source
  errors propagate directly; it cannot roll back by appending the original
  compressed stream.
- `GRPCFrame(parts...)` builds a flag=0 message frame within the shared budget and
  returns a caller-owned View.
  `GRPCTransform(source, httpEncoding, grpcEncoding, rewrite)` accepts only identity
  outer HTTP encoding and rejects other encodings before installation; it does not
  automatically set Delivery.
- The Transform callback borrows Message and must not close it or retain it
  asynchronously. Returning `nil, nil` preserves the original frame; a new payload
  View must use the same budget and transfers ownership to the transformer. An empty
  View is an empty message, not a deletion. The transformer encodes the new frame
  for the caller; do not return an encoded frame as payload. Mixed streams may
  still contain original compressed frames, so retain `Grpc-Encoding`.
- For HTTP, Wire limits total input and Decoded limits each layer's output. For
  gRPC, Wire limits a single frame (including its five-byte header) and Decoded
  limits a single payload, not the cumulative bytes of a long stream. Original
  bytes, decompressed results, compression workspaces and pending output share the
  budget; estimates must account for all representations retained simultaneously.

Codec itself stores only limits and budget references; returned Views, Messages
and readers own the actual resources. Serialize Read calls on a reader and Next
calls on a Decoder. Close can concurrently close the actual input before waiting
for the read lock and releasing workspaces; it must not instead hold a lock while
waiting for a blocked Read. Cancellation notifications are bound lazily when
reading starts, so Transform installation does not close input prematurely.

Each HTTP layer reads at most one extra byte to detect a limit overrun and never
delivers that byte to the next layer. After decoding EOF, input is still drained
within bounds to actual EOF to complete trailer publication. HTTP sources and all
decoding layers preserve errors returned alongside data; gRPC also preserves
source errors exactly at frame boundaries, which fixed-length reads must not hide.
An empty compressed payload does not mean the entire gRPC stream ended normally.
Deflate limits read-ahead to six bytes when trying a zlib header; on failure it
replays only that prefix and decodes as raw deflate. Brotli accepts only standard
window sizes of up to 24 bits and rejects the Large Window extension; its budget includes
window state and auxiliary tables that coexist during growth.

#### Snapshot and unary: commit after full validation

The following example is called by a plugin that has already identified the target
RPC and applies a strict HTTP 200 and final `grpc-status: 0` policy. First Snapshot
to retain the original representation, then decode fully, confirm exactly one
message and read the **current** `Head.Trailer` after actual HTTP EOF. Do not cache
an early Trailer map or treat a complete message or framing EOF as RPC success.
Whether to accept a missing status is a business-level choice, such as bilijump's
compatibility policy, not a default rule of the shared codec.

```go
package example

import (
    "context"
    "errors"
    "io"
    "net/http"
    "strings"

    "github.com/daeuniverse/dae/component/plugin"
    "github.com/daeuniverse/dae/component/plugin/codec"
    "github.com/daeuniverse/dae/pkg/membuffer"
)

func rewriteUnary(ctx context.Context, r *plugin.Response, limits codec.Limits,
    rewrite func(*codec.Message) (*membuffer.View, error)) error {
    snapshot, err := r.Body().Snapshot(limits.Wire)
    if err != nil {
        return err
    }
    budget := snapshot.Budget()
    c, err := codec.New(ctx, budget, limits)
    if err != nil {
        snapshot.Close()
        return err
    }
    decoded, err := c.HTTPView(snapshot, strings.Join(r.Head.Header.Values("Content-Encoding"), ","))
    if err != nil {
        return err
    }
    defer decoded.Close()
    source := decoded.Open()
    decoder, err := c.GRPCDecoder(source, r.Head.Header.Get("Grpc-Encoding"))
    if err != nil {
        source.Close()
        return err
    }
    defer decoder.Close()
    message, err := decoder.Next()
    if err != nil {
        return err
    }
    defer message.Close()
    extra, err := decoder.Next()
    if extra != nil {
        extra.Close()
        return errors.New("unary response contains multiple messages")
    }
    if err != io.EOF {
        return err
    }
    status := r.Head.Trailer.Get("Grpc-Status")
    if status == "" {
        status = r.Head.Header.Get("Grpc-Status")
    }
    if r.Head.StatusCode != http.StatusOK || status != "0" {
        return errors.New("RPC did not finish successfully")
    }
    payload, err := rewrite(message)
    defer payload.Close()
    if err != nil || payload == nil {
        return err
    }
    if payload.Budget() != budget {
        return codec.ErrBudgetMismatch
    }
    frame, err := c.GRPCFrame(payload.Bytes())
    if err != nil {
        return err
    }
    defer frame.Close()
    r.Body().Replace(frame)
    return nil
}
```

The callback borrows Message for business-level parsing and validation; this
function closes the returned new payload. Keep the callback free of side effects
and commit business results only after all validation and required output
construction succeed. HTTPView consumes snapshot, but Body retains the original
representation; Replace acquires an independent reference to the new frame and
restores default delivery. If the example returns an error, the caller can still
deliver the unchanged `r`; to abort the exchange, close `r` before returning
`nil, err`.

#### Transform and streaming: commit per message

Use the host-injected `Services.BodyMemory` budget. The following function only
installs a lazy transform; it has read no messages when it returns and explicitly
declares Streaming after successful installation. The callback captures only the
required business state, not the entire Exchange.

```go
package example

import (
    "context"
    "io"
    "strings"

    "github.com/daeuniverse/dae/component/plugin"
    "github.com/daeuniverse/dae/component/plugin/codec"
    "github.com/daeuniverse/dae/pkg/membuffer"
)

func installGRPCStream(ctx context.Context, r *plugin.Response, budget *membuffer.Budget,
    limits codec.Limits, rewrite func(*codec.Message) (*membuffer.View, error)) error {
    c, err := codec.New(ctx, budget, limits)
    if err != nil {
        return err
    }
    httpEncoding := strings.Join(r.Head.Header.Values("Content-Encoding"), ",")
    grpcEncoding := r.Head.Header.Get("Grpc-Encoding")
    if err := r.Body().Transform(func(source io.ReadCloser) (io.ReadCloser, error) {
        return c.GRPCTransform(source, httpEncoding, grpcEncoding, rewrite)
    }); err != nil {
        return err
    }
    r.SetDelivery(plugin.DeliveryStreaming)
    return nil
}
```

Installation failure leaves the body, Head and delivery policy unchanged. If the
callback panics, the transformer releases the borrowed Message and propagates the
panic. Each complete, validated message commits independently; the first frame
does not wait for the next frame or EOF. Unsupported content, decoding/business
callback failure, a limit overrun or budget rejection passes through the current
undelivered message and the entire remaining stream as original bytes, with no
further rewrite attempts. Previously delivered messages cannot be retracted.
Actual source read errors, cancellation and truncation must propagate, not be
misrepresented as successful EOF. A final nonzero `grpc-status` may arrive after
the first frame has been delivered and must still reach the client; business logic
requiring success of the entire RPC must not use this early-commit approach.
A later `Body.Replace` closes the transformer and restores default delivery rather
than inheriting its Streaming policy.

## Lifecycle

The configured factory prepares a non-nil plugin using the instance logger, base directory and
`PrepareClient`; release partial resources on error. Optional methods are:

- `Run(ctx, client)`: background work after activation. Set task deadlines, honor
  cancellation and join goroutines before returning. Errors are logged.
- `Close()`: release resources after execution exits, or during setup rollback.
- `Report()`: a concurrent, JSON-serializable snapshot for the status API's `details`.
  Exclude configuration credentials. Explicit script output (such as Surge
  notifications) is documented by the plugin and uses status API access controls.

HTTP handlers may run concurrently. Workers run once; queues, retries, caches and
waiting belong to the plugin. Copy needed exchange data for background work.
Unchanged instances keep their workers across reload. The daemon-provided worker
HTTP client selects current routing on each request. Replacing the last active
owner cancels that instance's worker. Retired protocol hosts drain requests; after
5 seconds of draining they cancel requests and close connections. An instance is
closed only after its last protocol host releases it and its worker exits.

The control plane selects a host and registers DNS or protocol-connection work
under one short admission lock. New work waits for instance replacement to finish,
respecting its context; already admitted work keeps its original protocol host.
Each routing generation owns its protocol connections even when it shares plugin
instances with another generation. When routing replacement also rebuilds plugin
instances, late TCP/QUIC setups and DNS requests requiring admission to the old
host fail with `net.ErrClosed`; clients must retry on the new generation. This
includes ordinary TCP setup, since it also consults the host's DNS-address policy.
Rebuilt instances never run with old routing policies or outbounds. Reused
instances retain the normal setup grace period. Direct host embedders can use `Host.Admit` and release the returned admission
after the operation ends; they must coordinate host selection with retirement.
DNS observers run inside the admitted request's finalizer, before that admission
is released.

See [configuration](../../docs/zh/configuration/mitm-plugins.md) and
[status fields](../../docs/en/configuration/api.md).

## Interface observations

`Services.Interfaces` is the host's shared interface monitor and link cache.
Create a scope with `Services.Interfaces.NewScope()` to register interface
callbacks, and close that scope during rollback or plugin cleanup. Scope closure
removes its subscriptions and waits for dispatched callbacks; other plugins and
control-plane generations continue using the source. Never close the borrowed
source or register unscoped callbacks on it. Callbacks must finish promptly, and
must not close their own scope or wait for synchronous callback registration.

The source survives configuration reload. A plugin can keep its scope while its
instance is reused or old requests drain. A change of source causes the host to
prepare a new instance. Standalone factory callers may leave the service nil;
plugins requiring live interface observations then own their monitor and close it.

## Persistent storage

`Services.ResourceCacheDir` is the shared configuration-resource cache root, or
empty when `global.resource_cache` is disabled. Use `common/resource.Cache` with
`PrepareClient` to load and validate HTTP/HTTPS resource groups. Set a stable,
plugin-specific `Namespace` for in-memory snapshots and a plugin-specific `Dir`,
or an empty `Dir` to disable persistence. Changing persistence does not change
in-memory resource identity. Complete snapshots are published atomically and used
as fallback only after a failed refresh. Local files always use current contents.
Include source URLs and interpretation options in the cache key; report cache
warnings after a successful load. This cache is separate from plugin execution state.

`Services.Storage` provides instance-scoped `Get(key)`, `Put(key, []byte)` and
`Delete(key)` operations for small persistent state. The daemon supplies it
automatically through `Configuration.Prepare` when `Services.BaseDir` is nonempty. Direct
factory callers can leave it nil for memory-only operation or inject a store
implementing the same contract. Backend construction and lifetime belong to the
host; `Configuration.Prepare` derives each instance's store from its base directory, type and
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

Plugins own schemas, validation, TTLs, limits and error policy.
Retain original timestamps when restoring expiring state. Coalesce frequent
writes in a worker and flush in `Close` after requests/workers have drained;
`Report` must not perform storage I/O. Preparation may overlap the active old
generation: the factory must not write state, and a failed/abandoned preparation's
`Close` must not flush an unactivated snapshot. Restore mutable runtime state
after activation so the old generation's final flush and invalidations are seen.
When replacing an instance, the daemon waits for all old protocol hosts to release
it and complete its final `Close` before starting the successor. Reused instances
keep their workers running and do not restore state again. Direct embedders must
first retire earlier hosts, call `old.DrainFor(next, abort)`, and call the returned
release function after starting or abandoning the successor. `abort` skips the
request drain grace period, not final cleanup. Otherwise, embedders must coordinate
concurrent writers themselves.

## Prometheus metrics

The host records fixed wall-clock intervals with
`dae_mitm_http_stage_duration_seconds{stage}`: `upstream` covers the actual
transport.RoundTrip call, `response_ready` spans request entry through the plugin
chain's return (including errors), `request` covers the full handler lifetime and
`snapshot` covers the shared Snapshot operation. Collection does not require Debug.
These intervals can overlap; adding or subtracting them does not yield CPU time.
Auxiliary requests are not automatically attributed to the current downstream
exchange. Trace records the first body Read, first data, first Write/Flush and
completion; a returned Write/Flush does not prove client receipt. Plugins observe
protocol-internal authentication/transformation themselves, without treating Transform
installation time as body processing or double-counting the shared Snapshot.

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
filtered by plugin type and `--instance` in `PluginStatus.Plugins`.
`PluginStatus.BufferMemory` is a single process-wide snapshot, retained even when
the selection contains no instances. `services.BaseDir` is the local cache
base directory for commands such as Surge's interactive module configurator.
A plugin can define its own `status`; otherwise the host provides generic status.
`dae plugins status [--instance ID]` shows an overview. `--verbose` (`-v`) runs
each active type's `status` command with defaults against the same daemon snapshot,
preserving its Cobra lifecycle, context and instance selection. Status commands
must be read-only. Types without a status renderer fall back to full JSON reports;
a renderer failure also shows its raw reports and does not hide other types.
`--json` prints the complete snapshot directly, including when combined with `-v`.
These commands use the local Unix status socket and do not require `api_port`.
See Surge's [command implementation](../../plugins/surge/command_configure.go).

`services.TriggerScript(ctx, instance, request)` requests an existing task through
the daemon API. A plugin implementing `ScriptTrigger` must return promptly, reject
inactive/overlapping work and attach accepted tasks to its worker lifetime, so
shutdown/reload cancels and joins them. Execution requests never carry script
source or arbitrary arguments. The CLI returns an acceptance snapshot; execution
results are available through the plugin's status report.

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

## Client reports and commands

The host transports `Report()` as opaque JSON in `api.PluginInstanceStatus.Details`.
A plugin owns its report types, schema, decoding and rendering. Core status views
show daemon state; detailed plugin reports are available through `plugins status
--verbose`, `plugins <type> status` and JSON output.

`Definition.Commands` receives scoped host services. A plugin may expose a
separate lightweight client package for API commands, registered explicitly by a
standalone client through `cli.NewMITMCommand`. That package must not import its
runtime implementation. Surge's [`api`](../../plugins/surge/api) and
[`client`](../../plugins/surge/client) packages follow this boundary.
