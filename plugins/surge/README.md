# Surge

This plugin runs Surge scripts, focusing on HTTP request/response scripts in MITM
flows. Each instance owns an ordered collection of sgmodules, resource downloads,
module rewrites and the JavaScript bridge. HTTP/TLS serving and connection lifetime
belong to `component/mitm`.

Start with [`setup.go`](setup.go), [`config.go`](config.go) and
[`surge.go`](surge.go). `module_*` files interpret sgmodule declarations;
`handler_*` files process HTTP contents; `runtime_*` files implement script APIs.
[`execution.go`](execution.go) shares slot admission, script metadata and limits,
local debug-source refresh and execution timing across HTTP, DNS and background tasks.
[`runtime_bridge.go`](runtime_bridge.go) dispatches VM host calls and asynchronous
events; [`runtime_http.go`](runtime_http.go) owns script HTTP requests, Fetch
redirects and bounded response decoding.
[`tasks.go`](tasks.go) runs cron and generic scripts through the host's Worker
lifecycle and routed HTTP client, sharing execution slots and persistent storage.
Generic tasks run only on demand; omitted MAC always means local execution.
Cron runs once locally and, when the script isolates LAN clients, once per
currently MITM-enabled LAN MAC. Shared scripts run only once locally. Local work
requires neither device discovery, global MITM nor a CA; slow or failed LAN
discovery does not delay local admission or dispatch. Automatic discovery has one
in-flight query; repeated ticks for a pending script coalesce instead of building
an unbounded backlog. Device execution is admitted only after its batch's query
succeeds, then rechecks eligibility before running. The execution timeout starts
at admission and includes slot waiting, revalidation, JS and HTTP, not the earlier
batch discovery. Device targets require global MITM and a ready CA.
Explicitly enabled MACs need not be online; `all`, IP and CIDR selectors expand
only over host-known LAN devices. State and busy detection belong to the task's
effective scope; all scopes share instance slots. Background HTTP uses daemon
routing, not the selected device's routing identity.
[`module_load.go`](module_load.go) uses [`resource.Cache`](../../common/resource/cache.go)
for validated module/dependency snapshots. [`module_dependencies.go`](module_dependencies.go)
resolves scripts, Host sets and Map Local files through one bounded dependency reader.
Automatic refreshes reuse remote resources until their next check; explicit reloads
and refresh requests read them again. `global.resource_cache` controls disk snapshots;
the active resource set and its refresh schedule remain in memory independently.
The plugin's CLI [`list` and `run` commands](client/scripts.go) discover
configured cron/generic tasks and request manual execution through the daemon API.
`list` supports instance/module filtering and JSON, always including a local row
and adding device rows only for isolated scripts. Local rows precede devices,
which are ordered by MAC. Counts and name resolution use instance/module/name,
not row count. `run --mac` selects a MITM-enabled device only for isolated scripts;
shared scripts return 400 and require omitting MAC. Malformed MACs return 400,
disabled devices or busy scope tasks 409, and unavailable discovery 503.
Acceptance reports `status.scope`; only device scope has `status.mac`.
Status reads the target snapshot refreshed at activation, cron ticks and manual
requests without discovery I/O. Discovery failure marks idle known device rows
unavailable, or adds module warnings when none exist, without corrupting local
state. Confirmed removal of idle devices drops their in-memory task counters.
Manual and timer execution share `runTask` under the active worker's lifetime.
The [plugin host](../../component/mitm/host.go) supplies instance-scoped resource
services. File stores merge writes under a context-bounded cross-process sidecar lock.
Script persistence defaults to `store: true`, at
`BaseDir/plugins/<instance ID>/surge-store.json`; `store: false` is memory-only.
Instance `isolate_lan` defaults to true. In dae's named module block, optional
`isolate_lan` sets the module policy, and repeated
`script { name: 'script.name' isolate_lan: false }` blocks override individual
scripts. Precedence is script > module > instance; sgmodule and JS stay unchanged.
Names match exactly after module arguments and conditions are resolved. Missing,
ambiguous or duplicate overrides fail preparation. Policy changes rebuild the
instance without changing download identity; unchanged descriptors permit reuse.
This applies to HTTP, DNS, cron and generic scripts independently of persistence.
Local calls always share the instance's local bucket. Isolated LAN calls use a
host-confirmed directly connected MAC bucket; unknown identity reads null and
writes/deletes false. With isolation disabled, every source uses the local bucket.
Keys remain unchanged and are shared across scripts/modules within a bucket;
omitted keys use the resolved script path. Capture and cron scripts must use the
same isolation policy and effective scope to read the same Cookie/token. Shared
mode intentionally exposes those values to other clients using that bucket.
Changing policy never migrates, merges or deletes existing buckets. MACs identify
devices, not authenticated users; MAC reuse can inherit a bucket.

`dae plugins surge store migrate OLD_MAC NEW_MAC --instance surge` moves all keys
in one device bucket through the running daemon's admin API. The independent
client provides the same command. An existing target (even empty) is rejected;
there is no overwrite or merge mode. Source or target executions must finish
before migration, including overlapping reload generations. Other scopes do not
cause a busy rejection. Stop old-device traffic and background eligibility first:
new executions under the old MAC can recreate its bucket. Migration does not
change authorization, routing, task targets, local data, or notification history.
It invalidates device DNS script cache generations, not local or upstream caches.
`--json` reports instance, normalized MACs and keys moved, never stored values.
With `store: false` it only moves current runtime memory; no script runtime means
503 rather than opening historical files. A 500 error stating that the migration
was published means the move took effect but durability could not be confirmed. Timeouts/disconnects
also do not prove that nothing changed; the command never retries automatically.
Cross-process file locks serialize individual updates, not another process's
whole script execution; stop other writers sharing the file before migration.
See [usage and limits](../../docs/en/configuration/surge-module.md#migrating-data-after-a-mac-change).

The single JSON file maps bucket names to key/string maps, with 64 MiB total and
4 MiB per value. Construction normalizes absolute paths and symlinks, which may perform metadata
I/O, but does not read store contents. Live runtimes share stores by normalized
path through a weak cache. `Warm` does not execute user scripts; construction, warmup,
scripts that do not access the store, and `Close` do not load or flush its
contents or create store directories, JSON or sidecar lock files. The first
actual read or write loads the latest snapshot; a first write without a preceding
read still preserves other keys. Invalid JSON, FIFOs and file-access errors surface
on read or as write returning false, without overwriting the bad file; repairing
the file allows retry on the same runtime. Reads reuse the decoded snapshot until
the file identity, size or mtime changes. Writes retain cross-process locking,
refresh-before-merge and atomic replacement.

DNS script answers key by effective scope, script, domain and
plugin chain; unknown bypasses the cache, while shared calls reuse local entries.
[`notification.go`](notification.go) retains up to 50 messages per effective
scope and script (scope/MAC/module/name/type), with a conservative 1 MiB JSON
budget per instance including scope and MAC bytes. The longest histories lose
their oldest entries first; ties remove the oldest entry. Reports include all
retained messages independently of log filtering; histories reset on reload.
CLI text shows the latest 3 per scope and script; `surge status -v` and
`plugins status -v` show all. Explicit local/device/unknown labels never infer
local from an empty MAC. Scope describes the effective bucket, not raw origin:
a shared LAN invocation reports local. Only device scope carries a MAC, and
MAC attribution is not a Prometheus label.
[`runtime_vm.go`](runtime_vm.go) defines the VM contract. Build with
`make SURGE_RUNTIME=quickjs` (default) for the native adapter in
[`internal/quickjs`](internal/quickjs), or `make SURGE_RUNTIME=nodejs` for
[`internal/nodejs`](internal/nodejs). The `surge_nodejs` Go build tag excludes
QuickJS and its CGo dependency; the default build excludes the Node adapter.
Both use the same bootstrap and Go host callbacks. Backend selection is fixed
for every Surge instance in a binary. Node.js 22.13+ is an external runtime
dependency only for the Node build.
Runtime preparation observes the startup/reload context, while each invocation
uses its own context and deadline.
Instances with scripts create a runtime and prewarm one Node worker during
preparation, without executing user scripts; failure rejects the candidate before
publication. Instances containing only rewrites or routing rules need no runtime. The Node.js process
pool creates a fresh context per invocation. Cancellation kills the leased
process; failed workers are discarded. `Engine.Close` releases the pool after
host draining or setup rollback.
Excess workers idle for 60 seconds are reaped on a 5-second maintenance interval,
keeping the most recently returned idle worker warm. Active leases are retained
even while waiting for host I/O. Maintenance starts with the first worker,
including the prewarmed one, and joins on close. Preflight uses a disposable pool.
The Node worker receives a minimal environment and runs in permission mode;
`node:vm` is not a security boundary for hostile scripts. The configured memory limit applies to each worker's V8 old generation.
Node and jq share `internal/processgroup`, backed by containerd/cgroups. Each Node
worker also has a cgroup memory limit of twice the V8 budget plus 64 MiB, with
swap disabled. The parent pool limit is that amount times its worker capacity plus one worker
budget for delayed kernel charges from retired processes.
A writable delegated cgroup v2 memory controller is required during prewarming.
The supplied systemd unit uses `Delegate=memory` and `DelegateSubgroup=daemon`
(systemd 254+). Pools remain below that unit; discovery never crosses a service,
scope or slice boundary. Other supervisors must provide an empty, writable
ancestor with memory enabled for its children. The daemon is never moved.
Workers enter their cgroup at process creation. Retirement kills the group,
reaps the process, waits for all descendants to leave and deletes the group.
Cleanup failures remain owned by the pool and are retried in the background;
new work is paused until cleanup succeeds. A closing pool never resumes.
The parent retirement allowance avoids waiting for delayed anonymous-memory
statistics before reusing a slot. Kernel OOM kills are identified before the
worker group is removed; they do not prove that the worker's own limit was hit,
since an ancestor limit or host-wide OOM can also kill its processes.
The fixed headroom needs calibration on target Node versions and workloads;
it covers a different budget from the V8 heap. Pool limits are per runtime,
so overlapping reload generations each have their own budget, while an enclosing
service `MemoryMax` also covers all generations and the daemon.
Within the Node adapter, `pool.go` owns admission and reuse, `vm.go` owns an
invocation's lease and host calls, and `worker.go` configures Node and owns framing.
`internal/processgroup` owns process launch, pipes, cgroup placement and retirement
for both Node and jq.
`pool_stats.go` owns idle maintenance and cached process memory samples.

[`metrics.go`](metrics.go) owns instance-level Prometheus collectors shared by
all connection-scoped engine copies. It exposes loaded rules, HTTP/DNS/cron/generic script
results and runtime durations, execution-slot waits/occupancy, rule matches and
processing skips. Collection is independent of trace logging. See the
[metric definitions and examples](../../docs/en/configuration/metrics.md#surge).
Node.js pool counters, background RSS/PSS samples, and separately cached cgroup
usage, peak, limit and OOM-kill counts appear in `dae plugins surge status`,
`dae plugins status --verbose` and raw JSON reports. Core `dae status` and
`status --recent` do not expand plugin runtime reports. Collectors and status
queries read cached values without process I/O. Sample coverage and age identify
partial/stale data. Console and notification log messages are limited to 4096
UTF-8 bytes per entry; truncated entries carry `truncated=true`.

See [configuration](../../docs/en/configuration/surge-module.md),
[supported features](../../docs/zh/configuration/surge-module-support.md), and
[the common plugin contract](../../component/plugin/README.md).
The [script compatibility boundaries](../../docs/zh/development/surge-compatibility.md)
describe execution ownership, kernel passthrough and rule/event limitations.

## Body representation and decoding

HTTP plugins observe, snapshot and replace bodies only through the managed message's
`Body()`; `Head` carries metadata only. Generic content decoding uses
`component/plugin/codec` with the input View's actual budget, which also accounts for
compression workspaces. `decodeBodyView` consumes the input View and releases it even
on failure; the caller closes the View returned on success. Unsupported or corrupt
encodings skip body-dependent scripts and replay the original representation.
Oversized request bodies still fail with 413, and request cancellation propagates.
A 206 response carries only a range of the representation, which shared
`Body.Replace` rejects: Body Rewrite skips it and requires-body scripts receive no
body, so the range passes through unchanged.

Valid bodyless responses may carry encoding headers. Surge treats empty input as
identity; this compatibility policy is not part of the shared codec. Originally
bodyless HEAD/304 responses update only the required metadata, without using body
replacement that would incorrectly remove their validators. Shared
`Response.TakeHTTP()` discards forbidden bodies and trailers after all plugin edits,
including synthetic responses and script status changes to 204/205/304. 205 is
framed with Content-Length: 0. It releases the original body and its budget without
changing the delivery policy. Omitting
the transmitted body is not the same as replacing the selected representation, so ETag,
Last-Modified, Content-Encoding and Repr-Digest remain if still valid, but digests
of the original message content do not. Fields already cleared by an actual body
replacement are not restored.

## Reports and clients

[`api`](api) owns the plugin report types and [OpenAPI schemas](api/openapi.json).
[`client`](client) decodes and renders those reports and provides API commands
without importing the engine or a JavaScript runtime. The daemon's `Commands`
and the standalone client's entry point register this package explicitly.
Runtime details are displayed by `plugins surge status` and
`plugins status --verbose`; core status views consume only daemon fields.
