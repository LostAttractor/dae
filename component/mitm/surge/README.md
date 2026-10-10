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
Generic tasks run only on demand; cron tasks also have a timer schedule.
[`module_load.go`](module_load.go) uses [`resource.Cache`](../../../common/resource/cache.go)
for validated module/dependency snapshots. [`module_dependencies.go`](module_dependencies.go)
resolves scripts, Host sets and Map Local files through one bounded dependency reader.
Automatic refreshes reuse remote resources until their next check; explicit reloads
and refresh requests read them again. `global.resource_cache` controls disk snapshots;
the active resource set and its refresh schedule remain in memory independently.
The shared CLI [`list` and `run` commands](../../../client/cli/scripts.go) discover
configured cron/generic tasks and request manual execution through the daemon API.
`list` supports instance/module filtering and JSON; `run` returns an acceptance snapshot. Manual and
timer execution share `runTask` under the active worker's lifetime.
The [plugin host](../host.go) supplies instance-scoped resource
services. File stores merge writes under a context-bounded cross-process sidecar lock.
Script persistence defaults to `store: true`, at
`BaseDir/plugins/<instance ID>/surge-store.json`; `store: false` is memory-only.
Reads reuse the decoded snapshot until the file identity, size or mtime changes.
[`notification.go`](notification.go) keeps the latest 50 notifications per script
(module/name/type) within each runtime, subject to a conservative 1 MiB JSON
budget per instance. The longest histories lose their oldest entries first;
ties remove the oldest entry. Reports include all retained messages
independently of log filtering; histories reset on reload. CLI text shows the
latest 3 per script by default; `surge status -v` and `plugins status -v` show all.
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
The Node.js process pool creates a fresh context
per invocation. Cancellation kills the leased process; failed workers are
discarded. `Engine.Close` releases the pool after host draining or setup rollback.
Excess workers idle for 60 seconds are reaped on a 5-second maintenance interval,
keeping the most recently returned idle worker warm. Active leases are retained
even while waiting for host I/O. Maintenance starts on the first application
lease and joins on close; startup probes leave no maintenance worker behind.
The Node worker receives a minimal environment and runs in permission mode;
`node:vm` is not a security boundary for hostile scripts. Node's memory limit
applies to each worker's V8 old generation, not ArrayBuffer storage or RSS.
Within the Node adapter, `pool.go` owns admission and reuse, `vm.go` owns an
invocation's lease and host calls, and `worker.go` owns process launch and framing.
`pool_stats.go` owns idle maintenance and cached process memory samples.

[`metrics.go`](metrics.go) owns instance-level Prometheus collectors shared by
all connection-scoped engine copies. It exposes loaded rules, HTTP/DNS/cron/generic script
results and runtime durations, execution-slot waits/occupancy, rule matches and
processing skips. Collection is independent of trace logging. See the
[metric definitions and examples](../../../docs/en/configuration/metrics.md#surge).
Node.js pool counters and background RSS/PSS samples also appear in ordinary
status, `--recent`, and plugin reports. Collectors and status queries read cached
values without process I/O. Sample coverage and age identify partial/stale data.

See [configuration](../../../docs/zh/configuration/surge-module.md),
[supported features](../../../docs/zh/configuration/surge-module-support.md), and
[the common plugin contract](../../plugin/plugin.go).
The [script compatibility boundaries](../../../docs/zh/development/surge-compatibility.md)
describe execution ownership, kernel passthrough and rule/event limitations.
