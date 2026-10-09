# Surge

This plugin runs Surge scripts, focusing on HTTP request/response scripts in MITM
flows. Each instance owns an ordered collection of sgmodules, resource downloads,
module rewrites and the QuickJS bridge. HTTP/TLS serving and connection lifetime
belong to `component/mitm`.

Start with [`setup.go`](setup.go), [`config.go`](config.go) and
[`surge.go`](surge.go). `module_*` files interpret sgmodule declarations;
`handler_*` files process HTTP contents; `runtime_*` files implement script APIs.
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
The native VM adapter lives in [`internal/quickjs`](internal/quickjs).

[`metrics.go`](metrics.go) owns instance-level Prometheus collectors shared by
all connection-scoped engine copies. It exposes loaded rules, HTTP/DNS/cron/generic script
results and runtime durations, execution-slot waits/occupancy, rule matches and
processing skips. Collection is independent of trace logging. See the
[metric definitions and examples](../../../docs/en/configuration/metrics.md#surge).

See [configuration](../../../docs/zh/configuration/surge-module.md),
[supported features](../../../docs/zh/configuration/surge-module-support.md), and
[the common plugin contract](../../plugin/plugin.go).
The [script compatibility boundaries](../../../docs/zh/development/surge-compatibility.md)
describe execution ownership, kernel passthrough and rule/event limitations.
