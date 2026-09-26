# Surge

One plugin instance runs an ordered collection of sgmodules. It owns configuration
parsing, resource downloads, module rewrites and the QuickJS bridge. HTTP/TLS
serving and connection lifetime belong to `component/mitm`.

Start with [`setup.go`](setup.go), [`config.go`](config.go) and
[`surge.go`](surge.go). `module_*` files interpret sgmodule declarations;
`handler_*` files process HTTP contents; `runtime_*` files implement script APIs.
The native VM adapter lives in [`internal/quickjs`](internal/quickjs).

[`metrics.go`](metrics.go) owns instance-level Prometheus collectors shared by
all connection-scoped engine copies. It exposes loaded rules, HTTP/DNS script
results and runtime durations, execution-slot waits/occupancy, rule matches and
processing skips. Collection is independent of trace logging. See the
[metric definitions and examples](../../../docs/en/configuration/metrics.md#surge).

See [configuration](../../../docs/zh/configuration/surge-module.md),
[supported features](../../../docs/zh/configuration/surge-module-support.md), and
[the common plugin contract](../plugin/plugin.go).
