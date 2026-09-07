# Surge

One plugin instance runs an ordered collection of sgmodules. It owns configuration
parsing, resource downloads, module rewrites and the QuickJS bridge. HTTP/TLS
serving and connection lifetime belong to `component/mitm`.

Start with [`setup.go`](setup.go), [`config.go`](config.go) and
[`surge.go`](surge.go). `module_*` files interpret sgmodule declarations;
`handler_*` files process HTTP contents; `runtime_*` files implement script APIs.
The native VM adapter lives in [`internal/quickjs`](internal/quickjs).

See [configuration](../../../docs/zh/configuration/surge-module.md),
[supported features](../../../docs/zh/configuration/surge-module-support.md), and
[the common plugin contract](../plugin/plugin.go).
