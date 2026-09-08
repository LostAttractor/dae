# MITM Go plugins

Implement an independent Go module importing
`github.com/daeuniverse/dae/component/mitm/plugin` and export:

```go
var Plugin = plugin.Definition{Setup: Setup, Commands: Commands} // Commands is optional

func Setup(context.Context, plugin.Spec, plugin.Services) (plugin.Plugin, error)
```

Decode settings in `Setup` (`DecodeSettings` handles scalar fields), implement
`Plan` and `Wrap`, add `type:Go/import/path` to
[mitm_plugins.cfg](../../../mitm_plugins.cfg), then run `make`.
See the [build guide](../../../docs/en/user-guide/build-by-yourself.md#external-mitm-plugins)
for dependencies and multiple plugins.

## HTTP contract

`Plan` declares immutable scopes and routing rules; the host takes ownership
without copying. Scope rules match the original host and port, first match wins,
unmatched hosts are denied, and separate scopes are ORed:

```go
scope := plugin.Scope{
    {Host: "private.example.com", Ports: []uint16{443}, Exclude: true},
    {Host: "*.example.com", Ports: []uint16{80, 443}},
}
```

Host globs support `*` and `?`, ignore case and contain no port or exclusion
prefix. Empty `Ports` matches every nonzero port. Plugins validate their own input.

`Wrap(flow, next)` builds middleware in configuration order: requests A → B →
upstream, responses B → A. Call `next` synchronously. Success returns a valid
response with non-nil Header and Body, transferring body ownership; failure closes
owned bodies and returns `nil, err`. Compiled plugins must honor this contract.
The host associates the response returned by `next` with `Exchange.Request`,
including local responses produced by downstream plugins.
`HTTPError` requires an underlying error and a valid HTTP error status.

`Exchange.Client` uses the selected outbound. `SetReadDeadline`, when non-nil,
bounds request-body reads and is reset by the host when calling `next`, before
another plugin or the upstream transport reads the body.
[Body helpers](body.go) provide bounded snapshots and replacement with correct
framing and trailers; plugins handle decompression and protocol-specific semantics.

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

See [configuration](../../../docs/zh/configuration/mitm-plugins.md) and
[status fields](../../../docs/en/configuration/api.md).

## Commands

`Definition.Commands` returns fresh `[]*cobra.Command` using `plugin.CommandServices`.
The host mounts them under `dae mitm <type>` and supplies `--instance <ID>`.
The factory must not load runtime configuration, initialize workers, query the
daemon or fetch remote resources. Perform command work in `RunE`, using Cobra's
context and input/output streams.

`services.Status(cmd.Context())` reads the running daemon's reports, already
filtered by plugin type and `--instance`. `services.BaseDir` is the local cache
base directory for commands such as Surge's interactive module configurator.
A plugin can define its own `status`; otherwise the host provides generic status.
`dae mitm status [--instance ID]` shows an overview. `--verbose` (`-v`) runs
each active type's `status` command with defaults against the same daemon snapshot,
preserving its Cobra lifecycle, context and instance selection. Status commands
must be read-only. Types without a status renderer fall back to full JSON reports;
a renderer failure also shows its raw reports and does not hide other types.
`--json` prints the complete snapshot directly, including when combined with `-v`.
These commands use the local Unix status socket and do not require `api_port`.
See Surge's [command implementation](../surge/command_configure.go).

Create human-readable tables with [`clitable.New()`](../../../pkg/clitable/table.go)
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
`plugin.Services.Logger`; it carries `mitm_instance` so messages do not need a
repeated plugin-name prefix. In plain-text logs the instance appears first after
the optional timestamp, before severity and message.
