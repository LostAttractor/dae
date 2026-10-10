# API and independent clients

`dae status`, its `--verbose` and `--recent` modes, and `dae plugins surge status` read runtime state through the same API client. The Web application communicates through HTTP APIs.

## Build and connect

With Go 1.27+ (or inside `nix-shell`):

```sh
make client
sudo ./dae-client status
./dae-client status --api http://192.168.1.1:9080 --recent
./dae-client plugins status --api http://192.168.1.1:9080 --json
./dae-client plugins status --api http://192.168.1.1:9080 --verbose
./dae-client plugins surge status --api http://192.168.1.1:9080 --instance personal
./dae-client status --api unix:///var/run/dae.sock --json
```

`make client` runs `CGO_ENABLED=0 go build -trimpath -o dae-client ./cmd/dae-client`. It needs no eBPF generation, clang, kernel headers, native runtime or daemon submodules. Go dependencies must already be cached or downloadable. Cross-compilation is supported, for example `GOOS=darwin GOARCH=arm64 make client`.

| Option | Meaning |
| --- | --- |
| `--api` | Defaults to `DAE_API_ENDPOINT`, then `unix:///var/run/dae.sock` |
| `--timeout` | Request timeout, default `10s` |
| `DAE_API_KEY` | Configured API key for TCP administration, sent as a Bearer credential; unnecessary for verified direct LAN clients when the daemon has no key |
| `--json` | `status`: full snapshot, mutually exclusive with `--verbose` and `--recent`; MITM report commands: filtered instance array |
| `--color` | `status` text colors: `auto` (default), `always`, or `never` |

`status --color always` (or `--color=always`) preserves ANSI colors in pipes and
redirected output; `--color never` disables them. Both override the environment.
The default `auto` retains terminal detection and the `FORCE_COLOR`, `NO_COLOR`,
and `TERM` settings. This applies to ordinary, `--verbose`, and `--recent` text
views; `--json` always emits plain JSON. With `watch`, also enable its `--color`
(`-c`) option to display the colors:

```sh
watch --color -n 2 'dae status --recent --color always'
```

The standalone client also supports this, for example
`watch --color -n 2 'dae-client status --recent --color always'`.

### Manage selectors

Both `dae` and `dae-client` provide:

```sh
dae selector                         # All selectors and candidates; * marks the actual choice
dae selector proxy                   # One group, including candidate IDs
dae selector set proxy 'Hong Kong'    # Exact display name
dae selector set proxy NODE_ID       # ID, including namesakes or different entrances
dae selector reset proxy             # Restore the explicit selector(n) default
dae selector proxy --json
```

Duplicate names require an ID rather than guessing by list order. Connection flags and environment variables are the same as for status. The daemon applies and persists changes; the CLI never edits the state file directly. Missing or ambiguous preferences remain visible alongside the temporary actual choice and can be restored on a later reload. Reset requires a configured default.

The Unix socket remains mode `0600` and is available regardless of `global.api_port`. Neither command entry point elevates privileges automatically; use `sudo` or existing filesystem permission for the local socket.

Enable the [TCP API](api.md) and set `DAE_API_KEY` if the daemon has a configured key. Without one, a verified direct LAN client can request status without credentials; WAN and unidentifiable callers are rejected. Clients bypass environment proxies and reject redirects. The daemon serves HTTP; HTTPS support in the Go client does not add TLS or reverse-proxy support to the daemon.

The Go SDK owns its transport and does not depend on application changes to `http.DefaultTransport`. Successful responses are limited to 32 MiB and error bodies to 8 KiB. Oversized error bodies still preserve the HTTP status in `client.Error.StatusCode`.

Status tables use composite titles for `UP/24H` and the traffic
`AVG/MAX` pairs. These titles share field widths with their data: each title
and value starts at the left of its field, and `/` stays
at the same position across rows. Display widths account for CJK text and ANSI colors.

## Traffic table

For `selector` groups, the API's `nodes` includes only selected, continuously monitored, currently testing, or actively connected nodes. All status modes respect this scope; group/global totals still include omitted paths. Fetch `/api/selectors` for every candidate and its last test result.

All text status modes end with a shared `Traffic` table:

```text
GROUP / DIALER       UPLOAD 1M     DOWNLOAD 1M   AVG /MAX ↑     AVG /MAX ↓     TOTAL ↑  TOTAL ↓
ALL                  ▂▂▂▂▂▂▂▂▂▂▂▂  █▂▂▂▂▂▂▂▂▂▂▂  54.3/146Kbps   2.48/20.8Mbps  7.21M    85.5M
direct              ▃▂▄▅▃▃▃▃▃▂▃▃  ▄▅▅█▄▅▆▄▃▃▃▃  2.77/6.00Kbps  5.26/11.2Kbps  63.5K    112K
proxy_jp(lightsail)  ▂▂▂▂▂▂▂▂▂▂▂▂  █▂▂▂▂▂▂▂▂▂▂▂  51.5/144Kbps   2.47/20.8Mbps  7.15M    85.4M
```

- Ordinary status shows groups with active connections or cumulative payload bytes,
  including their selected or active/data-bearing dialers. `--recent` shows only
  groups and dialers with a nonzero upload or download sample in the last minute;
  selection, active connections and historical totals alone do not keep a row visible.
  After filtering, one dialer gives a `group(dialer)` row; multiple dialers give
  `group (total)` followed by indented rows. Distinct IDs remain separate even if
  their names match. `--verbose` expands all groups and includes idle dialers.
  Built-in direct uses one `direct` row with its group totals in every mode.
- `ALL` is always shown and uses daemon statistics; group rows, including collapsed
  rows, use group statistics from the API, including retired paths. Dialers are accounted for
  separately in each group. These aggregation levels should not be added together.
  `TOTAL ↑` and `TOTAL ↓` are cumulative payload bytes, preserved across reloads
  and reset on daemon restart.
- `UPLOAD 1M` and `DOWNLOAD 1M` contain the twelve most recent completed five-second
  throughput samples, oldest first. Both directions share a scale within each
  row; rows scale independently. Missing history shows `-`.
- The `AVG/MAX` columns follow the graphs and precede `TOTAL ↑/↓`, showing each
  direction's average and maximum bit rates over the available samples. Ordinary
  and recent views hide both rate columns when the full table exceeds the terminal
  width. `--verbose` always includes
  them; remaining overflow is clipped at the right edge.
- The shared `GROUP / DIALER` label uses at most 52 display columns. Long labels
  are elided with `…`, and whitespace within names is normalized so each entry
  occupies one row.

## Recent status view

All text modes render built-in direct separately with active and lifetime connection
counts, plus `Fallback Total` when nonzero. It has no connectivity check or
availability history. `--verbose` also shows its per-network connection counts.
Built-in block remains hidden by the daemon.

`status --recent` puts each proxy group's current selection and connectivity on one row,
followed by the shared traffic table at the bottom.
For example, without color:

```text
direct: 8 active · 120 total · Fallback Total 3

GROUP     STATE  24H      1H            SELECTED              ACTIVE
proxy_hk  UP     100.00%  [......++++]  香港标准 IEPL 专线 2  0
proxy_jp  UP     100.00%  [......++++]  lightsail             108
proxy_tw  UP     100.00%  [......++++]  台湾标准 IEPL 专线 3  0
proxy_us  UP     100.00%  [......++++]  美国高级 IEPL 专线 1  0
tor       UP     100.00%  [......++++]  tor                   0
```

- `ACTIVE` is the group's active connection count. Fallback is a single
  process-lifetime direct counter, not a per-node, per-group or per-network metric.
  It counts established connections using no-connectivity fallback, survives reloads
  and resets on restart; it is not the number currently using fallback.
- `SELECTED` uses `selected_node_ids`. This compact view only includes confirmed
  capabilities or live selections; `unknown` and `unsupported` networks without
  a current selection are omitted. If all displayed networks select one node,
  only its name is shown.
  Different selections are joined with semicolons and prefixed with `ipv4:`, `ipv6:`, `tcp:`,
  `udp:`, or explicit network names. Confirmed networks without a current
  selection show `-`; a group with no selection also shows `-`. `random` means per-connection
  selection with no stable group-level node. Existing connections may still use
  previously selected nodes.
- `STATE`, `24H`, and `1H` are separate columns for current state, time-weighted
  availability, and ten six-minute connectivity buckets. Titles and values are
  left-aligned consistently, including the percentage and history columns. Without color,
  `+`, `x`, and `.` mean available, unavailable, and
  unobserved. Color terminals use green/red dots and gray hollow dots. Unchecked
  groups show `N/A`, with `-` for availability and history.
- Group names use at most 18 display columns; each node selection uses at most
  32, with longer names elided using `…`, including CJK text and ANSI colors.
  Table headers, group rows and daemon summaries are clipped at the terminal's
  right edge instead of wrapping;
  trailing selections or counters may therefore be partially hidden.
  Without a known terminal width, lines are not clipped.

## Independently deployable Web assets

```sh
make web
# Or build directly within the frontend directory:
make -C web
```

`web/` owns the frontend source and build entry point. `make web` writes to `build/web/` (configurable with `WEB_OUTPUT`); `make -C web` writes to `web/dist/`. Both need only Make and standard file utilities, without Go or Node.js. `dae-client` contains only terminal commands and does not include Web assets.

The bundle contains `index.html`, `style.css`, `app.js` and `api.js`. The default embedded page uses native form controls for client sets, selectors, HTTPS settings and certificate downloads. More complex presentation and interaction can live in an external frontend. To update the UI without rebuilding dae, deploy the bundle and set `DAE_WEB_ROOT` in the daemon's service environment:

```sh
DAE_WEB_ROOT=/opt/dae-web dae run -c /etc/dae/config.dae
```

Assets are read on each request. Replace the complete bundle directory when updating; missing files return `404`. The entire directory and its subdirectories are public; put only frontend assets there. New JS, CSS and nested assets require no daemon routing changes. The API handler takes precedence for `/api/` and certificate download paths.

The Web address remains `http://ROUTER_IP:<api_port>/`. The daemon serves these files on the API origin, preserving browser origin checks and the caller's direct LAN identity. Building the bundle separately does not enable `file://`, arbitrary cross-origin hosting or ordinary reverse proxies for device self-service. Forwarding headers cannot impersonate a device.

`make` and `make test` run `make web-assets` to build the frontend and replace `internal/webui/assets/` with its output before compiling Go. Generated bundles are ignored by Git; only `web/src/` is edited. When invoking `go build` or tests of `internal/webui` or `cmd` directly, first run `make web-assets` alongside the usual daemon build prerequisites. Client-only builds and tests do not need this step.

`dae plugins status`, plugin status commands and the standalone client share API connection options and report rendering. Select the connection with `--api`, `--timeout`, `DAE_API_ENDPOINT` and `DAE_API_KEY`; filter reports with `--instance`. The standalone client provides `plugins status` for any plugin report and `plugins surge status` for Surge tables without loading runtime plugins. Report commands emit the filtered instance array with `--json`; `status --json` emits the complete daemon snapshot.

The port is bound once: `internal/apiserver` creates one TCP listener and `http.Server`. In `cmd/api_server.go`, `http.ServeMux` dispatches `/api/` and the three certificate download paths to the internal/apiserver handler, and all remaining paths to the static file handler. Browser calls such as `fetch("/api/...")` use the page's protocol, address and port, so no separate Web server is needed. The Unix socket mounts only the API handler and does not serve pages.

## Architecture

| Directory | Responsibility |
| --- | --- |
| `api` | Plain public wire models and network order; standard library only |
| `api/client` | Concurrent reusable HTTP/Unix client, authentication, JSON and typed errors |
| `client/status` | Shared snapshot rendering, MITM summaries and Surge report decoding/display, without runtime access |
| `client/cli` | Shared API connection options, instance filtering and status commands |
| `web` | Frontend source, browser requests and independent build |
| `internal/webui` | Embedding and static serving of frontend build output |
| `cmd/dae-client` | Independently buildable entry point |
| `internal/apiserver` | TCP/Unix listeners, reload draining, HTTP routing, authorization and validation; runtime access through stores |
| `control` | Runtime projection, LAN identity, settings application and persistence |

Runtime and client code use `api` types directly. `internal/apiserver` owns the server-side protocol and transport without importing the control plane, clients or frontend. `handler.go` registers API routes; `auth.go` authorizes Unix, LAN and key/session access; `session.go` handles login/logout and signed cookies; `request.go`, `device.go` and `selectors.go` validate and handle operations; `server.go` and `unix.go` own listener lifecycle. The control plane supplies the stores defined in `state.go`. `control` does not import UI packages; the daemon command layer composes the Web routes. Unix and TCP use the same API handler, and reloads drain old requests before retiring the control plane.

The frontend boundary consists of its public build output and the HTTP API contract. `web/` builds without reading its parent directory, so it can later move into a separate repository or submodule while the embedding and routing code stays in dae.

`make client-test` runs tests with CGO disabled, checks OpenAPI against the Go wire types and rejects transitive imports of daemon implementation packages. CI runs it before installing clang or generating eBPF. TUI navigation, sorting, polling and presentation belong in client packages; only new runtime data or operations require daemon changes.

## API reference

The [OpenAPI 3.1 document](../../api/openapi.json) describes all operations and fields. Edit it directly; `make client-test` checks fields, required properties, types and array lengths against the Go contract. See [API configuration](api.md) for persistence and routing semantics, and the [detailed Chinese reference](../../zh/configuration/api-client.md) for field explanations and a complete Go example.

| Operation | Response / requirement |
| --- | --- |
| `GET /api/status` | `StatusSnapshot`; TCP uses the configured key/session or verified direct LAN identity when no key is configured; Unix uses filesystem permissions |
| `GET /api/selectors` | `SelectorsResponse`; administration required; `auth_mode` is `api_key`, `lan` or `unix` |
| `PUT` / `DELETE /api/session` | Browser login / clear cookie; `204`, empty body; keyless login verifies LAN/Unix access and clears stale cookies without issuing a session |
| `PUT /api/selectors/{group}` | `SelectorState`; admin, `{"node_id":"..."}` |
| `DELETE /api/selectors/{group}` | Restore explicit `selector(n)`; admin, empty body; `409` without a default |
| `POST /api/probes` | `202` + `ProbeResponse`; admin, `{"outbound":"group","node_id":"..."}`; omit or leave `node_id` empty for the entire outbound |
| `GET /api/device` | `DeviceState`; direct identifiable LAN caller, TCP only |
| `GET /api/device/status` | `DeviceStatus`; MAC-attributed upstream traffic, connections and used outbounds for the direct LAN caller |
| `POST /api/device/certificate-tests` | `201` + `CertificateTest`; empty body, creates a short-lived browser challenge |
| `GET /api/device/certificate-tests/{id}` | This device's observations; `404` after expiry or configuration replacement |
| `PUT` / `DELETE /api/device/sets/{name}` | Join / leave a set; empty body |
| `PUT /api/device/mitm` | Explicit override, `{"enabled":true}` or `{"enabled":false}` |
| `DELETE /api/device/mitm` | Restore configuration; empty body |
| `GET /api/certificate` | Public CA name, SHA-256 fingerprint, `test_available` and optional `test_generation` |
| `GET /ca.pem`, `/ca.cer`, `/ca.mobileconfig` | Public certificate downloads, `404` when unavailable |

All PUT and DELETE requests require `X-Dae-API: 1`; the SDK supplies it. MITM changes require `X-Dae-MITM: <current CA SHA-256 fingerprint>`. If `global.api_key` is configured, TCP administration (including LAN selector reads) requires `Authorization: Bearer <api_key>` or a valid session; missing/incorrect credentials return `401`. The Go SDK accepts `client.Options.APIKey`. Without a configured key, each TCP administration request must pass the direct LAN ingress and neighbor checks, otherwise it returns `403`; credentials are not required. Browsers in key mode may use the seven-day session cookie issued by `PUT /api/session`; `DELETE /api/session` clears it. Both session operations use empty bodies and return `204` on success; keyless access never issues a session. Filesystem-authorized Unix clients have administrative access but cannot perform LAN device self-service.

URL-encode names as path segments. Bodies are limited to 1 KiB; JSON requires `Content-Type: application/json`, and other requests must have empty bodies. API query parameters are rejected. Browsers must use the same origin; TCP Host must match the literal router address and listener port. GET routes also accept HEAD.

Successful state operations return `200`; probes return `202` with accepted targets; session operations return `204` without a body. POST also requires `X-Dae-API: 1`, supplied by the SDK. Application errors have `{"error":"message"}`; route/method errors and some certificate errors may be plain text. Treat the HTTP status as the contract, rather than matching error text: `400` invalid input; `401`/`403` authorization; `404`/`405` resource/method; `409` changed CA, absent selector default, or unsupported probe target; `413`/`415` body size/media type; `500` application or persistence failure; `503` startup/reload.

The device SDK exposes `DeviceStatus(ctx)`, `StartCertificateTest(ctx)` and `CertificateTest(ctx, id)`. The last two create/read a challenge; its HTTPS requests must originate in the browser being tested. Validate the returned `CertificateTestProof` ID, fingerprint and stage together with same-origin observations. Discard results when `test_generation` changes. A server observation alone is not a device-wide trust verdict.

## Snapshot semantics and TUI integration

The current status schema is `12`. Top-level `direct_fallback_connections` contains the single direct fallback counter; `PathStats` contains active/total connections, payload totals and history without fallback fields. Prometheus exports `dae_fallback_connections_total` as one unlabeled process counter. Domain table `limit: 0` means unbounded userspace retention; `breakdown.gc` counts time-collected pairs. Kernel `candidates` reports IPs eligible before capacity selection. Plugin state is carried in `plugins`; optional `details` contains the plugin-defined report. Surge reports contain `enabled` and `modules`, and the standalone Surge command combines these reports by instance. There is no top-level `surge` field. Clients tolerate additive response fields and reject unsupported schemas, null responses, duplicate keys and type errors. Unknown request fields are invalid. Breaking changes require a new schema version. The status endpoint is `/api/status`.

Node latency statistics contain successful probes only. Automatic selection exposes `selection` with the group-local role (selected, monitoring or standby), effective priority, signed score, verified recovery duration and measurement time. Failed nodes show `[degraded]`; `[recover 5s/30s verified]` appears after the first recovery success and advances only on successful probes. The state column also shows active verification, queueing or the actual next recheck countdown during recovery observation. Node `dormant` denotes physical sleep, shown once in the state column with historical latency age. Standby paths may share monitoring from other groups; `recovery` reports actual check/retry progress. See [outbound selection](outbound-selection.md).

Registry `used` counts domain-IP pairs. Its `breakdown.domains`, `ips`, `ipv4` and
`ipv6` describe distinct retained names and addresses; IPs shared by multiple names
count once, and `ips = ipv4 + ipv6`. The CLI labels these quantities separately
from kernel residency and capacity omissions.

Schema 10 requires these registry counts. Upgrade the daemon and CLI together;
schema 9 responses without the counts are rejected instead of displaying zeros.

`groups[].nodes[].revision` identifies the node state revision. `observed_session_seq` and optional `session_detail` describe the observed session and its resource identity. `recovery` exposes the executor, phase, verification and attempt count; `retry_at` appears only when an actual backoff timer exists. Clients must not infer a countdown for library-managed recovery. Optional `failure` identifies the failure source and resource so a TUI can distinguish current recovery from the most recent failure.

Status is an observational snapshot, not a transaction across all subsystems. Health checks and node selection may update at different times. Clients accept transitional health differences; server tests check field invariants.

Network arrays always contain four entries ordered `tcp4`, `tcp6`, `udp4`, `udp6`. Node IDs are opaque identifiers, and an empty selected node ID means no currently selected node. Network support (`unknown`, `confirmed`, `unsupported`) describes capability separately from health.

Timestamps use RFC 3339, with Go's zero time indicating no observation. Durations are integer nanoseconds; selector `latency_ms` uses milliseconds. Availability ratios are time-weighted values from 0 to 1; `seen=false` means no valid observation.

Traffic totals are bytes. Each traffic history contains up to 12 completed five-second byte/second averages, oldest first, with equal lengths for upload and download. Counters survive reloads and reset on process restart. JavaScript consumers needing exact 64-bit counters must account for precision above `2^53-1`.

Checked groups have ten six-minute history buckets over the last hour, oldest first. Each bucket records the worst observed state: unavailable, available, or unknown if unobserved. Unchecked groups have no connectivity history.

Create an `api/client.Client`, reuse it across requests, and pass cancelable contexts. Use `Status`, `Selectors`, `SelectNode`, `ResetSelector`, `Probe`, `Device`, `SetMembership`, `SetMITM`, `ResetMITM` and `Certificate` as needed. `SetMITM(ctx, false, fingerprint)` explicitly disables it; `ResetMITM(ctx, fingerprint)` restores configuration.

`Probe(ctx, api.ProbeRequest{Outbound: "group", NodeID: "..."})` requests a one-shot probe. Empty/omitted NodeID targets the whole outbound. `ProbeResponse` contains `outbound` and accepted `node_ids`; `202` includes coalescing with queued/running checks, not a completed test result. It uses configured DNS probes, timeouts and concurrency bounds for any instantiated, checked outbound. Arbitrary URLs and per-request probe configuration are not supported. Poll selectors for selector results, and status for other outbound health/latency.

`SelectorState.track_all` is read-only group configuration; when true, the UI shows continuous monitoring instead of test buttons. There is no mutation API. `default_node_id` is present only for explicit `selector(n)`; hide default badges and reset controls when absent. Candidate `tested` distinguishes untested from failed, `checking` indicates queued/running work, `tracking` indicates continuous monitoring, and optional `checked_at` is the last completion time in RFC 3339. Untracked results are historical, not a continuous health guarantee.

Use `errors.As` with a `*client.Error` variable to inspect `StatusCode`. Poll at a suitable interval, such as two seconds; keep the last snapshot and back off on `503`. No push stream or cross-request transaction is currently provided. The library does not retry writes: after a timeout, query the current state before deciding whether to repeat an operation.
