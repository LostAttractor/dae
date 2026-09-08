# API and independent clients

`dae status`, its `--verbose` and `--recent` modes, and `dae mitm surge status` read runtime state through the same API client. The Web application communicates through HTTP APIs.

## Build and connect

With Go 1.27+ (or inside `nix-shell`):

```sh
make client
sudo ./dae-client status
./dae-client status --api http://192.168.1.1:9080 --recent
./dae-client mitm status --api http://192.168.1.1:9080 --json
./dae-client mitm status --api http://192.168.1.1:9080 --verbose
./dae-client mitm surge status --api http://192.168.1.1:9080 --instance personal
./dae-client status --api unix:///var/run/dae.sock --json
```

`make client` runs `CGO_ENABLED=0 go build -trimpath -o dae-client ./cmd/dae-client`. It needs no eBPF generation, clang, kernel headers, native runtime or daemon submodules. Go dependencies must already be cached or downloadable. Cross-compilation is supported, for example `GOOS=darwin GOARCH=arm64 make client`.

| Option | Meaning |
| --- | --- |
| `--api` | Defaults to `DAE_API_ENDPOINT`, then `unix:///var/run/dae.sock` |
| `--timeout` | Request timeout, default `10s` |
| `DAE_API_TOKEN` | Bearer token for TCP administration; kept out of URL and command arguments |
| `--json` | `status`: full snapshot, mutually exclusive with `--verbose` and `--recent`; MITM report commands: filtered instance array |

The Unix socket remains mode `0600` and is available regardless of `global.api_port`. Neither command entry point elevates privileges automatically; use `sudo` or existing filesystem permission for the local socket.

Enable the [TCP API](api.md) and set `DAE_API_TOKEN` before requesting remote status. Clients bypass environment proxies and reject redirects. The daemon serves HTTP; HTTPS support in the Go client does not add TLS or reverse-proxy support to the daemon.

The Go SDK owns its transport and does not depend on application changes to `http.DefaultTransport`. Successful responses are limited to 32 MiB and error bodies to 8 KiB. Oversized error bodies still preserve the HTTP status in `client.Error.StatusCode`.

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

`dae mitm status`, plugin status commands and the standalone client share API connection options and report rendering. Select the connection with `--api`, `--timeout`, `DAE_API_ENDPOINT` and `DAE_API_TOKEN`; filter reports with `--instance`. The standalone client provides `mitm status` for any plugin report and `mitm surge status` for Surge tables without loading runtime plugins. Report commands emit the filtered instance array with `--json`; `status --json` emits the complete daemon snapshot.

The port is bound once: `internal/apiserver` creates one TCP listener and `http.Server`. In `cmd/api_server.go`, `http.ServeMux` dispatches `/api/` and the three certificate download paths to the component/api handler, and all remaining paths to the static file handler. Browser calls such as `fetch("/api/...")` use the page's protocol, address and port, so no separate Web server is needed. The Unix socket mounts only the API handler and does not serve pages.

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
| `component/api` | HTTP routing, authorization and validation over public wire models |
| `control` | Runtime projection, LAN identity, settings application and persistence |

Runtime and client code use `api` types directly. `internal/apiserver` manages both listeners and request draining without depending on the control plane or frontend. `control` does not import UI packages; the daemon command layer composes the Web routes. Unix and TCP use the same API handler, and reloads drain old requests before retiring the control plane.

The frontend boundary consists of its public build output and the HTTP API contract. `web/` builds without reading its parent directory, so it can later move into a separate repository or submodule while the embedding and routing code stays in dae.

`make client-test` runs tests with CGO disabled, checks OpenAPI against the Go wire types and rejects transitive imports of daemon implementation packages. CI runs it before installing clang or generating eBPF. TUI navigation, sorting, polling and presentation belong in client packages; only new runtime data or operations require daemon changes.

## API reference

The [OpenAPI 3.1 document](../../api/openapi.json) describes all operations and fields. Edit it directly; `make client-test` checks fields, required properties, types and array lengths against the Go contract. See [API configuration](api.md) for persistence and routing semantics, and the [detailed Chinese reference](../../zh/configuration/api-client.md) for field explanations and a complete Go example.

| Operation | Response / requirement |
| --- | --- |
| `GET /api/status` | `StatusSnapshot`; TCP admin token or filesystem-authorized Unix connection |
| `GET /api/selectors` | `SelectorsResponse`; public |
| `PUT /api/selectors/{group}` | `SelectorState`; admin, `{"node_id":"..."}` |
| `DELETE /api/selectors/{group}` | Restore configured selection; admin, empty body |
| `GET /api/device` | `DeviceState`; direct identifiable LAN caller, TCP only |
| `PUT` / `DELETE /api/device/sets/{name}` | Join / leave a set; empty body |
| `PUT /api/device/mitm` | Explicit override, `{"enabled":true}` or `{"enabled":false}` |
| `DELETE /api/device/mitm` | Restore configuration; empty body |
| `GET /api/certificate` | Public CA name and SHA-256 fingerprint |
| `GET /ca.pem`, `/ca.cer`, `/ca.mobileconfig` | Public certificate downloads, `404` when unavailable |

All PUT and DELETE requests require `X-Dae-API: 1`; the SDK supplies it. MITM changes require `X-Dae-MITM: <current CA SHA-256 fingerprint>`. TCP admin operations require `Authorization: Bearer <api_token>`: `403` if no token is configured, `401` if a configured token is missing or incorrect. Filesystem-authorized Unix clients have administrative access but cannot perform LAN device self-service.

URL-encode names as path segments. Bodies are limited to 1 KiB; JSON requires `Content-Type: application/json`, and other requests must have empty bodies. API query parameters are rejected. Browsers must use the same origin; TCP Host must match the literal router address and listener port. GET routes also accept HEAD.

Successful operations return `200` with current state. Application errors have `{"error":"message"}`; route/method errors and some certificate errors may be plain text. Treat the HTTP status as the contract, rather than matching error text: `400` invalid input; `401`/`403` authorization; `404`/`405` resource/method; `409` changed CA; `413`/`415` body size/media type; `500` application or persistence failure; `503` startup/reload.

## Snapshot semantics and TUI integration

The current status schema is `7`. Plugin state is carried in `mitm_plugins`; optional `details` contains the plugin-defined report. Surge reports contain `enabled` and `modules`, and the standalone Surge command combines these reports by instance. There is no top-level `surge` field. Clients tolerate additive response fields and reject unsupported schemas, null responses, duplicate keys and type errors. Unknown request fields are invalid. Breaking changes require a new schema version. The status endpoint is `/api/status`.

`groups[].nodes[].revision` identifies the node state revision. `observed_session_seq` and optional `session_detail` describe the observed session and its resource identity. `recovery` exposes the executor, phase, verification and attempt count; `retry_at` appears only when an actual backoff timer exists. Clients must not infer a countdown for library-managed recovery. Optional `failure` identifies the failure source and resource so a TUI can distinguish current recovery from the most recent failure.

Status is an observational snapshot, not a transaction across all subsystems. Health checks and node selection may update at different times. Clients accept transitional health differences; server tests check field invariants.

Network arrays always contain four entries ordered `tcp4`, `tcp6`, `udp4`, `udp6`. Node IDs are opaque identifiers, and an empty selected node ID means no currently selected node. Network support (`unknown`, `confirmed`, `unsupported`) describes capability separately from health.

Timestamps use RFC 3339, with Go's zero time indicating no observation. Durations are integer nanoseconds; selector `latency_ms` uses milliseconds. Availability ratios are time-weighted values from 0 to 1; `seen=false` means no valid observation.

Traffic totals are bytes. Each traffic history contains up to 12 completed five-second byte/second averages, oldest first, with equal lengths for upload and download. Counters survive reloads and reset on process restart. JavaScript consumers needing exact 64-bit counters must account for precision above `2^53-1`.

Checked groups have ten six-minute history buckets over the last hour, oldest first. Each bucket records the worst observed state: unavailable, available, or unknown if unobserved. Unchecked groups have no connectivity history.

Create an `api/client.Client`, reuse it across requests, and pass cancelable contexts. Use `Status`, `Selectors`, `SelectNode`, `ResetSelector`, `Device`, `SetMembership`, `SetMITM`, `ResetMITM` and `Certificate` as needed. `SetMITM(ctx, false, fingerprint)` explicitly disables it; `ResetMITM(ctx, fingerprint)` restores configuration.

Use `errors.As` with a `*client.Error` variable to inspect `StatusCode`. Poll at a suitable interval, such as two seconds; keep the last snapshot and back off on `503`. No push stream or cross-request transaction is currently provided. The library does not retry writes: after a timeout, query the current state before deciding whether to repeat an operation.
