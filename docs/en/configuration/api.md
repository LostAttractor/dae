# Management Page and Runtime API

See [API and independent clients](api-client.md) for standalone builds, TUI integration and wire semantics, and the [OpenAPI document](../../api/openapi.json) for machine-readable definitions.


```text
global {
  lan_interface: br-lan
  api_port: 9080
  api_key: 'replace-with-a-private-key'
}
group {
  manual {
    filter: subtag(my_sub)
    policy: selector
    # track_all: true  # Monitor every candidate; apply with dae reload
  }
}
client {
  work {
    description: 'Use the selected node to access work services'
  }
}
routing {
  client(work) && domain(suffix: example.com) -> manual
  fallback: direct
}
```

`global.api_port` defaults to `0`, disabling the listener. A nonzero port serves the HTTP page and API on all router addresses, independently of MITM plugins. Use the actual LAN IP, such as `http://192.168.1.1:9080/`. Domain names, reverse proxies, and cross-origin browser requests are unsupported. Reload after changing the port or router addresses.

## Usage and Persistence

`selector` continuously checks only the selected node by default; its startup barrier also waits only for that node. Switching immediately checks the new selection and pauses periodic checks on the old one. An in-flight test may finish. Automatic policies use the scope described in [outbound selection](outbound-selection.md).

Selectors use searchable dropdowns: the collapsed control shows the selected node, while the bounded, scrollable popup handles large lists and long names. By default, use **Test** beside the selected node or a candidate, or **Test All**. Each button requests one round of the group's configured DNS connectivity probe without changing selection or monitoring scope. Authorized, visible pages refresh results every two seconds. Untested nodes show **Not tested**.

Set `track_all: true` in a selector's group block and reload to continuously monitor every candidate; it defaults to false. This is configuration-only, with no mutation API or runtime preference. When enabled, the page shows **Monitoring all nodes** in place of every **Test / Test All** button. Checks use the group's interval settings; the startup barrier still waits only for the selected node. The option is selector-only and is not inherited through `group(name)`.

For selector groups, `dae status` (including verbose/JSON) includes only selected, monitored, currently testing, or actively connected nodes. Idle untracked candidates retain their last result in `/api/selectors` and the page. Group/global traffic totals still include those paths.

- **Selectors**: When `api_key` is configured, enter it in the top toolbar and click **Login** to view selector status or change nodes. Without a key, verified direct LAN clients can use selectors immediately; the toolbar shows **LAN access**. Plain `selector` has no configured default: restore a saved choice, otherwise initially select the first candidate, without a default badge or reset button. Only explicit `selector(n)`, including `selector(0)`, declares a default path index. Changes affect everyone using the group. Choices persist as independent logical path references; reordering, priority, TLS, multiplex, global mark and probe settings do not change them.
- **This Device**: Devices can join several `client(name)` MAC sets; routing order still applies. The API connection must traverse `global.lan_interface` ingress, and its observed source MAC must match a direct ARP/NDP neighbor. Interface patterns are supported; changing MAC requires joining again. Failed identification returns `403`; authenticated selector access and public certificate downloads remain available.
- **HTTPS Modules**: Device settings override `mitm.client_source_address`, including explicit disabling. Install and trust the CA before enabling; the page cannot detect trust.

Login stores a signed session in an `HttpOnly`, `SameSite=Strict` cookie for seven days; the API key itself is not stored in the cookie. Reloading the page or daemon preserves the session. **Logout** clears the browser cookie; changing `api_key` invalidates existing sessions. **Refresh** updates the displayed state and timestamp. Device self-service remains available without administrator login.

`global.api_key` is optional. When omitted or empty, status and selector administration use the same direct LAN identity checks as device self-service: current eBPF ingress evidence on `global.lan_interface` and a matching direct ARP/NDP neighbor. Each request is verified; a private source IP, forwarded header, or old session cookie is insufficient. WAN, routed peers and unidentifiable clients receive `403`. This mode needs no login and creates no session cookie. Configuring a key requires key/session authentication for TCP administration, including LAN callers. Unix socket administration uses filesystem permissions in either mode.

The configuration field is now `global.api_key` (formerly `global.api_token`). Update existing configurations when upgrading; CLI clients use `DAE_API_KEY` and the Go SDK uses `client.Options.APIKey`.

Identification uses TCP connection metadata recorded by eBPF at LAN ingress. The route or neighbor table's interface name does not need to match `lan_interface`. For `enp1s0f0np0 → lan (VLAN) → br-lan`, keep `lan_interface: lan`; bonds and other layered Ethernet interfaces use the same identification path. Each request updates the observed MAC and timestamp; configuration reloads clear observations. Missing observations, observations older than 30 seconds, indirect return routes, and MACs that do not match the ARP/NDP neighbor on the route's interface prevent device operations. The same IP on another interface does not affect identification.

The `client` block supplies the plain-text description used as the set's display label. When a description is provided, the page shows only that description; otherwise it shows the set name. Button accessibility labels and operation messages use the same display label. API requests still identify sets by their configuration names. Sets referenced by routing or configured for kernel export appear, and duplicate definitions are rejected. Descriptions update with `dae reload` without changing membership.

**Reset Default** is available for selectors only when `selector(n)` explicitly configures a default; it clears the saved selection and restores that path. Both selectors and HTTPS modules label their settings source **Default** or **Custom**. MITM reset still clears the device override. Settings persist in `$DAE_LOCATION_CACHE/runtime-state.json` (default `/var/lib/dae/runtime-state.json`, mode `0600`) across reloads, restarts, and API disabling. The main configuration is untouched. Existing connections and UDP sessions keep their paths.

References contain every hop's source and name, plus the entrance address family and explicit interface/mark. An omitted mark retains inheritance. Local nodes use configured names; subscription nodes use subscription tags and names, with a subscription-address fingerprint for untagged sources. Unique named nodes can follow address or credential updates. Link fingerprints disambiguate duplicates without storing links or credentials; a node chosen from duplicate source names must continue matching its fingerprint.

If a filter excludes the saved path, its entrance family temporarily disappears, or matching is ambiguous, the reference is retained while the explicit default or first candidate is used temporarily. The page displays **Temporary fallback**. A later reload restores a returning path. Choosing another node, including the current fallback, replaces the preference. Health-check failure alone does not clear or change the selection.

Manual file edits trigger reloads through filesystem events, including atomic replacements. Invalid contents, application failures, or a temporarily missing file preserve current state. For example:

```json
{
  "selectors": {},
  "clients": {"work": ["02:00:00:00:00:50"]},
  "mitm": {"02:00:00:00:00:50": true}
}
```

Keep all three objects; remove entries to clear overrides or memberships. Selector values are path objects with `nodes`, `ipversion`, `interface` and optional `mark`, not API runtime node IDs; use the page or `dae selector set` to save them. Use lowercase colon-separated MACs. Avoid concurrent file edits and API writes.

`track_all` is configured in the group block; runtime state cannot override it. Unknown fields in the runtime settings file are rejected.

## Exporting MAC Sets

Configure `ipset`, `nftset`, or both. Exported sets appear on the device page without a routing reference:

```text
client {
  work {
    description: 'Join the work device set'
    ipset: dae_work
    nftset: 'inet/filter/dae_work'
  }
}
```

`ipset` creates `hash:mac`. `nftset` takes `family/table/set` and creates `ether_addr`; families are `inet`, `ip`, `ip6`, `bridge`, `netdev`, and `arp`. Members are MACs, not resolved IPs or map values. Kernel support and `CAP_NET_ADMIN` are required; command-line tools are not.

Startup, configuration reloads, and membership changes synchronize the sets, attempting rollback on failure. Each backend updates atomically; the backends and dae routing do not share one transaction.

Use dedicated sets, never shared between clients. dae creates missing tables/sets and replaces all members without changing firewall rules. Existing sets must be plain MAC sets: ipset extensions and nft constant/interval/timeout/dynamic flags are unsupported; nft element counters reset on replacement. Shutdown or removing configuration retains the sets. Run `dae reload` after a firewall rebuild.

Inspect with `ipset list dae_work` or `nft list set inet filter dae_work`. Match with iptables `-m set --match-set dae_work src`, or `ether saddr @dae_work` within the same nft table.

## API

POST, PUT and DELETE requests require `X-Dae-API: 1`. JSON bodies require `Content-Type: application/json`; other requests use empty bodies. With a configured key, status and selector reads/writes require `Authorization: Bearer <api_key>` or a valid browser session cookie; without a key they require verified direct LAN identity. MITM writes require `X-Dae-MITM: <current CA SHA-256 fingerprint>`. In key mode, an explicit Authorization header takes precedence over the cookie. URL-encode names in paths. Command-line clients may omit `Origin`.

Keyless TCP administration returns `403` if LAN identification fails. With a configured key, a missing, incorrect or expired key/session returns `401`. Device self-service always requires direct LAN identification and does not require this key.

| Method and path | Behavior |
| --- | --- |
| `PUT /api/session` | With a configured key, login using `Authorization: Bearer <api_key>` and receive a session cookie; without a key, verify LAN/Unix access and clear stale cookies. Empty body, `204` on success |
| `DELETE /api/session` | Clear the browser session cookie; empty body, `204` on success |
| `GET /api/status` | Full runtime snapshot; TCP uses the configured API key/session, or verified direct LAN identity when no key is configured; Unix uses filesystem permissions |
| `GET /api/device` | Caller IP, MAC, sets (`name`, `description`, `joined`), and MITM state (`enabled`, `override`, `ca_fingerprint`); `403` for an unknown MAC |
| `PUT` / `DELETE /api/device/sets/{name}` | Join / leave a set |
| `PUT /api/device/mitm` | Enable with `{"enabled":true}`, or disable with `false` |
| `DELETE /api/device/mitm` | Restore configuration |
| `GET /api/selectors` | Requires administration; default/current node IDs, overrides, candidate health and latency; `admin_enabled` is true after authorization, and `auth_mode` is `api_key`, `lan` or `unix` |
| `PUT /api/selectors/{name}` | Select with `{"node_id":"ID from status"}` |
| `DELETE /api/selectors/{name}` | Restore explicit `selector(n)`; `409` if no default exists |
| `POST /api/probes` | `{"outbound":"manual","node_id":"node ID"}` probes one node; omit or leave `node_id` empty for the whole outbound; returns `202` with accepted node IDs |
| `POST /api/plugins/{instance}/scripts/run` | Requires administration; `{"module":"tools","script":"demo.tool"}` triggers a configured cron/generic task; returns `202` with its per-task run number and acceptance status |
| `GET /api/certificate` | CA name and SHA-256 fingerprint; `404` when unavailable |
| `GET /ca.pem`, `/ca.cer`, `/ca.mobileconfig` | Download the public certificate without MAC identification |

A `null` MITM `override` inherits the configuration. Fetch the corresponding status after changes. A changed CA causes MITM writes to return `409`; refresh the page, verify the fingerprint, and install and trust the current certificate.

`POST /api/probes` is the shared manual probe API for instantiated, checked outbounds, including selectors, automatic policies and direct node references. It uses configured DNS probes, timeouts and concurrency bounds; arbitrary URLs and per-request probe configuration are not accepted. `202` acknowledges acceptance, including coalescing with queued/running work; it is not a health result or persistent job, and changes neither selection nor `track_all`. Poll `/api/selectors` for selector `checking`, `tested`, `checked_at`, `healthy` and `latency_ms`; other outbounds publish runtime health and latency through `/api/status`. Unknown outbound: `404`; node outside that outbound: `400`; unchecked builtin: `409`.

`SelectorState.track_all` is read-only configuration. `default_node_id` is present only for explicit `selector(n)`; clients should hide default labels and reset controls when it is absent.

`node_id` identifies the actual runtime choice. A saved preference sets `overridden` to true and adds `saved_selection` with `name` and `status` (`matched`, `missing`, or `ambiguous`). Missing or ambiguous preferences remain saved while the startup choice is used temporarily; clients must not overwrite the preference with that actual `node_id`.

Script acceptance is asynchronous: execution uses the daemon's background routing client and continues after the response. Poll `plugins[].details.modules[].tasks` in `/api/status` for completion; `type` is `cron` or `generic`, `runs` identifies the latest attempt, and `last_trigger` is `cron` or `http-api`. Generic tasks have no schedule and are `ready` when idle. Only the latest attempt is retained, and counters/history reset on reload. Manual execution preserves cron's next scheduled time. Missing instance/task: `404`; ambiguous name without `module`: `400`; already waiting/running: `409`; inactive worker: `503`. No inline source or argument overrides are accepted. The API client does not retry execution requests.

Discover configured cron/generic scripts with `dae plugins surge list`; filter with `--instance` and `--module`, or use `--json` for a task array. Trigger with `dae plugins surge run demo.tool --instance surge --module tools`; both commands require a running daemon. `run --json` prints an acceptance snapshot; inspect plugin status for completion. CLI/API triggers use `last_trigger: http-api`. See the [manual execution guide](../../zh/configuration/surge-module.md#手动触发).

Surge reports retain up to 50 recent `$notification.post` messages **per script** within each instance, identified by module, script name and script type. `plugins[].details.notifications` contains all retained messages, newest first; the field is omitted when empty. Each entry contains `id`, `created_at`, `module`, `script`, `script_type`, `title`, `subtitle`, and `body`. Module/script names and title/subtitle are limited to 1024 UTF-8 bytes each, body to 4096; shortened entries have `truncated: true`. History is independent of log filtering and script success, and resets on reload. `dae plugins surge status` shows the latest 3 per script by default, with an omission count. `surge status --verbose` (`-v`), `plugins status -v`, and JSON show all retained messages.

The daemon status schema is 12, served at `/api/status` over the Unix socket `/var/run/dae.sock` for `dae status`, `dae plugins status` and plugin commands. It does not require `global.api_port`. Top-level `direct_fallback_connections` counts established no-connectivity fallbacks to direct across the process lifetime; path, group and node statistics contain no fallback field. Domain tables report time-based GC and kernel candidates; userspace `limit: 0` means unbounded. Registry `used` counts domain-IP pairs; its `breakdown` includes distinct `domains`, distinct `ips`, address-family counts `ipv4` / `ipv6`, and cumulative collected pairs `gc`. `plugins` contains instance IDs, types, host lifecycle states and rule counts. Optional `details` is defined by each plugin; Surge supplies `enabled` and `modules`. Node latency contains successful samples only; automatic groups expose degradation and selection scoring in `selection`. Use matching CLI and daemon versions.

`dae plugins status --json` prints complete plugin reports. `dae plugins <type> status --instance <ID>` selects one instance. Automatic plugin state excludes configuration credentials; notification fields retain explicit script-authored text under the same administration access controls.

Notification histories also share a conservative 1 MiB JSON budget per instance, charging worst-case text escaping. When full, the longest history loses its oldest entry first; ties remove the oldest entry. A script may therefore retain fewer than 50 messages. Verbose and JSON output include all messages remaining within this budget.
