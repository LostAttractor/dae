# Management Page and Runtime API

See [API and independent clients](api-client.md) for standalone builds, TUI integration and wire semantics, and the [OpenAPI document](../../api/openapi.json) for machine-readable definitions.

See [Decision explanations and client management](explain.md) for read-only routing/subsystem analysis, membership previews and administrative MAC management. The [access-control design](../design/api-access-control.md) describes trust boundaries and listener/session lifecycles.

```text
global {
  lan_interface: br-lan
}
api {
  listen: '9080'
  user_key: 'replace-with-a-user-key'
  admin_key: 'replace-with-a-different-admin-key'
  allow_lan_anonymous: true
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

## Access and connections

An empty `api.listen` disables TCP. The `0600` Unix socket `/var/run/dae.sock` always provides the API without API keys. A port such as `'9080'` binds the ingress interfaces matched by `global.lan_interface`, following interface additions and removals. An explicit IP is bypassed only while it is assigned locally. For IPv6 link-local addresses, use a bare port and `global.lan_interface`; explicit link-local addresses and `%zone` literals are rejected. Wildcards `'0.0.0.0:9080'` and `'[::]:9080'` follow Go's `tcp` socket selection and system capabilities: either may accept both IPv4 and IPv6; `0.0.0.0` does not imply IPv4-only. HTTP and HTTPS share this endpoint; HTTPS uses the persistent daemon CA independently of MITM. Native direct clients must use the listener's actual literal IP; domain-name endpoints require an HTTPS reverse proxy.

A port-only listener requires `global.lan_interface`. Interfaces enslaved to a bridge, bond or other master are rejected because local TCP delivery uses the master rather than the observed ingress port. Use an explicit API IP address to retain the existing ingress scope, or select the master only if all its ports are intended LAN ingress. If no interface currently matches, it waits without falling back to all addresses. Host address changes atomically update the shared address set used by API bypass and device-routing exemptions, without replacing the control plane or interrupting management services. Failed preparation or publication retains the previous set and is retried. Updating patterns for the same LAN endpoint retains sockets on shared interfaces. Binding-type changes that cannot reuse the listener may fail on a port conflict, preserving the old service; restart for those changes. For a port-only listener, both kernel routing and device exemptions require a local destination, the TCP port and a logical LAN ingress interface with an active listener socket. The address need not belong to the ingress interface. Failed hotplug binds due to temporary port contention are retried without another link event.

| Role | Authorization | Functions |
| --- | --- | --- |
| User | HTTPS `user_key` / `admin_key` or their session cookie; verified direct LAN ingress when `allow_lan_anonymous` is enabled | Global status, metrics, selector reads, CA downloads and trust checks; identified device's own settings, status and MITM checks |
| Administrator | HTTPS `admin_key` or its session cookie; filesystem-protected Unix socket | All user functions, selector mutations, probes, scripts, reload, resources, other-device management, explanations, impact previews and pprof |

Keys must differ. Without `admin_key`, remote administration is unavailable. Anonymous LAN access never grants administration. Neither key establishes a device identity: current-device routes still verify LAN ingress, with an Ethernet MAC required for device mutations. Administrators and Unix clients use explicit MAC management routes for other devices.

All management and monitoring over TCP requires HTTPS, including anonymous LAN access. With `allow_lan_anonymous` enabled, verified direct LAN clients may use HTTP only for CA metadata, downloads and challenge creation. The challenge proof always requires HTTPS. The HTTP page does not send credentials or load management controls. Otherwise export the CA over Unix and install it through a trusted channel.

`web_origins` is an exact origin allowlist for all browser API and monitoring requests, including requests with keys or cookies; the default permits same-origin requests only. Entries are HTTP(S) origins without paths, normalized for hostname case and default ports. **Same-origin** means identical scheme, host and port; **same-site** is the browser's scheme/site boundary and does not require identical ports. For example, a page at `https://192.168.1.1:8443` calling `https://192.168.1.1:9080` is same-site but cross-origin, and its page origin must be listed. Management requests marked `Sec-Fetch-Site: cross-site` are rejected even for listed origins; different LAN IPs do not become same-site merely by sharing a network. CLI and Prometheus raw-key calls without Origin are unaffected by browser-origin checks but still require authorization.

Only an original `user_key` or `admin_key` can log in over HTTPS. The response contains `{role, expires_at}` and sets `__Host-dae-session` with `Secure; HttpOnly; SameSite=Strict; Path=/` and no `Domain`. Sessions are signed for their role and API Host/port with an absolute seven-day expiry. Existing cookies, anonymous LAN access and implicit Unix administration cannot create or extend a session. The page sends management requests with `credentials: include`, without saving the original key or exposing session credentials to JavaScript. Logout calls `DELETE /api/session` to clear the cookie, including an expired one; copied sessions remain valid until expiry or rotation of the corresponding key.

Cookies are not isolated by port: other HTTPS services on the same hostname/IP must be trusted; prefer a dedicated management hostname. Tabs in the cookie's scope share login state. Explicit Authorization takes precedence: an invalid key does not fall back to a cookie, an invalid cookie does not fall back to anonymous LAN access, and a valid raw key can replace an expired session.

An independent page's API target is fixed by `DAE_API_URL` at development/build time, defaulting to relative `/api/`; there is no runtime address selector. Supported deployments are same-site direct access or a same-origin HTTPS reverse proxy. Both proxy hops use TLS; the proxy verifies the dae CA, rewrites Host to the actual API IP:port, preserves the page Origin listed in `web_origins`, and unconditionally sets `X-Dae-Proxy: 1`. This marker and forwarding headers only remove capabilities: they never lend the proxy's LAN/MAC identity to its clients. Anonymous access, self/device routes and browser CA/MITM verification are unavailable through the proxy; key/cookie management, explicit-MAC administration and CA downloads remain available. HTTP or Unix upstreams are prohibited. See the [minimal proxy example](api-client.md#same-origin-https-reverse-proxy).

`api.web` defaults to `true`; `make WEBUI=n` excludes static pages from the daemon. See [independent clients](api-client.md) for static hosting. `/metrics` is always a user API with no separate switch. `api.pprof` defaults to `false`; enabling it exposes `/debug/pprof/` with administrator authorization.

## Usage and Persistence

`selector` continuously checks only the selected node by default; its startup barrier also waits only for that node. Switching immediately checks the new selection and pauses periodic checks on the old one. An in-flight test may finish. Automatic policies use the scope described in [outbound selection](outbound-selection.md).

Selectors use searchable dropdowns: the collapsed control shows the selected node, while the bounded, scrollable popup handles large lists and long names. By default, use **Test** beside the selected node or a candidate, or **Test All**. Each button requests one round of the group's configured DNS connectivity probe without changing selection or monitoring scope. Authorized, visible pages refresh results every two seconds. Untested nodes show **Not tested**.

Set `track_all: true` in a selector's group block and reload to continuously monitor every candidate; it defaults to false. This is configuration-only, with no mutation API or runtime preference. When enabled, the page shows **Monitoring all nodes** in place of every **Test / Test All** button. Checks use the group's interval settings; the startup barrier still waits only for the selected node. The option is selector-only and is not inherited through `group(name)`.

For selector groups, `dae status` (including verbose/JSON) includes only selected, monitored, currently testing, or actively connected nodes. Idle untracked candidates retain their last result in `/api/selectors` and the page. Group/global traffic totals still include those paths.

- **Selectors**: Users can read status; administrators can select, reset and trigger probes. Plain `selector` has no configured default: restore a saved choice, otherwise initially select the first candidate, without a default badge or reset button. Only explicit `selector(n)`, including `selector(0)`, declares a default path index. Changes affect everyone using the group. Choices persist as independent logical path references; reordering, priority, TLS, multiplex, global mark and probe settings do not change them.
- **This Device**: Devices can join several `client(name)` MAC sets; routing order still applies. The API connection must traverse `global.lan_interface` ingress, and its observed source MAC must match a direct ARP/NDP neighbor. Interface patterns are supported; changing MAC requires joining again. Failed identification returns `403`; authorized selector reads and certificate downloads remain available.
- **This Device Status**: Active/total connections, upload/download totals, recent rates and used outbounds for the visiting device. IPv4/IPv6 share the ingress MAC identity; administrator login is unnecessary. These are userspace upstream counters, including splice acceleration, excluding kernel passthrough, local HTTP/DNS responses and daemon-originated work. Totals survive reload. Devices with no active connections are retired after their last minute of history expires; returning devices start a new observation period identified by `started_at`. Process restart resets all counters.
- **Global Status**: Version, uptime, global connections/traffic, outbound/node state, domain tables and plugins. User authorization applies; logout clears data when anonymous LAN access is unavailable.
- **HTTPS Modules**: Choose **Router default**, **On** or **Off** for this device. **Router default** follows `mitm.client_source_address` and shows its current value; **On** and **Off** override it, including explicit disabling. [Install and trust the CA](certificate.md) before turning modules on: without it, the device's HTTPS connections fail. The section warns until this browser verifies the CA. While modules are on, the page tests the CA by itself and shows a red alert when verification fails. **Test certificate** separately checks CA acceptance by this browser and the transparent MITM path.

Visible pages refresh device and authorized global state every two seconds. Rates use five-second samples covering up to one minute. Hidden pages pause polling; failed reads display their retry state.

The Web UI displays an IP connection and its ingress interface when no Ethernet identity exists. Current-connection context remains available; read-only explanations additionally require administrator access. Device traffic, MAC-set membership changes and comparisons, per-device MITM preferences and MITM tests require a verified Ethernet MAC; administrator login does not supply one.

Ingress observations contain TCP endpoints, link type, timestamp and interface indices. Records must be younger than 30 seconds and their LAN hook must still be attached. New datapath generations start with an empty observation map; reloads retaining the datapath retain its observations. IPv6 link-local endpoint zones must correspond to observed ingress, following receive direction through VLANs, bridges or bonds. For `enp1s0f0np0 → lan (VLAN) → br-lan`, keep `lan_interface: lan` and set `api.listen` to an explicit IP:port rather than a bare port. Ethernet device identity additionally rejects indirect return routes and MACs that do not match the route interface's ARP/NDP neighbor.

The `client` block supplies the plain-text description used as the set's display label. When a description is provided, the page shows only that description; otherwise it shows the set name. Button accessibility labels and operation messages use the same display label. API requests still identify sets by their configuration names. Sets referenced by routing or configured for kernel export appear, and duplicate definitions are rejected. Descriptions update with `dae reload` without changing membership.

For administrators, expanding a membership shows **Referenced** rules, without evaluating a destination or changing membership. Collapsed rules show a compact policy indicator: green for **Applies**, gray for **Does not apply**, and amber for **Unknown**. Its accessible label and hover text identify the policy and state. Expanded details show **Rules** and the full **Policy** badge in a separate row. The API field `policy_match` describes policy selection independently of the rule's `match`; an applicable policy still requires the rule's conditions and execution order to be evaluated. Missing ingress with multiple active policies leaves applicability unknown. Shared fragments retain each policy occurrence; global system or plugin references appear once. DNAT expressions retain the target IP and optional port. Predicate details show their values before and after the proposed membership change. **Compare a target** evaluates complete conditions and rule order for a specified flow; its **Uncertain** results indicate that the available context does not establish a complete decision.

**Reset Default** is available for selectors only when `selector(n)` explicitly configures a default; it clears the saved selection and restores that path. Both selectors and HTTPS modules label their settings source **Default** or **Custom**. MITM reset still clears the device override. Settings persist in `$DAE_LOCATION_CACHE/runtime-state.json` (default `/var/lib/dae/runtime-state.json`, mode `0600`) across reloads, restarts, and API disabling. The main configuration is untouched. Existing connections and UDP sessions keep their paths.

References contain every hop's source and name, plus the entrance address family and explicit interface/mark. An omitted mark retains inheritance. Local nodes use configured names; subscription nodes use subscription tags and names, with a subscription-address fingerprint for untagged sources. Unique named nodes can follow address or credential updates. Link fingerprints disambiguate duplicates without storing links or credentials; a node chosen from duplicate source names must continue matching its fingerprint.

If a filter excludes the saved path, its entrance family temporarily disappears, or matching is ambiguous, the reference is retained while the explicit default or first candidate is used temporarily. The page displays **Temporary fallback**. A later reload restores a returning path. Choosing another node, including the current fallback, replaces the preference. Health-check failure alone does not clear or change the selection.

Manual file edits trigger reloads through file system events, including atomic replacements. Invalid contents, application failures, or a temporarily missing file preserve current state. For example:

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

## Certificate and MITM tests

With the page enabled, HTTP and HTTPS share the page/API on `api.listen`. Browser CA/MITM verification requires a direct connection to dae; proxy deployments show it as unavailable, because a proxy's TLS handshake cannot prove the browser trusts dae's CA. CA trust testing uses a newly issued server certificate and a short-lived challenge without requiring MITM or a device MAC. Transparent verification additionally requires MITM enabled in the daemon and for this device. Transparent-MITM testing uses virtual destinations on port 443, configured by `api.mitm_test_ipv4` (default `203.0.113.254`) and `api.mitm_test_ipv6` (default `2001:db8:ffff::254`). Neither test needs an extra listening port or an upstream service.

Expand **Certificate & browser verification** to access **Test certificate** and the **Download** menu with the configuration profile, DER and PEM formats. The page also runs the test when it finds HTTPS modules on for this device, when they are turned on and when the device or CA changes:

1. The browser sends an authorized `POST /api/certificate/tests`, issuing a temporary certificate and new key held only in memory. It then reads `/api/certificate/tests/{id}` over HTTPS at the same IP and port. The server requires a handshake using this or a newer challenge certificate for the initiating source/router IP pair. Connections using the management certificate or an older challenge receive `409` and close so the browser can retry. The page checks the challenge ID and CA fingerprint before showing **CA trusted by this browser**. There is no need to open the HTTPS page or accept a certificate warning first.
2. If the first step succeeds and MITM is enabled for the device, the browser visits the virtual IP of the same address family through normal kernel capture, device admission and TLS decryption. The built-in `dae-mitm-test` plugin checks the ingress MAC and answers locally, without dialing an upstream. Different source IPs selected by the same device for the router and virtual destination are supported.

Choose unused virtual addresses whose traffic reaches dae. They must be outside local subnets and other software's Fake IP pools; local subnet overlap is rejected. Do not assign these addresses to a router interface. Networks that discard the default documentation ranges before reaching dae need different configured addresses or routing. Capture is limited to the two exact IPs on port 443; API traffic remains kernel-direct, and unrelated traffic keeps its normal routing behavior.

Tests do not change the persistent management certificate, CA, MITM certificate cache or device settings. A successful proof consumes its trust challenge; unfinished challenges expire after one minute. At most 8 trust challenges may be pending per source IP and 64 globally; excess requests return `429`. The temporary certificate includes five additional minutes of validity for client clock skew, capped by CA expiry; this does not extend the challenge deadline. Each challenge owns its temporary certificate. Once no challenges remain for the source/router IP pair, new connections use the original management certificate again. Clients sharing a source IP share this temporary selection; other source IPs are unaffected. MITM challenges and observations are retained for one minute, with at most 8 per verified MAC and 256 globally; excess creation requests return `503`. Replacing the CA invalidates trust challenges, while publishing MITM configuration invalidates interception challenges. A changed CA fingerprint clears both results; changes to the MITM test generation, device identity or setting clear only interception results. Results include a time and fingerprint and apply only to the current browser, not every application on the device. An exception previously accepted for the management certificate cannot validate a challenge certificate. Users relying on that exception may temporarily lose new HTTPS connections while a challenge is pending and can use the HTTP setup page to install and trust the CA. **Verification incomplete** means the browser could not complete verification; certificate rejection, network failures and some browser-policy failures are indistinguishable to page JavaScript.

Use the literal router IPv4 or non-link-local IPv6 API address. Challenges accept only their initiating page Origin, including independent pages. Clients validate the advertised test origins, proof ID and CA fingerprint. Replacing the CA prevents old TLS connections from reading the new identity's metadata; reloads with the same CA preserve connections. Both proofs represent only the invoking browser or CLI trust store.

## API

JSON API mutations require `X-Dae-API: 1`; JSON bodies require `Content-Type: application/json`. MITM changes also require `X-Dae-MITM: <current CA SHA-256 fingerprint>`. URL-encode path names; JSON APIs reject query parameters. Missing or invalid credentials return `401`; insufficient privileges or unverifiable device identity return `403`. Authorization precedes body and resource access. pprof retains standard tool formats and query parameters.

| Method and path | Behavior |
| --- | --- |
| `PUT /api/session` | Original HTTPS Bearer key → `200` JSON `{role, expires_at}` and an HttpOnly session cookie; existing sessions, anonymous LAN and implicit Unix access cannot log in |
| `DELETE /api/session` | Empty body, `204`; clears the session cookie without revoking copied sessions |
| `GET /api/status` | User: global runtime status |
| `GET /api/device` | Caller IP, MAC, sets (`name`, `description`, `joined`), and MITM state (`enabled`, `override`, `default`, `ca_fingerprint`); `403` for an unknown MAC |
| `GET /api/device/status` | Caller device state and MAC-attributed userspace upstream statistics; verified direct LAN only |
| `POST /api/device/mitm-tests` | Empty body; `201` with browser challenge URLs; does not change MITM settings |
| `GET /api/device/mitm-tests/{id}` | This device's observations; `404` for expired, replaced or foreign challenges |
| `PUT` / `DELETE /api/device/sets/{name}` | Join / leave a set |
| `PUT /api/device/mitm` | Enable with `{"enabled":true}`, or disable with `false` |
| `DELETE /api/device/mitm` | Restore configuration |
| `GET /api/selectors` | User: selector status; `admin_enabled` permits mutations; `auth_mode`: `user_key`, `admin_key`, `lan`, `unix` |
| `PUT /api/selectors/{name}` | Select with `{"node_id":"ID from status"}` |
| `DELETE /api/selectors/{name}` | Restore explicit `selector(n)`; `409` if no default exists |
| `POST /api/probes` | `{"outbound":"manual","node_id":"node ID"}` probes one node; omit or leave `node_id` empty for the whole outbound; returns `202` with accepted node IDs |
| `POST /api/plugins/{instance}/scripts/run` | Requires administration; `{"module":"tools","script":"demo.tool","mac":"02:00:00:00:00:50"}` triggers a configured cron/generic task; returns `202` with its per-task run number and acceptance status |
| `POST /api/plugins/{instance}/store/migrate` | Requires administration; `{"from_mac":"02:00:00:00:00:11","to_mac":"02:00:00:00:00:22"}` moves one device storage partition; synchronous `200` with `instance`, canonical MACs and `keys_moved`, never values |
| `POST /api/resources/refresh` | Administrator; empty body, refresh resources from the accepted configuration; returns `202` and an operation ID |
| `GET /api/resources` | Administrator; latest API/automatic refresh operation and next scheduled check |
| `POST /api/operations` | Administrator; submit reload, suspend or refresh; returns `202` and a unique operation ID |
| `GET /api/operations/{id}` | Administrator; operation status; `404` for unknown or expired IDs |
| `GET /api/certificate` | CA name, SHA-256 fingerprint, and optional `mitm_test_generation` and `mitm_test_origins`; `404` when unavailable |
| `POST /api/certificate/tests` | `201` with a one-minute CA trust challenge and a temporary certificate held in memory; preserves the management certificate; TCP API only, no MAC or MITM required |
| `GET /api/certificate/tests/{id}` | HTTPS only; a challenge handshake returns `id`, `ca_fingerprint` and `expires_at` and consumes the challenge; management or older challenge connections receive `409` and close for retry; consumed or expired challenges return `404` |
| `GET /api/certificate/ca.pem`, `/api/certificate/ca.cer`, `/api/certificate/ca.mobileconfig` | Download the public certificate without MAC identification |

A `null` MITM `override` inherits the configuration; `default` is that configured value for the device, which applies again after the override is cleared. Fetch the corresponding status after changes. A changed CA causes MITM writes to return `409`; refresh the page, verify the fingerprint, and install and trust the current certificate.

`POST /api/probes` is the shared manual probe API for instantiated, checked outbounds, including selectors, automatic policies and direct node references. It uses configured DNS probes, timeouts and concurrency bounds; arbitrary URLs and per-request probe configuration are not accepted. `202` acknowledges acceptance, including coalescing with queued/running work; it is not a health result or persistent job, and changes neither selection nor `track_all`. Poll `/api/selectors` for selector `checking`, `tested`, `checked_at`, `healthy` and `latency_ms`; other outbounds publish runtime health and latency through `/api/status`. Unknown outbound: `404`; node outside that outbound: `400`; unchecked builtin: `409`.

The server computes `health` consistently for status and selector nodes: `unknown` (unchecked or unobserved), `healthy`, `confirming` (failure confirmation in progress), or `unhealthy`. Dormant nodes retain their latest health observation; the `healthy` boolean still describes current runtime availability. Node `support` reports learned capability per network and `failing` marks confirmed networks whose latest probe failed; a failing network serves nothing until a probe succeeds, while its capability stays confirmed. Group `health` is `healthy`, `warning`, or `degraded`. Clients render `health` directly; `checking` separately describes probe activity.

`SelectorState.track_all` is read-only configuration. `default_node_id` is present only for explicit `selector(n)`; clients should hide default labels and reset controls when it is absent.

`node_id` identifies the actual runtime choice. A saved preference sets `overridden` to true and adds `saved_selection` with `name` and `status` (`matched`, `missing`, or `ambiguous`). Missing or ambiguous preferences remain saved while the startup choice is used temporarily; clients must not overwrite the preference with that actual `node_id`.

Script acceptance is asynchronous: `status.scope` identifies the effective scope, and only device scope includes `status.mac`. Omitted request `mac` always means local execution, even with exactly one eligible LAN device. Local execution needs no LAN discovery, MITM or CA. Explicit MAC is allowed only for scripts with LAN isolation enabled and selects a currently MITM-enabled device. Cron runs once locally and, when isolated, once per enabled LAN MAC; shared scripts run only once locally. Explicitly enabled MACs need not be online; all/IP/CIDR enumerate only host-known LAN devices. Background HTTP always uses daemon routing, and execution continues after the response.

Poll `plugins[].details.modules[].tasks` in `/api/status` for completion. Each definition always has a local row; isolated scripts additionally have device rows with MACs. Local rows precede devices sorted by MAC; unknown is not executable. Status/list read snapshots without discovery I/O. LAN discovery failure affects device rows or module warnings, never blocks local work and never dispatches stale LAN targets. `type` is cron/generic, `runs` belongs to the task and effective scope, and `last_trigger` is `cron`/`http-api`. Generic tasks have no schedule and are ready when idle. Count and resolve definitions by instance/module/name, not scope rows. Only the latest attempt is retained; counters reset on reload and manual runs preserve the cron schedule. Missing instance/task: `404`; ambiguous name, malformed MAC or MAC on a non-isolated script: `400` (omit MAC); disabled device or busy same-scope task: `409`; inactive worker or unavailable discovery: `503`. No inline source, argument overrides or automatic retries.

Surge instance `isolate_lan` defaults to true. Dae's module descriptor supports a module-level `isolate_lan` and repeated `script { name: 'script.name' isolate_lan: false }` overrides. Precedence is script > module > instance; sgmodule syntax stays unchanged. Local calls always use the local bucket. Isolated LAN calls use host-confirmed direct MAC buckets; unknown identity reads null, writes/deletes false and bypasses the DNS script-answer cache. Disabled isolation maps every source to the local bucket and local cache; reported scope is local, not a claim about raw origin. Capture and cron must use the same policy and scope to share Cookie/token state. Shared mode intentionally shares credentials across clients. Policy changes never migrate, merge or delete existing buckets. `store` controls persistence independently. The file maps buckets to key/string maps, limited to 64 MiB per instance and 4 MiB per value.

Explicit storage migration moves every `$persistentStore` key/value in one instance's old-MAC partition and removes that partition. It does not merge or overwrite: an existing destination, even empty, returns `409`. Source/destination scripts executing in this daemon or overlapping reload generations also return `409`. Invalid or equal MACs return `400`; missing instance/source returns `404`; unavailable capability/runtime or canceled/timed-out lock waits return `503`. MACs must be distinct nonzero unicast six-byte addresses; local/unknown are not targets. Neither device needs to be online or MITM-enabled. The fixed five-second context limits cancellable lock waits, not filesystem I/O.

Before migrating, stop traffic and background eligibility for the old MAC, verify the destination MAC and absence of destination data, and stop other processes writing the same file. Use `dae plugins surge store migrate 02:00:00:00:00:11 02:00:00:00:00:22 --instance surge`. There is no per-script/module selection: storage is shared within the device partition. Local storage, notifications, counters, queued tasks, authorization, routing and isolation settings are unchanged; a later old-MAC execution can create a fresh partition. Memory mode moves only the current runtime's data, without enabling persistence or preserving it across reloads. A `500` stating “script store migration was published, but durability is unconfirmed” means the move already took effect. Timeout or connection loss does not prove otherwise. Neither API clients nor CLI automatically retry; verify the outcome before taking further action. Cross-process file locks serialize commits, not entire script executions in other processes.

Discover configured cron/generic scripts with `dae plugins surge list`; filter with `--instance` and `--module`, or use `--json` for a task array. Trigger with `dae plugins surge run demo.tool --instance surge --module tools`; both commands require a running daemon. `run --json` prints an acceptance snapshot; inspect plugin status for completion. CLI/API triggers use `last_trigger: http-api`. See the [manual execution guide](surge-module.md#manual-triggers).

Surge reports retain up to 50 `$notification.post` messages per effective scope and script, grouped by scope, MAC, module, script name and type. `plugins[].details.notifications` contains all retained messages newest first and is omitted when empty. Each entry includes `id`, `created_at`, `scope` (local/device/unknown), device-only `mac`, `module`, `script`, `script_type`, `title`, `subtitle`, and `body`. Local and unknown never share a group; shared LAN invocations report local. Module/script names and title/subtitle are capped at 1024 UTF-8 bytes each, body at 4096; shortened entries have `truncated: true`. History is independent of log filtering and execution success and resets on reload. CLI text shows the latest 3 per group; `surge status -v`, `plugins status -v` and JSON show all retained messages.

The daemon status schema is 15, served at `/api/status` over the Unix socket `/var/run/dae.sock` for `dae status`, `dae plugins status` and plugin commands. It does not require `api.listen`. Top-level `direct_fallback_connections` counts no-connectivity fallbacks to direct established in userspace across the process lifetime; like other kernel bypass traffic, fallback flows forwarded directly by eBPF are not counted; path, group and node statistics contain no fallback field. `tables` reports kernel tables and userspace resource pools with `scope` (`kernel` / `userspace`), `on_full` (`evict` / `reject` / `omit` / `unlimited`) and optional `error`. `limit: 0` means unlimited; nonempty `error` makes `used` unavailable rather than zero. Full LRU tables normally evict, unlike pools that reject new entries. Domain tables also report time-based GC, kernel candidates and pending projection changes. Registry `used` counts domain-IP pairs; its `breakdown` includes distinct `domains`, distinct `ips`, address-family counts `ipv4` / `ipv6`, and cumulative collected pairs `gc`. `compiled_plugins` lists plugin types registered in the running daemon, excluding the system MITM diagnostic. `plugins` contains accepted instance IDs, types, `enabled`, host lifecycle states and rule counts, including disabled configuration and the system diagnostic. `declared_scopes` counts declared HTTP scopes; `scopes` counts effective scopes after the HTTP switch. Disabled instances do not evaluate plans, report zero counts and have no `details`. `http_active` means effective scopes can participate in HTTP processing, not a guarantee of device interception or worker health. `http_reason` is empty when active, otherwise `disabled`, `no_scopes`, `mitm_disabled`, `prepared`, `draining` or `unavailable`. Only administrators receive plugin-defined `details`; Surge supplies `enabled` and `modules`. Node latency contains successful samples only; automatic groups expose degradation and selection scoring in `selection`. Use matching CLI and daemon versions.

`dae plugins status --json` prints process-wide `compiled_plugins`, the `buffer_memory` budget and complete reports in `plugins`. The compiled list and budget remain visible with no active instances and after instance filtering. The CLI plugin overview and Web Plugins section use the same accepted state; failed reloads leave it unchanged. The ordinary `dae status` text display does not expand plugin details. `dae plugins <type> status --instance <ID>` selects one instance. User and anonymous LAN requests retain statistics and common plugin state but omit every `plugins[].details` field. Full plugin reports and notifications require administration. Automatic plugin state excludes configuration credentials; notification fields retain explicit script-authored text.

Notification histories share a conservative 1 MiB JSON budget per instance, charging scope/MAC bytes and worst-case text escaping. The longest scope/script history loses its oldest entry first; ties remove the oldest entry. A group may retain fewer than 50 messages. Verbose and JSON include all retained entries; MACs are not Prometheus labels.

### Resource refresh

```sh
sudo curl --unix-socket /var/run/dae.sock -X POST -H 'X-Dae-API: 1' http://localhost/api/resources/refresh
sudo curl --unix-socket /var/run/dae.sock http://localhost/api/operations/OPERATION_ID
sudo curl --unix-socket /var/run/dae.sock http://localhost/api/resources
```

Refresh uses the accepted configuration; changes to configuration files still
require `dae reload`. A `202` response contains a unique operation ID. Work
continues after the HTTP response and is published serially with reload and
suspend operations. Another refresh while one is queued or running returns `409`.
Operations include `id`, `kind`, `state` (`queued`, `running`, `completed`, `failed`
or `canceled`), `trigger` (`api` or `automatic`), queue/start/finish timestamps,
`progress`, `result` and `error`. `GET /api/resources` returns the latest refresh
as `operation` and the next check as `next_check`; `operation` is omitted before
the first refresh. The result reports how many resource groups retained their
previous contents after download or validation failures. See
[resource caching (Chinese)](../../zh/configuration/cache-directory.md#全局资源缓存) for the
automatic check interval and fallback rules.

`POST /api/operations` accepts `{"kind":"reload"}`, `{"kind":"suspend"}` or
`{"kind":"refresh"}`. Reload and suspend may also set `"abort":true`. The queue
holds up to 16 waiting operations and returns `409` when full. The daemon retains
the latest 64 completed operations and current work. `GET /api/operations/{id}`
returns `404` for unknown, expired or previous-process IDs. A CLI timeout stops
waiting but does not cancel accepted work. Local Unix operation routes remain
available while the control plane is replaced.
