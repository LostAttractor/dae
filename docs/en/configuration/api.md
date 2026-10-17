# Management Page and Runtime API

See [API and independent clients](api-client.md) for standalone builds, TUI integration and wire semantics, and the [OpenAPI document](../../api/openapi.json) for machine-readable definitions.

See [Decision explanations and client management](explain.md) for read-only routing/subsystem analysis, membership previews and administrative MAC management.

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

`global.api_port` defaults to `0`, disabling the listener. A nonzero port serves the HTTP page and API on all router addresses. The same port also serves the complete page and API over HTTPS, using a router-IP certificate signed by the daemon CA. A persistent self-signed CA is initialized automatically; MITM need not be enabled. Explicit CA paths belong in the top-level `certificate { ca_cert, ca_key }` block and are only loaded, never generated or overwritten. After installing and trusting the CA, use `https://192.168.1.1:9080/`. Use the actual LAN IP, such as `http://192.168.1.1:9080/`. Domain names, reverse proxies, and cross-origin browser requests are unsupported. Reload after changing the port or router addresses.

The managed CA is stored in `$DAE_LOCATION_CACHE/pki` (default `/var/lib/dae/pki`) as `ca.pem` and `ca.key`. It is reused across restarts, reloads and MITM toggles. An existing incomplete, invalid or expired store causes an error instead of automatic replacement. Use `dae ca info`, `dae ca export`, or `dae ca generate` to inspect, export or pre-create the CA. Explicit generation paths require both `--cert` and `--key`.

## Usage and Persistence

`selector` continuously checks only the selected node by default; its startup barrier also waits only for that node. Switching immediately checks the new selection and pauses periodic checks on the old one. An in-flight test may finish. Automatic policies use the scope described in [outbound selection](outbound-selection.md).

Selectors use searchable dropdowns: the collapsed control shows the selected node, while the bounded, scrollable popup handles large lists and long names. By default, use **Test** beside the selected node or a candidate, or **Test All**. Each button requests one round of the group's configured DNS connectivity probe without changing selection or monitoring scope. Authorized, visible pages refresh results every two seconds. Untested nodes show **Not tested**.

Set `track_all: true` in a selector's group block and reload to continuously monitor every candidate; it defaults to false. This is configuration-only, with no mutation API or runtime preference. When enabled, the page shows **Monitoring all nodes** in place of every **Test / Test All** button. Checks use the group's interval settings; the startup barrier still waits only for the selected node. The option is selector-only and is not inherited through `group(name)`.

For selector groups, `dae status` (including verbose/JSON) includes only selected, monitored, currently testing, or actively connected nodes. Idle untracked candidates retain their last result in `/api/selectors` and the page. Group/global traffic totals still include those paths.

- **Selectors**: When `api_key` is configured, enter it in the top toolbar and click **Login** to view selector status or change nodes. Without a key, clients with verified LAN ingress can use selectors immediately; the toolbar shows **LAN access**. Plain `selector` has no configured default: restore a saved choice, otherwise initially select the first candidate, without a default badge or reset button. Only explicit `selector(n)`, including `selector(0)`, declares a default path index. Changes affect everyone using the group. Choices persist as independent logical path references; reordering, priority, TLS, multiplex, global mark and probe settings do not change them.
- **This Device**: Devices can join several `client(name)` MAC sets; routing order still applies. The API connection must traverse `global.lan_interface` ingress, and its observed source MAC must match a direct ARP/NDP neighbor. Interface patterns are supported; changing MAC requires joining again. Failed identification returns `403`; authenticated selector access and public certificate downloads remain available.
- **This Device Status**: Active/total connections, upload/download totals, recent rates and used outbounds for the visiting device. IPv4/IPv6 share the ingress MAC identity; administrator login is unnecessary. These are userspace upstream counters, including splice acceleration, excluding kernel passthrough, local HTTP/DNS responses and daemon-originated work. Totals survive reload and reset on process restart.
- **Global Status**: Version, uptime, global connections/traffic, outbound/node state, domain tables and plugins. Existing administrative authorization applies; logout or session expiry clears protected data.
- **HTTPS Modules**: Device settings override `mitm.client_source_address`, including explicit disabling. Install and trust the CA before enabling. **Test Certificate** separately checks CA acceptance by this browser and the transparent MITM path.

Visible pages refresh device and authorized global state every two seconds. Rates use five-second samples covering up to one minute. Hidden pages pause polling; failed reads display their retry state.

Login stores a signed session in an `HttpOnly`, `SameSite=Strict` cookie for seven days; the API key itself is not stored in the cookie. Reloading the page or daemon preserves the session. **Logout** clears the browser cookie; changing `api_key` invalidates existing sessions. **Refresh** updates the displayed state and timestamp. Device self-service remains available without administrator login.

`global.api_key` is optional. When empty, verified LAN connections receive full management access, including selectors, global status, other-device settings, probes, configured script tasks and resource refresh. Ethernet ingress requires a matching direct ARP/NDP neighbor. IP-only interfaces such as `tailscale0` or a TUN interface require a current observation on `global.lan_interface`, without inventing a MAC or requiring a direct neighbor. This trusts every source arriving through that interface, including other VPN nodes and routed subnets; `lan_interface` itself supplies no encryption or per-user authentication.

There are two privilege levels: ordinary LAN devices and administrators. With `api_key` configured, an unauthenticated LAN device can read only its own settings, traffic and connection context, change its own memberships and MITM preferences, and run its own MITM tests. Global state, other devices, nodes, all diagnostics and routing impact previews require administrator access. Without a key, every verified LAN connection is an administrator. The Web UI shows diagnostics and routing impact only to administrators and clears loaded results on logout or loss of access. Certificate downloads and CA metadata remain public.

Every request checks permissions. A private source IP, forwarded header or saved cookie cannot establish LAN access. Unverified ingress returns `403`. Keyless access creates no session. Configuring a key requires key/session authentication for all TCP management requests, independently of LAN identity. Unix administration uses file system permissions. HTTP exposes keys and reusable sessions to observers of its network path. After installing and trusting the CA, use HTTPS on the same port. Both protocols enforce the same authorization rules.

The Web UI displays an IP connection and its ingress interface when no Ethernet identity exists. Current-connection context remains available; read-only explanations additionally require administrator access. Device traffic, MAC-set membership changes and comparisons, per-device MITM preferences and MITM tests require a verified Ethernet MAC; administrator login does not supply one.

Ingress observations contain TCP endpoints, link type, timestamp and interface indices. Records must be younger than 30 seconds and their LAN hook must still be attached. New datapath generations start with an empty observation map; reloads retaining the datapath retain its observations. IPv6 link-local endpoint zones must correspond to observed ingress, following receive direction through VLANs, bridges or bonds. For `enp1s0f0np0 → lan (VLAN) → br-lan`, keep `lan_interface: lan`. Ethernet device identity additionally rejects indirect return routes and MACs that do not match the route interface's ARP/NDP neighbor.

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

With the page enabled, HTTP and HTTPS share the page/API on `global.api_port`; CA trust testing uses a newly issued server certificate and a short-lived challenge without requiring MITM or a device MAC. Transparent verification additionally requires MITM enabled in the daemon and for this device. Transparent-MITM testing uses virtual destinations on port 443, configured by `global.api_mitm_test_ipv4` (default `203.0.113.254`) and `global.api_mitm_test_ipv6` (default `2001:db8:ffff::254`). Neither test needs an extra listening port or an upstream service.

Expand **Certificate & browser verification** and click **Test Certificate**:

1. The browser sends a same-origin `POST /api/certificate/tests`, issuing a temporary certificate and new key held only in memory. It then reads `/api/certificate/tests/{id}` over HTTPS at the same IP and port. The server requires a handshake using this or a newer challenge certificate for the initiating source/router IP pair. Connections using the management certificate or an older challenge receive `409` and close so the browser can retry. The page checks the challenge ID and CA fingerprint before showing **CA trusted by this browser**. There is no need to open the HTTPS page or accept a certificate warning first.
2. If the first step succeeds and MITM is enabled for the device, the browser visits the virtual IP of the same address family through normal kernel capture, device admission and TLS decryption. The built-in `dae-mitm-test` plugin checks the ingress MAC and answers locally, without dialing an upstream. Different source IPs selected by the same device for the router and virtual destination are supported.

Choose unused virtual addresses whose traffic reaches dae. They must be outside local subnets and other software's Fake IP pools; local subnet overlap is rejected. Do not assign these addresses to a router interface. Networks that discard the default documentation ranges before reaching dae need different configured addresses or routing. Capture is limited to the two exact IPs on port 443; API traffic remains kernel-direct, and unrelated traffic keeps its normal routing behavior.

Tests do not change the persistent management certificate, CA, MITM certificate cache or device settings. A successful proof consumes its trust challenge; unfinished challenges expire after one minute. At most 8 trust challenges may be pending per source IP and 64 globally; excess requests return `429`. The temporary certificate includes five additional minutes of validity for client clock skew, capped by CA expiry; this does not extend the challenge deadline. Each challenge owns its temporary certificate. Once no challenges remain for the source/router IP pair, new connections use the original management certificate again. Clients sharing a source IP share this temporary selection; other source IPs are unaffected. MITM challenges and observations are retained for one minute, with at most 8 per verified MAC and 256 globally; excess creation requests return `503`. Replacing the CA invalidates trust challenges, while publishing MITM configuration invalidates interception challenges. A changed CA fingerprint clears both results; changes to the MITM test generation, device identity or setting clear only interception results. Results include a time and fingerprint and apply only to the current browser, not every application on the device. An exception previously accepted for the management certificate cannot validate a challenge certificate. Users relying on that exception may temporarily lose new HTTPS connections while a challenge is pending and can use the HTTP setup page to install and trust the CA. **Verification incomplete** means the browser could not complete verification; certificate rejection, network failures and some browser-policy failures are indistinguishable to page JavaScript.

Access the page using a router IPv4 or non-link-local IPv6 literal; tests need no external websites or DNS mappings. MITM challenges accept only the initiating page's exact HTTP or HTTPS Origin. Only the certificate challenge's HTTPS GET permits the initiating HTTP setup page at the same IP and port to read across protocols; `/api/certificate` metadata and other API routes remain same-origin. The browser validates virtual origins against `/api/certificate`'s `mitm_test_origins`. CA metadata cannot be cached, and old TLS connections cannot read the new CA metadata after an identity change; reloads with the same CA and certificate directory preserve connections and pending trust challenges. MITM challenge connections close after the response; ordinary HTTPS reachability cannot prove MITM interception. Because virtual targets have no upstream service, an incomplete MITM test cannot distinguish bypass from unreachable traffic.

## API

POST, PUT and DELETE requests require `X-Dae-API: 1`. JSON bodies require `Content-Type: application/json`; other requests use empty bodies. With a configured key, status and selector reads/writes require `Authorization: Bearer <api_key>` or a valid browser session cookie; without a key they require verified LAN ingress. MITM writes require `X-Dae-MITM: <current CA SHA-256 fingerprint>`. In key mode, an explicit Authorization header takes precedence over the cookie. URL-encode names in paths. Command-line clients may omit `Origin`.

Keyless TCP administration returns `403` if LAN identification fails. With a configured key, a missing, incorrect or expired key/session returns `401`. Device self-service always requires direct LAN identification and does not require this key.

| Method and path | Behavior |
| --- | --- |
| `PUT /api/session` | With a configured key, login using `Authorization: Bearer <api_key>` and receive a session cookie; without a key, verify LAN/Unix access and clear stale cookies. Empty body, `204` on success |
| `DELETE /api/session` | Clear the browser session cookie; empty body, `204` on success |
| `GET /api/status` | Full runtime snapshot; TCP uses the configured API key/session, or verified LAN ingress when no key is configured; Unix uses file system permissions |
| `GET /api/device` | Caller IP, MAC, sets (`name`, `description`, `joined`), and MITM state (`enabled`, `override`, `ca_fingerprint`); `403` for an unknown MAC |
| `GET /api/device/status` | Caller device state and MAC-attributed userspace upstream statistics; verified direct LAN only |
| `POST /api/device/mitm-tests` | Empty body; `201` with browser challenge URLs; does not change MITM settings |
| `GET /api/device/mitm-tests/{id}` | This device's observations; `404` for expired, replaced or foreign challenges |
| `PUT` / `DELETE /api/device/sets/{name}` | Join / leave a set |
| `PUT /api/device/mitm` | Enable with `{"enabled":true}`, or disable with `false` |
| `DELETE /api/device/mitm` | Restore configuration |
| `GET /api/selectors` | Requires administration; default/current node IDs, overrides, candidate health and latency; `admin_enabled` is true after authorization, and `auth_mode` is `api_key`, `lan` or `unix` |
| `PUT /api/selectors/{name}` | Select with `{"node_id":"ID from status"}` |
| `DELETE /api/selectors/{name}` | Restore explicit `selector(n)`; `409` if no default exists |
| `POST /api/probes` | `{"outbound":"manual","node_id":"node ID"}` probes one node; omit or leave `node_id` empty for the whole outbound; returns `202` with accepted node IDs |
| `POST /api/plugins/{instance}/scripts/run` | Requires administration; `{"module":"tools","script":"demo.tool"}` triggers a configured cron/generic task; returns `202` with its per-task run number and acceptance status |
| `GET /api/certificate` | CA name, SHA-256 fingerprint, and optional `mitm_test_generation` and `mitm_test_origins`; `404` when unavailable |
| `POST /api/certificate/tests` | `201` with a one-minute CA trust challenge and a temporary certificate held in memory; preserves the management certificate; TCP API only, no MAC or MITM required |
| `GET /api/certificate/tests/{id}` | HTTPS only; a challenge handshake returns `id`, `ca_fingerprint` and `expires_at` and consumes the challenge; management or older challenge connections receive `409` and close for retry; consumed or expired challenges return `404` |
| `GET /ca.pem`, `/ca.cer`, `/ca.mobileconfig` | Download the public certificate without MAC identification |

A `null` MITM `override` inherits the configuration. Fetch the corresponding status after changes. A changed CA causes MITM writes to return `409`; refresh the page, verify the fingerprint, and install and trust the current certificate.

`POST /api/probes` is the shared manual probe API for instantiated, checked outbounds, including selectors, automatic policies and direct node references. It uses configured DNS probes, timeouts and concurrency bounds; arbitrary URLs and per-request probe configuration are not accepted. `202` acknowledges acceptance, including coalescing with queued/running work; it is not a health result or persistent job, and changes neither selection nor `track_all`. Poll `/api/selectors` for selector `checking`, `tested`, `checked_at`, `healthy` and `latency_ms`; other outbounds publish runtime health and latency through `/api/status`. Unknown outbound: `404`; node outside that outbound: `400`; unchecked builtin: `409`.

`SelectorState.track_all` is read-only configuration. `default_node_id` is present only for explicit `selector(n)`; clients should hide default labels and reset controls when it is absent.

`node_id` identifies the actual runtime choice. A saved preference sets `overridden` to true and adds `saved_selection` with `name` and `status` (`matched`, `missing`, or `ambiguous`). Missing or ambiguous preferences remain saved while the startup choice is used temporarily; clients must not overwrite the preference with that actual `node_id`.

Script acceptance is asynchronous: execution uses the daemon's background routing client and continues after the response. Poll `plugins[].details.modules[].tasks` in `/api/status` for completion; `type` is `cron` or `generic`, `runs` identifies the latest attempt, and `last_trigger` is `cron` or `http-api`. Generic tasks have no schedule and are `ready` when idle. Only the latest attempt is retained, and counters/history reset on reload. Manual execution preserves cron's next scheduled time. Missing instance/task: `404`; ambiguous name without `module`: `400`; already waiting/running: `409`; inactive worker: `503`. No inline source or argument overrides are accepted. The API client does not retry execution requests.

Discover configured cron/generic scripts with `dae plugins surge list`; filter with `--instance` and `--module`, or use `--json` for a task array. Trigger with `dae plugins surge run demo.tool --instance surge --module tools`; both commands require a running daemon. `run --json` prints an acceptance snapshot; inspect plugin status for completion. CLI/API triggers use `last_trigger: http-api`. See the [manual execution guide](../../zh/configuration/surge-module.md#手动触发).

Surge reports retain up to 50 recent `$notification.post` messages **per script** within each instance, identified by module, script name and script type. `plugins[].details.notifications` contains all retained messages, newest first; the field is omitted when empty. Each entry contains `id`, `created_at`, `module`, `script`, `script_type`, `title`, `subtitle`, and `body`. Module/script names and title/subtitle are limited to 1024 UTF-8 bytes each, body to 4096; shortened entries have `truncated: true`. History is independent of log filtering and script success, and resets on reload. `dae plugins surge status` shows the latest 3 per script by default, with an omission count. `surge status --verbose` (`-v`), `plugins status -v`, and JSON show all retained messages.

The daemon status schema is 13, served at `/api/status` over the Unix socket `/var/run/dae.sock` for `dae status`, `dae plugins status` and plugin commands. It does not require `global.api_port`. Top-level `direct_fallback_connections` counts established no-connectivity fallbacks to direct across the process lifetime; path, group and node statistics contain no fallback field. Domain tables report time-based GC and kernel candidates; userspace `limit: 0` means unbounded. Registry `used` counts domain-IP pairs; its `breakdown` includes distinct `domains`, distinct `ips`, address-family counts `ipv4` / `ipv6`, and cumulative collected pairs `gc`. `plugins` contains instance IDs, types, host lifecycle states and rule counts. Optional `details` is defined by each plugin; Surge supplies `enabled` and `modules`. Node latency contains successful samples only; automatic groups expose degradation and selection scoring in `selection`. Use matching CLI and daemon versions.

`dae plugins status --json` prints the process-wide `buffer_memory` budget and complete reports in `plugins`. The budget remains visible with no active instances. `dae plugins <type> status --instance <ID>` selects one instance. Automatic plugin state excludes configuration credentials; notification fields retain explicit script-authored text under the same administration access controls.

Notification histories also share a conservative 1 MiB JSON budget per instance, charging worst-case text escaping. When full, the longest history loses its oldest entry first; ties remove the oldest entry. A script may therefore retain fewer than 50 messages. Verbose and JSON output include all messages remaining within this budget.
