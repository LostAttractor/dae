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

- **Selectors**: When `api_key` is configured, enter it in the top toolbar and click **Login** to view selector status or change nodes. Without a key, verified direct LAN clients can use selectors immediately; the toolbar shows **LAN access**. `selector` means `selector(0)`; `selector(n)` sets the default path index. Changes affect everyone using the group. Choices use node IDs, survive reordering, and reset when the configured node disappears.
- **This Device**: Devices can join several `client(name)` MAC sets; routing order still applies. The API connection must traverse `global.lan_interface` ingress, and its observed source MAC must match a direct ARP/NDP neighbor. Interface patterns are supported; changing MAC requires joining again. Failed identification returns `403`; authenticated selector access and public certificate downloads remain available.
- **HTTPS Modules**: Device settings override `mitm.client_source_address`, including explicit disabling. Install and trust the CA before enabling; the page cannot detect trust.

Login stores a signed session in an `HttpOnly`, `SameSite=Strict` cookie for seven days; the API key itself is not stored in the cookie. Reloading the page or daemon preserves the session. **Logout** clears the browser cookie; changing `api_key` invalidates existing sessions. **Refresh** updates the displayed state and timestamp. Device self-service remains available without administrator login.

`global.api_key` is optional. When omitted or empty, status and selector administration use the same direct LAN identity checks as device self-service: current eBPF ingress evidence on `global.lan_interface` and a matching direct ARP/NDP neighbor. Each request is verified; a private source IP, forwarded header, or old session cookie is insufficient. WAN, routed peers and unidentifiable clients receive `403`. This mode needs no login and creates no session cookie. Configuring a key requires key/session authentication for TCP administration, including LAN callers. Unix socket administration uses filesystem permissions in either mode.

The configuration field is now `global.api_key` (formerly `global.api_token`). Update existing configurations when upgrading; CLI clients use `DAE_API_KEY` and the Go SDK uses `client.Options.APIKey`.

Identification uses TCP connection metadata recorded by eBPF at LAN ingress. The route or neighbor table's interface name does not need to match `lan_interface`. For `enp1s0f0np0 → lan (VLAN) → br-lan`, keep `lan_interface: lan`; bonds and other layered Ethernet interfaces use the same identification path. Each request updates the observed MAC and timestamp; configuration reloads clear observations. Missing observations, observations older than 30 seconds, indirect return routes, and MACs that do not match the ARP/NDP neighbor on the route's interface prevent device operations. The same IP on another interface does not affect identification.

The `client` block supplies plain-text descriptions below set names; empty descriptions are hidden. Sets referenced by routing or configured for kernel export appear, and duplicate definitions are rejected. Descriptions update with `dae reload` without changing membership.

**Use Configuration** clears selector or MITM overrides. Settings persist in `$DAE_LOCATION_CACHE/runtime-state.json` (default `/var/lib/dae/runtime-state.json`, mode `0600`) across reloads, restarts, and API disabling. The main configuration is untouched. Existing connections and UDP sessions keep their paths.

Manual file edits trigger reloads through filesystem events, including atomic replacements. Invalid contents, unknown node IDs, application failures, or a temporarily missing file preserve current state. For example:

```json
{
  "selectors": {},
  "clients": {"work": ["02:00:00:00:00:50"]},
  "mitm": {"02:00:00:00:00:50": true}
}
```

Keep all three objects; remove entries to clear overrides or memberships. Use node IDs from `/api/selectors` and lowercase colon-separated MACs. Avoid concurrent file edits and API writes.

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

PUT and DELETE requests require `X-Dae-API: 1`. JSON bodies require `Content-Type: application/json`; other requests use empty bodies. With a configured key, status and selector reads/writes require `Authorization: Bearer <api_key>` or a valid browser session cookie; without a key they require verified direct LAN identity. MITM writes require `X-Dae-MITM: <current CA SHA-256 fingerprint>`. In key mode, an explicit Authorization header takes precedence over the cookie. URL-encode names in paths. Command-line clients may omit `Origin`.

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
| `DELETE /api/selectors/{name}` | Restore configuration |
| `GET /api/certificate` | CA name and SHA-256 fingerprint; `404` when unavailable |
| `GET /ca.pem`, `/ca.cer`, `/ca.mobileconfig` | Download the public certificate without MAC identification |

A `null` MITM `override` inherits the configuration. Fetch the corresponding status after changes. A changed CA causes MITM writes to return `409`; refresh the page, verify the fingerprint, and install and trust the current certificate.

The daemon status schema is 11, served at `/api/status` over the Unix socket `/var/run/dae.sock` for `dae status`, `dae plugins status` and plugin commands. It does not require `global.api_port`. Top-level `direct_fallback_connections` counts established no-connectivity fallbacks to direct across the process lifetime; path, group and node statistics contain no fallback field. Domain tables report time-based GC and kernel candidates; userspace `limit: 0` means unbounded. Registry `used` counts domain-IP pairs; its `breakdown` includes distinct `domains`, distinct `ips`, address-family counts `ipv4` / `ipv6`, and cumulative collected pairs `gc`. `plugins` contains instance IDs, types, host lifecycle states and rule counts. Optional `details` is defined by each plugin; Surge supplies `enabled` and `modules`. Use matching CLI and daemon versions.

`dae plugins status --json` prints complete plugin reports. `dae plugins <type> status --instance <ID>` selects one instance. Task details may intentionally include video identifiers and titles, but never cookies or API keys.
