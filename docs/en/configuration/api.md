# Management Page and Runtime API

```text
global {
  lan_interface: br-lan
  api_port: 9080
  api_token: 'replace-with-a-private-token'
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

`global.api_port` defaults to `0`, disabling the listener. A nonzero port serves the HTTP page and API on all router addresses, independently of Surge. Use the actual LAN IP, such as `http://192.168.1.1:9080/`. Domain names, reverse proxies, and cross-origin browser requests are unsupported. Reload after changing the port or router addresses.

## Usage and Persistence

- **Selectors**: `selector` means `selector(0)`; `selector(n)` sets the default path index. Changes affect everyone using the group and require `api_token`. Choices use node IDs, survive reordering, and reset when the configured node disappears.
- **This Device**: Devices can join several `client(name)` MAC sets; routing order still applies. Only direct ARP/NDP neighbors on `global.lan_interface` qualify. Interface patterns are supported; changing MAC requires joining again. Failed identification returns `403`; node lists and certificate downloads remain available.
- **HTTPS Modules**: Device settings override `mitm.client_source_address`, including explicit disabling. Install and trust the CA before enabling; the page cannot detect trust.

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

Every write requires `X-Dae-API: 1`. JSON bodies require `Content-Type: application/json`; other requests use empty bodies. Selector writes require `Authorization: Bearer <api_token>`; MITM writes require `X-Dae-MITM: <current CA SHA-256 fingerprint>`. URL-encode names in paths. Command-line clients may omit `Origin`.

Selector writes return `403` with an explanation when `global.api_token` is not configured, or `401` when the request token is missing or incorrect. Device self-service does not require this token.

| Method and path | Behavior |
| --- | --- |
| `GET /api/device` | Caller IP, MAC, sets (`name`, `description`, `joined`), and MITM state (`enabled`, `override`, `ca_fingerprint`); `403` for an unknown MAC |
| `PUT` / `DELETE /api/device/sets/{name}` | Join / leave a set |
| `PUT /api/device/mitm` | Enable with `{"enabled":true}`, or disable with `false` |
| `DELETE /api/device/mitm` | Restore configuration |
| `GET /api/selectors` | Default/current node IDs, overrides, candidate health and latency; `admin_enabled` indicates a configured token |
| `PUT /api/selectors/{name}` | Select with `{"node_id":"ID from status"}` |
| `DELETE /api/selectors/{name}` | Restore configuration |
| `GET /api/certificate` | CA name and SHA-256 fingerprint; `404` when unavailable |
| `GET /ca.pem`, `/ca.cer`, `/ca.mobileconfig` | Download the public certificate without MAC identification |

A `null` MITM `override` inherits the configuration. Fetch the corresponding status after changes. A changed CA causes MITM writes to return `409`; refresh the page, verify the fingerprint, and install and trust the current certificate.
