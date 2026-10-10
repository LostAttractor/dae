# Decision explanations and client management

`dae explain`, `dae-client explain`, and Web **Explain Decisions** analyze a hypothetical new flow using current configuration and runtime evidence. They do not connect to targets, query DNS, run scripts, refresh caches or health checks, or change settings. Existing connections and UDP source associations may retain earlier decisions.

## CLI

Both executables share commands and the usual [API connection options](api-client.md):

```sh
dae explain route 198.51.100.10:443 --self --api http://192.168.1.1:9080
dae explain route 198.51.100.10:443 --self --sni example.com --join work \
  --api http://192.168.1.1:9080 --json
dae explain route 198.51.100.10:443 --mac 02:00:00:00:00:10 \
  --source-ip 192.168.1.10 --source-port 40000 --interface br-lan --dscp 0
dae explain domain example.com
dae explain dns example.com --qtype AAAA
dae explain outbound proxy --network tcp4
dae explain plugins https://example.com/path --mac 02:00:00:00:00:10 \
  --source-ip 192.168.1.10
dae explain route --input request.json --json
```

`--input -` reads a full JSON request from stdin, replacing other input fields; `--self` still chooses the device endpoint. `--join` and `--leave` compare hypothetical memberships. `explain` is separate from privileged kernel packet tracing with `trace`.

Self-service requires a verified direct LAN TCP connection. It inherits IP, MAC, memberships, MITM preferences and observed ingress/physical bridge interfaces, rather than the browser connection's ephemeral source port, DSCP, SNI, Host or process identity. Unix-socket administrators use explicit MAC/context instead of `--self`.

Omitted packet fields remain unknown. If they can affect the result, `complete` is false and `missing` identifies required inputs. `origin` accepts `lan`, `local`, and `daemon`; the last represents userspace explicit-target routing. Nonzero input marks require hook-specific local semantics and are rejected; rule-generated mark/must results are explained.

## Reading results

- `verdict` distinguishes `kernel_direct`, `userspace`, `drop`, `unknown`, `analysis`, and `local_response`. An outbound named `direct` alone does not mean kernel bypass.
- Predicate truth (`match`) is separate from execution (`status`): mismatch, short circuit, earlier termination, unavailable outbound, missing context, other ingress policy, or inactive configuration. Supplementary predicates never change the interpreter's decision.
- `sources` retains expressions and file positions. Merged rules list multiple origins; repeated shared fragments have distinct step IDs. Expanded conditions appear in predicate details.
- Destination domain, TLS SNI, HTTP URL/Host and kernel domain-IP evidence remain separate. Supplying SNI cannot create a kernel domain match. Missing mappings follow ordinary routing semantics without broader capture.
- Hostname-only targets list retained candidates and require a destination IP; they are never resolved actively. Evidence reflects current retained records and kernel residency, including records awaiting collection.
- Host/DNAT analysis lists rewritten targets. Random destinations and nodes remain candidates without consuming randomness. Node explanations include availability, policy, priority and score without waiting for recovery checks.
- The DNS router explains request rules, upstreams and response predicates. Supply `dns.answer_ips`, `dns.upstream` or `dns.rcode` for response context. Without a DNS server IP, this is DNS policy analysis; with IP/port and complete identity, kernel capture and exact cache keys can also be analyzed. Cache peeks do not update LRU, counters or TTL.
- HTTP explanations cover declarative scope, request headers, URL rewrites, Map Local, Host and script matching. Scripts and body-dependent changes are unknown execution boundaries; plugins without explanation support are explicitly identified. Dependent downstream decisions remain unresolved.
- Results carry configuration generation and observation time. Comparisons reuse routing, membership, domain and node snapshots; plugins reuse read-only observations for identical keys. Sampling across subsystems is not globally atomic, and later health changes can affect real connections.

## Client management

```sh
dae client list
dae client show work
dae client device --mac 02:00:00:00:00:10
dae client join work --mac 02:00:00:00:00:10
dae client leave work --self --api http://192.168.1.1:9080
dae client impact work --mac 02:00:00:00:00:10 --joined=false \
  --target 198.51.100.10:443 --source-ip 192.168.1.10
dae client mitm enable --mac 02:00:00:00:00:10
dae client mitm disable --mac 02:00:00:00:00:10
dae client mitm reset --mac 02:00:00:00:00:10
```

`list/show/device --self` reads the current device. Membership, impact and MITM operations accept either `--self` or `--mac`. Only configured groups can be changed. Reset removes the MITM override; the effective default may depend on source IP. MITM commands submit the current CA fingerprint.

`impact` lists direct, negated and conditional membership references without saving anything. An optional target adds a same-snapshot before/after trace. Other predicates and earlier rules can still take precedence. Results include connection retention/closure behavior and ipset/nftset export names; external firewall rules are not evaluated.

Web **Routing impact** loads on demand. **Compare a target** carries its proposed membership into the explanation form. Administrators can inspect arbitrary MACs and change membership/MITM through **Manage Devices by MAC**. **Administrator context** accepts explicit identity in advanced JSON; advanced fields replace corresponding top-level form fields.

## API

The main [OpenAPI document](../../api/openapi.json) references the [diagnostics contract](../../api/diagnostics.json). Go types are in `api/diagnostics.go`, with SDK methods in `api/client/diagnostics.go`.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/device/context` | Verified inheritable context |
| `POST /api/device/diagnostics/explain` | Self-service explanation |
| `POST /api/diagnostics/explain` | Administrator-supplied context |
| `POST /api/device/sets/{name}/impact` | Self-service membership preview |
| `POST /api/clients/{name}/impact` | Membership preview for a specified MAC |
| `GET /api/clients`, `GET /api/clients/{name}` | Administrator group/member listing |
| `PUT` / `DELETE /api/clients/{name}/members/{mac}` | Administrator membership changes |
| `GET /api/devices/{mac}` | Saved device preferences |
| `PUT` / `DELETE /api/devices/{mac}/mitm` | Set/reset MITM override |

Explanation and impact bodies are limited to 64 KiB with a five-second evaluation context. Other settings retain their 1 KiB limit. POST/PUT/DELETE require `X-Dae-API: 1`; MITM changes also require the current CA fingerprint in `X-Dae-MITM`. Device endpoints reject identity overrides and do not trust forwarded headers.

```json
{
  "kind": "flow",
  "context": {"mac": "02:00:00:00:00:10", "source_ip": "192.168.1.10", "dscp": 0},
  "flow": {"protocol": "tcp", "destination": {"ip": "198.51.100.10", "port": 443}, "sni": "example.com"},
  "compare": {"client_sets": {"work": true}, "bindings": [{"ip": "198.51.100.10", "domains": ["example.com"]}]},
  "detail": "predicates"
}
```

`compare` also supports `mitm` and outbound availability assumptions through `outbounds`. Assumptions modify private copies only. `complete` describes decision completeness, not a connectivity guarantee.
