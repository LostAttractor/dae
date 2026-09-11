# Routing

`routing` selects an outbound. To override the dialed IP using the same filter syntax, use the separate [`rules` / DNAT](../../zh/configuration/destination-rules.md) section (Chinese guide); `dnat` is not a routing outbound.

## Outbound Targets and Proxy Paths

Routing targets may be built-in outbounds, groups, or uniquely named nodes. Quote a target name when it contains spaces or non-ASCII characters; parameters follow the quoted name directly:

```shell
domain(full: special.example) -> 'Hong Kong 01'(skip_while_noalive)
fallback: 'Hong Kong 01'(mark: 0x800)
```

Each statement in a group declares one candidate proxy path. Join stages with `->` in physical order from the client towards the destination. A stage can filter the global node pool inline or strictly reference one node or a reusable group:

```text
path  := stage ("->" stage)*
stage := "filter:" filter-expression annotation?
       | node(name) annotation?
       | group(name) annotation?
```

A group with `policy` is a selector over all of its expanded complete paths. A group without `policy` is a reusable template for `group(name)`; it can also be a routing target when it expands to exactly one path.

```shell
group {
    relay {
        filter: name(relay-node)
    }

    proxy_jp {
        # A direct, one-stage candidate.
        filter: name(lightsail) [priority: 1]

        # Inline filters form a proxy chain.
        filter: name(lightsail) -> filter: subtag(flowercloud) && name(keyword: '日本')

        # A policyless group can be reused as a stage.
        group(relay) -> filter: subtag(exit) [add_latency: 20ms]
        policy: min_moving_avg
    }
}
```

Every path statement is independent, so the direct `lightsail` candidate and the chained candidates coexist. Each filter stage expands to all matching nodes. Multiple stages form a Cartesian product; a referenced group contributes all paths declared by that group.

`filter: name(name)` is a node-property filter and may match multiple definitions. A standalone `node(name)` stage always references the original node and rejects missing or duplicate node names. `group(name)` strictly references a group without `policy`; selector groups cannot be nested as path stages.

Without path or filter statements, a group selects the unique same-name node, or all nodes as single-hop candidates if none has that name; duplicate same-name nodes are ambiguous. Explicit statements override this default.

When a group and a node share a name, routing selects the group only if it expands to one single-hop path through that unique node; other collisions are ambiguous. This allows group settings without changing the routing target:

```shell
node { foo: 'socks5://proxy.example:1080' }
group { foo { check_async: true } }
routing { fallback: foo }
```

Expansion is statement-major and then terminal-major within each Cartesian path. For `entry-1`, `entry-2` followed by `exit-1`, `exit-2`, the order is `entry-1 -> exit-1`, `entry-2 -> exit-1`, `entry-1 -> exit-2`, then `entry-2 -> exit-2`. `fixed(n)` indexes this stable complete-path order. Separately declared identical physical paths remain separate candidates.

`priority` and `add_latency` annotations add across path stages. dae starts the initial connectivity checks of all paths together. A group with synchronous checks stops blocking startup when its policy has a usable candidate or all candidate paths relevant to that policy have completed their initial checks, even if none are available. `fixed(n)` only waits for the path at index `n`. The global 60-second deadline remains a fallback for checks that do not finish. Inconclusive connectivity modes continue support checks in the background.

Once a connectivity mode is confirmed, dae retains that capability. A node uses one supported mode for regular health checks, and all of its supported modes share the resulting health state.

Latency selection ignores `check_tolerance` until startup completes and once for each newly confirmed mode, so late support can correct selection for new connections. Existing connections remain on their original outbound.

`check_async: true` makes initial checks for the entire group run without blocking startup. It defaults to `true` when every routing reference uses `skip_while_noalive`, including unused groups; any reference without it, including `fallback`, makes the default `false`. Explicit `true` or `false` overrides this default. Directly routed nodes use the same default. `group(name)` does not inherit this setting, and groups used only as templates cannot configure it.

The former `[via: ...]` annotation is rejected. Node entries still contain exactly one share link; compose links only with group path expressions.

Quote a real node or group name that is `must` or begins with `must_` (for example, `'must_edge'`) to reference it literally. Flow controls belong in `rules {}`.

To bound health-check and runtime growth, a path may contain at most 16 hops, one routed target may expand to at most 4096 paths, and one configuration may materialize at most 16384 paths.

## Rule sets, routing policies and interface bindings

`rule_set` declares reusable rule fragments, `policy` declares complete policies with a fallback, and `default` and `interface` select policies:

```shell
routing {
    rule_set {
        local {
            dip(geoip:private) -> direct
        }
        china {
            dip(geoip:cn) -> direct
            domain(geosite:cn) -> direct
        }
    }
    policy {
        main {
            use: local, china
            fallback: proxy
        }
        lan {
            use: local
            fallback: direct
        }
    }
    default: main
    interface {
        br-lan: lan
        eth1: lan
        wg0: main
    }
}
```

- `use: local, china` inserts both fragments in order, just like two consecutive `use` statements. Rules and uses may be interleaved. Fragments may reference other fragments, but cannot reference policies or form cycles.
- Fragments contain only rules and uses, never a fallback. Each policy must declare exactly one `fallback`. It runs after all rules fail to match, regardless of where the field is written.
- `default: main` selects `main` for traffic without an interface binding. Each `interface` entry binds an exact device name to a named policy. Multiple interfaces and the default may share one policy, which is compiled only once.
- An interface name may appear only once, even when repeated entries select the same policy. Quote special names, for example `"foo,bar": lan`. Names are literal, not wildcard patterns. Interface recreation automatically updates the ifindex mapping.
- Policies are independent and do not inherit the default. Bindings select routing rules; configure `global.lan_interface` / `global.wan_interface` separately to capture traffic. The `interface(name)` predicate remains available inside individual rules.
- Policy names and fragment names have separate namespaces. Undefined references, duplicate declarations and cycles are rejected.

For a single default policy, write rules, uses and one fallback directly inside `routing`:

```shell
routing {
    rule_set {
        local { dip(geoip:private) -> direct }
    }
    use: local
    fallback: proxy
}
```

This anonymous default policy can coexist with `rule_set`, named `policy` and `interface` declarations, but cannot be combined with `default: policy_name`. Its fallback is also required. The old `default { ... }` form and policies defined inside interface blocks are no longer supported.

### Splitting policies across files

Use `include` to maintain fragments, policies and bindings in separate files, each with a `routing { ... }` wrapper. Declare each named fragment and policy once; compose larger policies with `use`. References may precede declarations. Rules and uses determine execution order, independently of declaration order. Export preserves references and rule order, placing fallback last in each policy. See [separate configuration files](separate-config.md) for a complete example.

A configuration supports up to 1024 fragments and policies, 65536 source rules and uses, 256 interface bindings and 64 reference levels. The shared physical rule pool and each policy's execution length are independently limited by `MaxMatchSetLen` (1024 by default). Unused definitions are validated but do not consume the active kernel rule pool or register interface listeners.

### Shared MITM, DNAT and Host capture

HTTP plugins, native `rules { ... -> dnat(ip) }` and literal-IP Surge Host mappings automatically share an internal capture and flow-control fragment across all policies. No manual rules or `use` are needed. Domain Host entries answer DNS without creating DNAT rules; ordinary uncaptured direct traffic stays in the kernel.

Execution order is: local API bypass → DNAT/Host and request-routing HTTP capture → must/bump controls and pure MITM capture → module `pre-matching` rules → user policy rules → ordinary module rules → policy fallback. All policies share the same capture and control instructions, while each policy selects the outbound, mark and block behavior. MITM retains each declared domain/IP and its ports; DNAT/Host retain their complete predicates, including domains. Missing DNS mappings do not widen capture, and unrelated direct traffic stays in the kernel. Exact userspace destination matching does not consume kernel instruction slots; identical domain and static IP predicates share resources across stages.

DNAT/Host candidates hand off before flow controls or routing commit the old destination. Destination rules select an effective IP; subsequent flow/routing uses that IP and address family while retaining client identity and Host/SNI. Pure MITM inspection retains a valid kernel route. Request-routing scopes (Surge scripts, URL Rewrite and Map Local) also hand off early: admitted clients run HTTP processing before destination rules, flow controls and final routing. An old-target block cannot prevent an admitted request from rewriting its target; a final-target block still rejects it. Excluded clients follow ordinary connection routing. Every deferred request is planned before pool lookup; pools distinguish effective addresses, nodes, outbounds, marks and TLS authority. Local responses require no upstream connection.

Named policies have stable IDs. Default and interface bindings to the same policy share its ID; failed candidates do not consume IDs. UDP lifetimes are keyed by source IP and port. An active source retains its initial policy and route when bindings, the default policy or interfaces change. After the lifetime ends, the next packet selects a route using the current bindings. DNS rerouting coalesces requests by policy ID as well, preventing decisions from being shared across policies.

## Manual Selection and Client Sets

`policy: selector` allows manual node selection, defaulting to the first node; `selector(n)` sets another default index. `client(name)` matches a MAC set that devices can join themselves. See the [page/API configuration](api.md).

## Fragmented TCP/UDP

dae supports fragmented TCP and UDP only on an unmarked direct, unmarked pass-through, or trusted control-plane path. Pass-through applies to an established inbound UDP flow or an outbound whose connectivity state is not available. dae never interprets non-initial fragment payload as a transport header. The initial fragment is dropped when routing selects a proxy, `block`, or `direct(mark: ...)`, so the packet cannot be reassembled through a different path. Avoid IP fragmentation when traffic must use a proxy; adjust the application or tunnel MTU instead.

## Examples

```shell
### Built-in outbounds: block, direct
# Flow controls must and bump are configured in rules {}, outside routing {}.

### fallback outbound
# If no rule matches, traffic will go through the outbound defined by fallback.
# fallback: my_group

### Domain rule
domain(suffix: v2raya.org) -> my_group  # equals to domain(v2raya.org) -> my_group 
domain(full: dns.google) -> my_group
domain(keyword: facebook) -> my_group
domain(regex: '\.goo.*\.com$') -> my_group
domain(geosite:category-ads) -> block
domain(geosite:cn)->direct

### Dest IP rule
dip(8.8.8.8) -> direct
dip(101.97.0.0/16) -> direct
dip(geoip:private) -> direct

### Source IP rule
sip(192.168.0.0/24) -> my_group
sip(192.168.50.0/24) -> direct

### Dest port rule
dport(80) -> direct
dport(10080-30000) -> direct

### Source port rule
sport(38563) -> direct
sport(10080-30000) -> direct

### Level 4 protocol rule:
l4proto(tcp) -> my_group
l4proto(udp) -> direct

### IP version rule:
ipversion(4) -> block
ipversion(6) -> ipv6_group

### Source MAC rule
mac('02:42:ac:11:00:02') -> direct

### Process Name rule (only support localhost process when binding to WAN)
pname(curl) -> direct

### DSCP rule (match DSCP; is useful for BT bypass). See https://github.com/daeuniverse/dae/discussions/295
dscp(0x4) -> direct

### Ingress interface rule
interface(br-lan) -> direct

### Multiple domains rule
domain(keyword: google, suffix: www.twitter.com, suffix: v2raya.org) -> my_group
### Multiple IP rule
dip(geoip:cn, geoip:private) -> direct
dip(9.9.9.9, 223.5.5.5) -> direct
sip(192.168.0.6, 192.168.0.10, 192.168.0.15) -> direct

### 'And' rule
dip(geoip:cn) && dport(80) -> direct
dip(8.8.8.8) && l4proto(tcp) && dport(1-1023, 8443) -> my_group
dip(1.1.1.1) && sip(10.0.0.1, 172.20.0.0/16) -> direct

### 'Not' rule
!domain(geosite:google-scholar,
        geosite:category-scholar-!cn,
        geosite:category-scholar-cn
    ) -> my_group

### Little more complex rule
domain(geosite:geolocation-!cn) &&
    !domain(geosite:google-scholar,
            geosite:category-scholar-!cn,
            geosite:category-scholar-cn
        ) -> my_group

### Customized DAT file
domain(ext:"yourdatfile.dat:yourtag")->direct
dip(ext:"yourdatfile.dat:yourtag")->direct

### Set fwmark
# Mark is useful when you want to redirect traffic to specific interface (such as wireguard) or for other advanced uses.

# An example of redirecting Disney traffic to wg0 is given here.
# You need set ip rule and ip table like this:
# 1. Set all traffic with mark 0x800/0x800 to use route table 1145:
# >> ip rule add fwmark 0x800/0x800 table 1145
# >> ip -6 rule add fwmark 0x800/0x800 table 1145
# 2. Set default route of route table 1145:
# >> ip route add default dev wg0 scope global table 1145
# >> ip -6 route add default dev wg0 scope global table 1145
# Notice that interface wg0, mark 0x800, table 1145 can be set by preferences, but cannot conflict.
# 3. Set routing rules in dae config file.
domain(geosite:disney) -> direct(mark: 0x800)

### Skip rules while the target group is not alive
# If a rule is annotated with "skip_while_noalive", it only applies while the target
# group is available. When the group is unavailable, the rule is treated as not hit
# and routing falls through to the following rules (and finally the fallback).
# This is useful when you prefer a specific egress for specific traffic, but do not
# require it: on failure the traffic transparently degrades to the general rules.
# It can be written as a bare parameter or with an explicit value:
domain(geosite:category-games) -> game_proxy(skip_while_noalive)
domain(geosite:category-games) -> game_proxy(skip_while_noalive: true)
# Notes:
# - This rule-level annotation takes precedence over global "no_connectivity_try_sniff":
#   an unavailable target is skipped immediately. The global setting still applies to rules
#   without this annotation.
# - It only works with user-defined groups and direct node targets. Using it with "direct" or "block" is a
#   configuration error because built-in outbounds do not participate in connectivity checks.
# - It cannot be used on the fallback rule.
# - It can be combined with other parameters, e.g. -> my_group(mark: 0x1000, skip_while_noalive).

```

## Flow controls in `rules {}`

`must` skips automatic DNS interception and continues to ordinary outbound selection. `bump` requires userspace routing; `routing {}` still chooses the outbound and mark. These controls are independent of MITM and may both match a connection, regardless of their order. A `must` match does not cancel explicit `bump`, MITM or DNAT capture. The entire flow-control phase runs before handing off to userspace: an ambiguous domain match cannot hide a later definite `must` or capture action.

```text
rules {
    pname(mosdns) -> must
    domain(full: api.example.com) && l4proto(tcp) -> bump
}
routing {
    ip(geoip:cn) -> direct
    domain(geosite:cn) -> direct
    fallback: my_group
}
```

Positive domain filters require an existing DNS mapping to select kernel-direct connections. Unmatched direct traffic stays in eBPF; no broad capture is added to obtain a hostname. Shared-IP ambiguity and negation retain the existing domain matching semantics.

Legacy `routing` actions `must_rules`, `must_direct`, `must_<outbound>`, outbound parameters such as `direct(must)`, and `bump` now produce a migration error, including in `fallback`. Move the control predicate into `rules {}`, and keep the outbound selection in `routing {}`. Unlike an interleaved `must_rules`, the new `must` is evaluated before all ordinary routing rules; narrow its filter if earlier routing rules used to exclude traffic. A fallback-wide control likewise needs an explicit filter with the intended scope.
