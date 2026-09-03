# Routing

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

`filter: name(name)` is a node-property filter and may match multiple definitions. A standalone `node(name)` stage is a strict typed reference and rejects missing or duplicate node names. `group(name)` strictly references a group without `policy`; selector groups cannot be nested as path stages. Typed references remain unambiguous when a node and group have the same name.

Expansion is statement-major and then terminal-major within each Cartesian path. For `entry-1`, `entry-2` followed by `exit-1`, `exit-2`, the order is `entry-1 -> exit-1`, `entry-2 -> exit-1`, `entry-1 -> exit-2`, then `entry-2 -> exit-2`. `fixed(n)` indexes this stable complete-path order. Separately declared identical physical paths remain separate candidates.

`priority` and `add_latency` annotations add across path stages. dae starts the initial connectivity checks of all paths together. A group stops blocking startup when it has a usable path or all of its blocking paths have completed their initial checks, even if none are available. The global 60-second deadline remains a fallback for checks that do not finish. Inconclusive connectivity modes continue support checks in the background.

Once a connectivity mode is confirmed, dae retains that capability. A node uses one supported mode for regular health checks, and all of its supported modes share the resulting health state.

Latency selection ignores `check_tolerance` until startup completes and once for each newly confirmed mode, so late support can correct selection for new connections. Existing connections remain on their original outbound. `check_async` is a node option rather than a path annotation; configure it on local nodes or through subscription node-option rules. A complete path starts its initial connectivity check asynchronously when any hop enables the option. A group whose relevant paths are all asynchronous does not participate in the startup wait.

```shell
node {
    slow_node: 'socks5://proxy.example:1080' [check_async: true]
}

subscription {
    provider {
        link: 'https://example.com/subscription'
        option {
            check_async: true
            filter: name(fast_node) [check_async: false]
        }
    }
}
```

Subscription defaults are applied first, followed by every matching option rule in declaration order. This allows a later rule to explicitly override `true` with `false`.

The former `[via: ...]` annotation is rejected. Node entries still contain exactly one share link; compose links only with group path expressions.

The legacy `must_name` shorthand is still available. Quote a real node or group name that begins with `must_` (for example, `'must_edge'`) to reference it literally.

To bound health-check and runtime growth, a path may contain at most 16 hops, one routed target may expand to at most 4096 paths, and one configuration may materialize at most 16384 paths.

## Fragmented TCP/UDP

dae supports fragmented TCP and UDP only on an unmarked direct, unmarked pass-through, or trusted control-plane path. Pass-through applies to an established inbound UDP flow or an outbound whose connectivity state is not available. dae never interprets non-initial fragment payload as a transport header. The initial fragment is dropped when routing selects a proxy, `block`, or `direct(mark: ...)`, so the packet cannot be reassembled through a different path. Avoid IP fragmentation when traffic must use a proxy; adjust the application or tunnel MTU instead.

## Examples

```shell
### Built-in outbounds: block, direct, must_rules

# must_rules means no redirecting DNS traffic to dae and continue to matching.
# For single rule, the difference between "direct" and "must_direct" is that "direct" will hijack and process DNS request
# (for traffic split use), but "must_direct" will not. "must_direct" is useful when there are traffic loops of DNS requests.
# "must_direct" can also be written as "direct(must)".
# Similarly, "must_groupname" is also supported to NOT hijack and process DNS traffic, which equals to "groupname(must)".

### fallback outbound
# If no rule matches, traffic will go through the outbound defined by fallback.
fallback: my_group

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
# It can be written as a bare parameter (like "must") or with an explicit value:
domain(geosite:category-games) -> game_proxy(skip_while_noalive)
domain(geosite:category-games) -> game_proxy(skip_while_noalive: true)
# Notes:
# - This rule-level annotation takes precedence over global "no_connectivity_try_sniff":
#   an unavailable target is skipped immediately. The global setting still applies to rules
#   without this annotation.
# - It only works with user-defined groups and direct node targets. Using it with "direct" or "block" is a
#   configuration error because built-in outbounds do not participate in connectivity checks.
# - It cannot be used on the fallback rule.
# - It can be combined with other parameters, e.g. -> my_group(must, skip_while_noalive).

### Must rules
# For following rules, DNS requests will be forcibly redirected to dae except from mosdns.
# Different from must_direct/must_my_group, traffic from mosdns will continue to match other rules.
pname(mosdns) -> must_rules
ip(geoip:cn) -> direct
domain(geosite:cn) -> direct
fallback: my_group
```
