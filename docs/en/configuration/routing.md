# Routing

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
# group can serve the traffic's network type (l4proto x ipversion). When the group
# has no dialer alive for that network type, the rule is treated as not hit and
# routing falls through to the following rules (and finally the fallback).
# This is useful when you prefer a specific egress for specific traffic, but do not
# require it: on failure the traffic transparently degrades to the general rules.
# It can be written as a bare parameter (like "must") or with an explicit value:
domain(geosite:category-games) -> game_proxy(skip_while_noalive)
domain(geosite:category-games) -> game_proxy(skip_while_noalive: true)
# Notes:
# - This rule-level annotation takes precedence over global "no_connectivity_try_sniff":
#   an unavailable target is skipped immediately. The global setting still applies to rules
#   without this annotation.
# - It only works with user-defined groups. Using it with "direct" or "block" is a
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
