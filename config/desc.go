/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

type Desc map[string]string

var SectionSummaryDesc = Desc{
	"mitm":         "Shared HTTP/TLS certificates, client selection and body memory settings.",
	"plugins":      "Ordered, statically compiled Go plugin instances, including HTTP and DNS processing.",
	"rules":        "Flow rules: filter() -> must, bump or dnat(ip). must skips automatic DNS interception; bump requires userspace routing; first matching DNAT overrides the dial IP. Outbound selection remains in routing.",
	"subscription": "Subscriptions defined here will be resolved as nodes and merged as a part of the global node pool. Expanded subscription descriptors can set default or filtered node options such as multiplex.\nSupport to give the subscription a tag, and filter nodes from a given subscription in the group section.",
	"node":         "Nodes defined here will be merged as a part of the global node pool. A uniquely named node can also be used directly as a routing target. Inline annotations configure node options such as multiplex.",
	"group":        "Proxy path groups. Declare ordered stages with ->. Groups with a policy select complete paths; policyless groups can be referenced as reusable path stages.",
	"client":       "Dynamic MAC sets: name { description: 'text' ipset: kernel_name nftset: 'family/table/set' }. All fields are optional. The device page shows sets referenced by client(name) routing rules or configured for kernel export. Configuration reloads update descriptions and exports; membership is stored separately.",
	"routing": `Traffic follows this routing. See https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/routing.md for full examples.
rule_set contains reusable rules and ordered uses; use: a, b inserts both fragments in order.
filter() -> use(a, b) ANDs the filter with every referenced rule; nested use conditions accumulate.
policy declares complete policies with exactly one fallback each. Fragments cannot contain fallback.
default: policy_name and interface { device: policy_name } select policies; configure global capture bindings separately.
Inline rules/use/fallback define an anonymous default policy and cannot be combined with default: policy_name.
Declare each routing block once across included files. MITM and DNAT/Host capture is shared automatically across policies.
Notice: domain traffic split will fail if DNS traffic is not taken over by dae.
Built-in outbounds: direct, block. Flow controls must and bump belong in rules {}.
Available functions: domain, sip, dip, sport, dport, ipversion, l4proto, pname, mac, client, dscp, interface.
Available keys in domain function: suffix, keyword, regex, full. No key indicates suffix.
domain: Match domain.
sip: Match source IP. CIDR format is also supported.
dip: Match dest IP. CIDR format is also supported.
sport: Match source port. Range like 8000-9000 is also supported.
dport: Match dest port. Range like 8000-9000 is also supported.
ipversion: Match IP version. Available values: 4, 6.
l4proto: Match level 4 protocol. Available values: tcp, udp.
pname: Match process name. It only works on WAN mode and for localhost programs.
mac: Match source MAC address. It works on LAN mode.
client: Match a dynamic MAC set whose members join or leave through the device API.
dscp: Match the DSCP value.
interface: Match the interface that received the traffic.`,
}

var SectionDescription = map[string]Desc{
	"MITMDesc":   MITMDesc,
	"GlobalDesc": GlobalDesc,
	"GroupDesc":  GroupDesc,
	"ClientDesc": ClientDesc,
}

var ClientDesc = Desc{
	"description": "Plain text shown below the set name on the device page.",
	"ipset":       "Export members to a dedicated hash:mac ipset. Missing sets are created; existing members are replaced. Requires kernel support and CAP_NET_ADMIN.",
	"nftset":      "Export members to a dedicated ether_addr nftables set, specified as family/table/set. Missing tables and sets are created; existing members are replaced. Requires kernel support and CAP_NET_ADMIN.",
}

var MITMDesc = Desc{
	"buffer_memory_limit":   "Process-wide managed body buffer budget in bytes, shared across plugin instances and reloads. Defaults to 256 MiB. Exhaustion skips Surge body processing and preserves the original stream. Does not limit RSS, native script heaps or arbitrary plugin allocations.",
	"enabled":               "Enable HTTP/TLS interception. DNS plugins, routing contributions and background tasks are configured independently in plugins{}.",
	"ca_cert":               "Shared PEM CA certificate path; required by HTTPS plugins. Destination-only plugins need no CA.",
	"ca_key":                "Shared PEM CA private key path.",
	"client_source_address": "HTTP/MITM client selection; per-device settings take precedence. Does not gate destination rules.",
	"_":                     "Ordered named plugin instances. The section name is the instance ID; type defaults to that name. Each plugin decodes its own settings.",
}

var GlobalDesc = Desc{
	"resource_cache":           "Cache validated HTTP/HTTPS configuration resources (subscriptions, Surge modules and dependencies). Network-first with fallback on download or validation failure. Defaults to true; false disables disk cache reads, writes and cleanup. Accepted resources remain available in memory while running.",
	"resource_update_interval": "Automatic refresh interval for remote subscriptions, modules and dependencies. Defaults to 24h; 0 disables these automatic checks. Surge script-update-interval controls individual remote scripts. Reload and the resource refresh API always attempt downloads.",
	"dns_resolver":             "Optional DNS server for dae's internal lookups: IP or IP:port (default port 53). Empty uses Go's system resolver. Bootstrap is direct; once ready, DNS transports follow routing rules. Proxy-server names use direct bootstrap to avoid circular dependencies. Supports reload.",
	"dns_retention_window":     "Sliding retention policy for observed domain-IP evidence, not a measured client cache lifetime. Defaults to 168h (seven days); must be positive. Delivered DNS uses max(TTL, window); observed traffic refreshes existing pairs by this window. Uncaptured kernel-direct traffic is not observed.",
	"api_port":                 "HTTP port for the global configuration page, device API and certificate downloads. Zero disables the listener. Use the router IP address directly.",
	"api_key":                  "Optional administrator API key for runtime status and selector groups. Empty allows verified, directly connected LAN clients to administer without login. When configured, administration requires the key or a browser session. Current-device controls always require direct LAN identification.",
	"tproxy_port":              "Internal transparent-proxy listener port. It is not an HTTP/SOCKS port and normally does not need to be changed.",
	"tproxy_port_protect":      "Set it true to protect tproxy port from unsolicited traffic. Set it false to allow users to use self-managed iptables tproxy rules.",
	"so_mark_from_dae":         "SO_MARK applied to traffic and hostname lookups sent by dae for policy routing. Zero or unset uses the reserved internal mark 0x100. A non-zero value overrides that mark and requires a restart to change. Ensure local fwmark rules do not accidentally match the selected value. Values containing the reserved tproxy bit 0x08000000 are rejected. The mark alone is never trusted as control-plane identity. Marked lookups use Go's resolver; hostname sources provided only by libc NSS modules are not supported.",
	"log_level":                "Log level: error (feature failure), warn (degradation), info (lifecycle and availability), debug (connections and requests), trace (packets and processing steps).",
	"udp_check_dns":            "This DNS will be used to check UDP connectivity of nodes. And if dns_upstream below contains tcp, it also be used to check TCP DNS connectivity of nodes.\nThis DNS should have both IPv4 and IPv6 if you have double stack in local.",
	"check_interval":           "Interval of connectivity checks while the node is alive.",
	"check_interval_max":       "Maximum interval for failed health checks and background connectivity-mode support retries.",
	"check_tolerance":          "Ignored during startup and once for each newly confirmed connectivity mode; otherwise a new node must improve latency by more than this value.",
	"lan_interface":            "The LAN interface to bind. Use it if you want to proxy LAN.",
	"wan_interface":            "The WAN interface to bind. Use it if you want to proxy localhost. Use \"auto\" to follow host default routes.",
	"allow_insecure":           "Allow insecure TLS certificates. It is not recommended to turn it on unless you have to.",
	"route_change_behavior":    "Keep (default) or close old connections when a device joins/leaves a routing-referenced client set, or when a group recovers from direct fallback. Membership changes affect that device across TCP/UDP and IPv4/IPv6; recovery affects only that group/network's fallback connections.",
	"dial_mode": `Optional values of dial_mode are:
1. "ip". Dial proxy using the IP from DNS directly. This allows your ipv4, ipv6 to choose the optimal path respectively, and makes the IP version requested by the application meet expectations. For example, if you use curl -4 ip.sb, you will request IPv4 via proxy and get a IPv4 echo. And curl -6 ip.sb will request IPv6. This may solve some weird full-cone problem if your are be your node support that.Sniffing will be disabled in this mode.
2. "domain". Dial proxy using the domain from sniffing. This will relieve DNS pollution problem to a great extent if have impure DNS environment. Generally, this mode brings faster proxy response time because proxy will re-resolve the domain in remote, thus get better IP result to connect. This policy does not impact routing. That is to say, domain rewrite will be after traffic split of routing and dae will not re-route it.
3. "domain+". Based on domain mode but do not check the reality of sniffed domain. It is useful for users whose DNS requests do not go through dae but want faster proxy response time. Notice that, if DNS requests do not go through dae, dae cannot split traffic by domain.
4. "domain++". Based on domain+ mode but force to re-route traffic using sniffed domain to partially recover domain based traffic split ability. It doesn't work for direct traffic and consumes more CPU resources.`,
	"disable_waiting_network":      "Disable waiting for network before pulling subscriptions.",
	"auto_config_kernel_parameter": "Automatically configure Linux kernel parameters like ip_forward and send_redirects. Check out https://github.com/daeuniverse/dae/blob/main/docs/en/user-guide/kernel-parameters.md to see what will dae do.",
	"sniffing_timeout":             "Timeout to waiting for first data sending for sniffing. It is always 0 if dial_mode is ip. Set it higher is useful in high latency LAN network.",
	"tls_implementation":           "TLS implementation. \"tls\" is to use Go's crypto/tls. \"utls\" is to use uTLS, which can imitate browser's Client Hello.",
	"utls_imitate":                 "The Client Hello ID for uTLS to imitate. This takes effect only if tls_implementation is utls. See more: https://github.com/daeuniverse/dae/blob/331fa23c16/component/outbound/transport/tls/utls.go#L17",
	"mptcp":                        "Enable Multipath TCP.  If is true, dae will try to use MPTCP to connect all nodes, but it will only take effects when the node supports MPTCP. It can use for load balance and failover to multiple interfaces and IPs.",
}

var GroupDesc = Desc{
	"reselect_behavior": "How to handle existing connections when the selected node changes: keep (default) or close. Applies to the changed TCP/UDP and IPv4/IPv6 combination, including retained fallback connections belonging to this group. Not supported with policy: random. Not inherited through group(name).",
	"path":              `Each statement declares one candidate proxy path. Join stages from client to destination with ->. A stage can be "filter: expression", "node(name)", or "group(name)". Filter stages expand all matching nodes; node references require one uniquely named node; group references expand a policyless group. Multiple stages form a Cartesian product. Stage priority and add_latency annotations are accumulated across the complete path.`,
	"filter": `Filter nodes from the global node pool defined by the "subscription" and "node" sections. A standalone filter declares a one-stage path. Use "filter: name(name)" for property matching; the strict "node(name)" reference stage instead requires one uniquely named node.
Available functions: name, subtag, link, protocol. Not operator is supported.
Available keys in name, link and protocol functions: keyword, regex. No key indicates full match.
Available keys in subtag function: regex. No key indicates full match.`,
	"policy": `Optional dialer selection policy. It selects one complete expanded proxy path for each new connection.
	If omitted, the group can be referenced by group(name) as a reusable path stage. It may also be used as a routing target when it expands to exactly one path.
Available values: random, fixed, selector, min, min_avg10, min_moving_avg, failover.
random: Select a complete path randomly.
fixed: Select the complete path at the stable expanded index.
selector: Select a path through the global API. Without an index, the initial choice is the first path and there is no configured default or reset operation. selector(n) explicitly sets a zero-based default index. Saved choices are restored first. Only the selected path is checked unless track_all is enabled; the probe API supports one-shot checks.
min: Select a path by the latency of its last check.
min_avg10: Select a path by the average of its last 10 check latencies.
min_moving_avg: Select a path by its moving average of check latencies, which gives recent checks more weight.
failover: Disable periodic latency checks on the healthy current path and same-tier peers. Real test results still trigger reselection by degradation, priority and last successful latency plus add_latency, respecting check_tolerance. Replacement candidates require a successful connectivity proof; candidates are tested concurrently within each tier with bounded timeouts. Higher-priority candidates are checked separately for promotion.
Automatic policies prefer non-degraded paths before priority and latency score. Only successful probes enter latency statistics. min_moving_avg accepts alpha: value (default 0.18).
`,
	"failure_recovery":     "Continuously monitored recovery window after the first successful probe (default 30s). Checks run at min(check_interval, 5s), with a final successful probe at the window boundary. Failure or paused observation restarts an incomplete window; verified degraded paths remain eligible for fallback.",
	"probe_timeout":        "Deadline for one selection test, including queueing, session connection and verification (default 3s).",
	"selection_timeout":    "Deadline for each selection round and each request's total selection wait (default 15s).",
	"upgrade_interval":     "Initial interval for discovering higher-priority or recovered candidates (default 3m).",
	"upgrade_interval_max": "Maximum backoff for unsuccessful promotion and group recovery checks (default 1h).",
	"udp_check_dns":        "Override global config.",
	"check_interval":       "Override global config when non-zero.",
	"check_interval_max":   "Override global config when non-zero.",
	"check_tolerance":      "Override global config.",
	"check_async":          "Skip startup waiting for this group. Defaults to true when all active routing uses specify skip_while_noalive; fallback defaults to false. Unused targets are not instantiated. Explicit values override this default. Not inherited through group(name).",
	"track_all":            "For selector policy only: continuously check all nodes instead of only the current selection. Defaults to false. Config-only; reload to apply. The startup barrier still waits only for the selected node. Not inherited through group(name).",
}
