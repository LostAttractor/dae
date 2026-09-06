/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

type Desc map[string]string

var SectionSummaryDesc = Desc{
	"subscription": "Subscriptions defined here will be resolved as nodes and merged as a part of the global node pool. Expanded subscription descriptors can set default or filtered node options such as multiplex.\nSupport to give the subscription a tag, and filter nodes from a given subscription in the group section.",
	"node":         "Nodes defined here will be merged as a part of the global node pool. A uniquely named node can also be used directly as a routing target. Inline annotations configure node options such as multiplex.",
	"dns":          "See more at https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/dns.md.",
	"group":        "Proxy path groups. Declare ordered stages with ->. Groups with a policy select complete paths; policyless groups can be referenced as reusable path stages.",
	"client":       "Dynamic MAC sets: name { description: 'text' ipset: kernel_name nftset: 'family/table/set' }. All fields are optional. The device page shows sets referenced by client(name) routing rules or configured for kernel export. Configuration reloads update descriptions and exports; membership is stored separately.",
	"routing": `Traffic follows this routing. See https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/routing.md for full examples.
Notice: domain traffic split will fail if DNS traffic is not taken over by dae.
Built-in outbound: direct, must_direct, block.
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
	"SurgeDesc":  SurgeDesc,
	"GlobalDesc": GlobalDesc,
	"DnsDesc":    DnsDesc,
	"GroupDesc":  GroupDesc,
	"ClientDesc": ClientDesc,
}

var ClientDesc = Desc{
	"description": "Plain text shown below the set name on the device page.",
	"ipset":       "Export members to a dedicated hash:mac ipset. Missing sets are created; existing members are replaced. Requires kernel support and CAP_NET_ADMIN.",
	"nftset":      "Export members to a dedicated ether_addr nftables set, specified as family/table/set. Missing tables and sets are created; existing members are replaced. Requires kernel support and CAP_NET_ADMIN.",
}

var SurgeDesc = Desc{
	"enabled":                "Enable Surge modules, including routing and destination rewrites. HTTPS interception requires clients to trust the configured CA.",
	"module":                 "Ordered module sources in module { name: 'source' }, with optional unique names. Arguments require a named block: module { youtube { link: 'source' arguments { '屏蔽上传按钮=false' '字幕翻译语言=zh-CN' } } }. Each argument is one quoted name=value string, split at the first '='; names are trimmed and values stay literal, including empty values. Use file:relative or file:///absolute for local modules, http:// or https:// for remote modules, and http-file:// or https-file:// for explicit persistent cache fallback. Ordinary HTTP(S) sources do not fall back to cache. Reload with dae reload.",
	"client_source_address":  "Ordered 'all', IPv4/IPv6 addresses, CIDRs or 6-byte MAC addresses for module HTTP/MITM processing. First match wins; '-' excludes. Omitted or unmatched clients bypass; use 'all' to enable every client. Comma-separated quoted values and repeated fields are accepted. Persistent per-device API settings override this list, including explicit off. This does not detect CA trust or change routing policies.",
	"ca_cert":                "PEM CA certificate path, relative to DAE_LOCATION_CACHE, default /var/lib/dae. Generate with dae mitm ca generate.",
	"ca_key":                 "PEM CA private key path, relative to DAE_LOCATION_CACHE, default /var/lib/dae. Keep it readable only by the daemon owner.",
	"store":                  "Optional JSON file for the scripts' persistent store, relative to DAE_LOCATION_CACHE, default /var/lib/dae. Empty uses memory only.",
	"script_timeout":         "Maximum time per script, including HTTP callbacks. Module timeout may lower this limit.",
	"memory_limit":           "QuickJS memory limit per script in bytes (16 MiB to 1 GiB).",
	"max_body_size":          "Maximum buffered/decompressed body in bytes. Overrides unlimited module max-size=-1.",
	"max_concurrent_scripts": "Maximum simultaneous QuickJS invocations; bounds aggregate script memory.",
}

var GlobalDesc = Desc{
	"api_port":            "HTTP port for the global configuration page, device API and certificate downloads. Zero disables the listener. Use the router IP address directly.",
	"api_token":           "Administrator bearer token required to change selector groups. Empty disables selector writes; current-device controls require a directly connected LAN client, but no token.",
	"tproxy_port":         "Internal transparent-proxy listener port. It is not an HTTP/SOCKS port and normally does not need to be changed.",
	"tproxy_port_protect": "Set it true to protect tproxy port from unsolicited traffic. Set it false to allow users to use self-managed iptables tproxy rules.",
	"so_mark_from_dae":    "SO_MARK applied to traffic and hostname lookups sent by dae for policy routing. Zero or unset uses the reserved internal mark 0x100. A non-zero value overrides that mark and requires a restart to change. Ensure local fwmark rules do not accidentally match the selected value. Values containing the reserved tproxy bit 0x08000000 are rejected. The mark alone is never trusted as control-plane identity. Marked lookups use Go's resolver; hostname sources provided only by libc NSS modules are not supported.",
	"log_level":           "Log level: error, warn, info, debug, trace.",
	"udp_check_dns":       "This DNS will be used to check UDP connectivity of nodes. And if dns_upstream below contains tcp, it also be used to check TCP DNS connectivity of nodes.\nThis DNS should have both IPv4 and IPv6 if you have double stack in local.",
	"check_interval":      "Interval of connectivity checks while the node is alive.",
	"check_interval_max":  "Maximum interval for failed health checks and background connectivity-mode support retries.",
	"check_tolerance":     "Ignored during startup and once for each newly confirmed connectivity mode; otherwise a new node must improve latency by more than this value.",
	"lan_interface":       "The LAN interface to bind. Use it if you want to proxy LAN.",
	"wan_interface":       "The WAN interface to bind. Use it if you want to proxy localhost. Use \"auto\" to follow host default routes.",
	"allow_insecure":      "Allow insecure TLS certificates. It is not recommended to turn it on unless you have to.",
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

var DnsDesc = Desc{
	"ipversion_prefer": "For example, if ipversion_prefer is 4 and the domain name has both type A and type AAAA records, the dae will only respond to type A queries and response empty answer to type AAAA queries.",
	"fixed_domain_ttl": "Give a fixed ttl for domains. Zero means that dae will request to upstream every time and not cache DNS results for these domains.",
	"upstream":         "Value can be scheme://host:port, where the scheme can be tcp/udp/tcp+udp.\nIf host is a domain and has both IPv4 and IPv6 record, dae will automatically choose IPv4 or IPv6 to use according to group policy (such as min latency policy).\nPlease make sure DNS traffic will go through and be forwarded by dae, which is REQUIRED for domain routing.\nIf dial_mode is \"ip\", the upstream DNS answer SHOULD NOT be polluted, so domestic public DNS is not recommended.",
	"request": `DNS requests will follow this routing.
Built-in outbound: asis.
Available functions: qname, qtype, dip, sip, interface`,
	"response": `DNS responses will follow this routing.
Built-in outbound: accept, reject.
Available functions: qname, qtype, ip, upstream`,
}

var GroupDesc = Desc{
	"path": `Each statement declares one candidate proxy path. Join stages from client to destination with ->. A stage can be "filter: expression", "node(name)", or "group(name)". Filter stages expand all matching nodes; node references require one uniquely named node; group references expand a policyless group. Multiple stages form a Cartesian product. Stage priority and add_latency annotations are accumulated across the complete path.`,
	"filter": `Filter nodes from the global node pool defined by the "subscription" and "node" sections. A standalone filter declares a one-stage path. Use "filter: name(name)" for property matching; the strict "node(name)" reference stage instead requires one uniquely named node.
Available functions: name, subtag, link, protocol. Not operator is supported.
Available keys in name, link and protocol functions: keyword, regex. No key indicates full match.
Available keys in subtag function: regex. No key indicates full match.`,
	"policy": `Optional dialer selection policy. It selects one complete expanded proxy path for each new connection.
	If omitted, the group can be referenced by group(name) as a reusable path stage. It may also be used as a routing target when it expands to exactly one path.
Available values: random, fixed, selector, min, min_avg10, min_moving_avg.
random: Select a complete path randomly.
fixed: Select the complete path at the stable expanded index.
selector: Select a path through the global API. Defaults to the first path; selector(n) sets another zero-based default index.
min: Select a path by the latency of its last check.
min_avg10: Select a path by the average of its last 10 check latencies.
min_moving_avg: Select a path by its moving average of check latencies, which gives recent checks more weight.
`,
	"udp_check_dns":      "Override global config.",
	"check_interval":     "Override global config when non-zero.",
	"check_interval_max": "Override global config when non-zero.",
	"check_tolerance":    "Override global config.",
	"check_async":        "Skip startup waiting for this group. Defaults to true when all routing uses specify skip_while_noalive (including unused groups); fallback defaults to false. Explicit values override this default. Not inherited through group(name).",
}
