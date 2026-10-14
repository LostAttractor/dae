# Working Principle of dae

[**简体中文**](../zh/how-it-works.md) | [**English**](./how-it-works.md)

dae uses [eBPF](https://en.wikipedia.org/wiki/EBPF) programs attached through TCX at Linux traffic-control ingress and egress hooks. These programs split traffic before it enters the TCP/IP network stack without creating a `clsact` qdisc. The position of traffic control in the Linux network stack is illustrated below (the diagram shows the receive path; the send path is reversed), where netfilter represents iptables/nftables.

![Network Stack Path](../netstack-path.webp)

## Traffic Splitting Principle

### Splitting Criteria

dae supports traffic splitting based on domain name, source IP, destination IP, source port, destination port, TCP/UDP, IPv4/IPv6, process name, MAC address, and other factors.

Among these, source IP, destination IP, source port, destination port, TCP/UDP, IPv4/IPv6, and MAC address can be obtained by parsing MACv2 frames.

The **process name** is obtained by monitoring local process socket, connect, and sendmsg system calls in the cgroupv2 mount point. It then reads and parses the command line from the process control block. This method is significantly faster than user-space programs like Clash that scan the entire procfs to obtain process information (the latter might take even tens of milliseconds). When WAN interface interception is enabled, the same cgroupv2 attachment identifies dae's own sockets and is therefore required.

The **domain name** is obtained by intercepting DNS requests and associating the requested domain name with the corresponding IP address. However, this method has some potential issues:

1. It might lead to misjudgment. For example, if a domestic and a foreign website sharing the same IP address are accessed simultaneously within a short period, or if the browser employs DNS caching.
2. The user's DNS requests must traverse dae. This can be achieved by setting dae as the DNS server or using a public DNS while dae serves as the gateway.

Despite these challenges, this approach is already an optimal solution compared to other methods. For instance, the Fake IP approach cannot perform IP-based splitting and is plagued by severe cache pollution issues. Similarly, domain sniffing can only intercept traffic like TLS/HTTP. While SNI sniffing for traffic splitting is effective, eBPF's limitations on program complexity and its lack of support for loops prevent us from implementing domain sniffing in the kernel space.

Hence, if DNS requests cannot pass through dae, domain-based splitting will not succeed.

> dae sniffs domains in traffic already admitted to userspace. `dial_target_override` (default `true`) controls whether a verified sniffed domain replaces the dial target, allowing the proxy server to resolve it again. `sniff_verify_mode` (default `loose`) controls verification against DNS records.
>
> `reroute_mode` (default `while_needed`) controls whether information obtained in userspace triggers a new routing evaluation. `force` reevaluates traffic already in userspace; `none` preserves valid kernel routing decisions. Domain sniffing and rerouting do not expand kernel capture predicates.

dae performs traffic splitting in the interface BPF programs. On an interface configured for both roles, TCX runs WAN before LAN on ingress and LAN before WAN on egress. Programs already attached through TCX retain precedence and must return `TCX_NEXT` for dae's programs on the same hook to run. Depending on the result, traffic is either redirected into dae's private Netkit/veth path for proxying or allowed to bypass dae and go directly.

### Proxy Mechanism

The LAN/WAN programs redirect selected packets into a private L2 link pair. dae prefers Netkit with native hooks; when the kernel does not support Netkit, it uses veth with TCX ingress hooks on both ends. Both paths prepare packets for local delivery in dae's network namespace, where a BPF SK_LOOKUP program assigns the TCP or UDP listener from dae's socket map. Both preserve the original destination and return path. The backend does not change capture predicates or send unrelated direct traffic through userspace.

Captured connections that select native TCP direct forwarding use two concurrent Go `io.Copy` workers, allowing the standard library to use Linux `splice(2)`. The upload worker first flushes sniffed bytes while the download worker is already running. EOF half-closes the destination; an error or owner/policy abort closes both endpoints. MPTCP, protocol adapters and connections without usable kernel counters use the ordinary buffered relay. Ingress still uses a listener SOCKMAP and SK_LOOKUP; established relay sockets are not registered in a SOCKHASH.

One Runtime monitor samples accepted payload writes using `TCP_INFO.bytes_acked` and `SIOCOUTQ`, excluding the handshake and FIN. Samples are monotonic lower bounds; each completed copy settles its exact byte count before half-close. Global, per-device, status and Prometheus totals share these counters. Sampling errors preserve the last total and suppress idle decisions. Queries do not sample or close connections.

TCP keepalive and retransmission timeouts on both sockets detect unreachable peers. For peers that stay reachable but never finish, such as proxied streams behind a silent remote or a half-closed peer that never closes its side, ordinary and native TCP relays share a bidirectional payload-idle limit that follows the conntrack policy of the startup network namespace: `net.netfilter.nf_conntrack_tcp_timeout_established` while both directions are open, and `net.netfilter.nf_conntrack_tcp_timeout_close_wait` after either direction half-closes. Missing, invalid or overflowing values use 7440 and 60 seconds. Startup and successful reloads reread both values and apply them to existing relays. The monitor checks every five seconds and rechecks before closing. Payload and half-close renew the limit; ACKs, keepalives and retransmissions alone do not. DNS and MITM retain their protocol-specific lifecycles.

In terms of benchmarking, dae's proxy performance slightly surpasses that of other proxy programs, but the difference is not significant.

### Direct Connection Mechanism

Conventionally, traffic splitting involves passing traffic through a proxy program, navigating the splitting module, and then determining whether to use a proxy or establish a direct connection. This process requires parsing, processing, and copying traffic through the network stack, delivering it to the proxy program, and subsequently copying, processing, and encapsulating it through the network stack before sending it out. This consumes substantial resources. Particularly in scenarios like BitTorrent downloads, even if a direct connection is set, it still consumes numerous connections, ports, memory, and CPU resources. It might even impact NAT type in gaming situations due to the proxy program's inadequate handling, resulting in connection errors.

dae performs traffic splitting at an earlier kernel stage, forwarding directly connected traffic through layer 3 routing. This approach reduces overhead by minimizing transitions between kernel and user space. At this point, Linux functions as a pure switch or router.

> For effective direct connection, advanced users with specific network topologies should ensure that, after configuring the [kernel parameters](user-guide/kernel-parameters.md) and **disabling** dae, other devices can access the network normally when the device with dae is set as the gateway. For instance, accessing 223.5.5.5 should yield a "UrlPathError" response. When performing tcpdump on the dae-equipped device, request packets from client devices should be visible.

Consequently, dae does not perform SNAT for directly connected traffic. In setups with a "side-router," this leads to asymmetric routing. In this scenario, when sent out, traffic from client devices passes through dae to the gateway, but when received, traffic goes directly from the gateway to client devices, bypassing dae.

> Here, "side-router" refers to: 1) functioning as the gateway, 2) performing SNAT on TCP/UDP, and 3) having the LAN and WAN interfaces in the same network segment.
>
> For example, if a laptop is at 192.168.0.3, the side-router is at 192.168.0.2, and the router is at 192.168.0.1, the logical three-layer topology would be: laptop -> side-router -> router. On the router side, only TCP/UDP traffic with a source IP of 192.168.0.2 would be visible, and no TCP/UDP traffic with a source IP of 192.168.0.3 would be present.
>
> To our knowledge, we are the pioneers of this "side-router" definition (laughter).

Asymmetric routing brings an advantage and a potential issue:

1. It can enhance performance. Since return traffic doesn't traverse dae, direct connection performance becomes as swift as without a side-router, reducing the path.
2. It might disrupt stateful firewall's state maintenance and lead to packet loss (e.g., Sophos Firewall). However, this issue generally doesn't occur in home networks.

From a benchmark perspective, dae's direct connectivity performance is formidable compared to other proxy solutions.
