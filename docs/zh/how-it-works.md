# dae 的工作原理

dae 通过 TCX 在 Linux traffic control 的 ingress 和 egress 挂载点加载 [eBPF](https://en.wikipedia.org/wiki/EBPF) 程序，在流量进入 TCP/IP 网络栈之前进行分流，且无需创建 `clsact` qdisc。traffic control 在 Linux 网络协议栈中的位置见下图所示（图为收包路径，发包路径方向相反），其中 netfilter 是 iptables/nftables 的位置。

![](../netstack-path.webp)

## 分流原理

### 分流信息

dae 支持以域名、源 IP、目的 IP、源端口、目的端口、TCP/UDP、IPv4/IPv6、进程名、MAC 地址等对流量进行分流。

其中，源 IP、目的 IP、源端口、目的端口、TCP/UDP、IPv4/IPv6、MAC 地址均可解析 MACv2 帧而得到。

**进程名**通过在 cgroupv2 挂载点侦听本地进程的 socket、connect、sendmsg 系统调用，并读取和解析进程控制块中的命令行来得到的。这种方式会比 clash 等用户态程序对传入的 socket 扫描整个 procfs 来得到进程信息要快得多（后者甚至是 10ms 级的）。进程记录在 socket 自身，随 socket 释放；内核创建的 MPTCP 子流归属其连接所属的进程。启用 WAN 接口流量拦截时，同一组 cgroupv2 程序还用于识别 dae 自身的 socket，因此 cgroupv2 挂载和挂接必须可用；dae 在建立出站连接之前完成挂接。

**域名**通过劫持 DNS 请求，将 DNS 请求的域名与所查 IP 进行关联来得到。尽管这种方式有一些问题：

1. 可能会出现误判。例如需要分流到国内和国外的两个网站拥有同一个 IP，且在短时间内同时被访问，或浏览器有 DNS 缓存。
2. 用户的 DNS 请求必须通过 dae。例如将 dae 设为 DNS，或在 dae 作为网关的情况下使用公共 DNS。

但相比其他方案，这种方案已经是较优解了。例如 Fake IP 方案存在无法通过 IP 分流且存在严重的缓存污染问题，而域名嗅探方案存在只能嗅探 TLS/HTTP 等流量的问题。实际上，通过 SNI 嗅探来进行分流确实是更优选择，但由于 eBPF 对程序复杂度的限制，以及对循环的支持不友好，我们无法在内核空间实现域名嗅探。

因此，当 DNS 请求无法通过 dae 时，基于 domain 的分流将会失效。

> dae 在用户空间对已导入的流量进行域名嗅探。`dial_target_override`（默认 `true`）控制代理连接是否使用通过验证的嗅探域名作为拨号目标，使代理服务器能够重新解析域名；direct 连接始终拨号客户端选择的目标 IP，地址族由客户端选择，客户端尝试的每个地址都经过路由；`sniff_verify_mode`（默认 `loose`）控制域名与 DNS 记录的验证方式。
>
> `reroute_mode`（默认 `while_possible`）控制是否根据用户态补充的信息重新匹配路由：`while_needed` 按通过验证的嗅探域名重新匹配已进入用户态的流量；`while_possible` 还让无可用节点的组的流量进入用户态而不在内核降级，以便重路由到可用出口；`none` 保留有效的内核路由决定。只有通过验证的域名才能改变有效的内核路由决定；没有可信域名时，内核交给用户态决定的流量沿用目标 IP 的 DNS 映射，与内核依据相同，歧义无法消除时拒绝。域名嗅探和重新匹配路由不扩大内核捕获范围。

dae 通过接口上的 BPF 程序进行流量分流。同一接口同时作为 WAN 和 LAN 时，TCX 在 ingress 按 WAN、LAN 顺序执行，在 egress 按 LAN、WAN 顺序执行。已经挂载的 TCX 程序保留优先级，并且必须返回 `TCX_NEXT`，dae 在同一 hook 上的程序才会继续执行。程序根据分流结果决定将流量重定向到私有 Netkit/veth 代理路径或直接放行。

### 代理原理

LAN/WAN 程序会把需要代理的流量重定向到私有 L2 设备对。dae 优先使用 Netkit 原生 hook；内核不支持 Netkit 时使用 veth，并在两端挂载 TCX ingress hook。两条路径都为 dae 网络命名空间内的本地投递准备数据包，再由 BPF SK_LOOKUP 程序从 socket map 中选择 TCP 或 UDP 监听 socket，保留原始目的地址和回包路径。设备类型不改变捕获条件，无关 direct 流量仍在内核直通。

已捕获且最终选择原生 TCP 直连的连接使用两个并行的 Go `io.Copy`，由标准库启用 Linux `splice(2)`。上传方向先写出嗅探缓冲，此时下载方向已在运行。EOF 半关闭目标连接；错误、连接所有者中止或策略变更会关闭两端。MPTCP、协议包装和内核计数不可用的连接使用普通缓冲复制。入口继续通过监听 socket 的 SOCKMAP 和 SK_LOOKUP 投递；已建立的转发连接不加入 SOCKHASH。

Runtime 共用一个监控器，利用 `TCP_INFO.bytes_acked` 和 `SIOCOUTQ` 统计目标 socket 已接纳的有效载荷，排除握手和 FIN。运行中的采样保留单调下界，每个复制方向结束后用实际复制量精确结算，再发送 FIN。全局、设备、status 和 Prometheus 共用这些计数。采样失败时保留已有计数，并暂停该连接的空闲判断；状态查询不会触发采样或关闭连接。

对端不可达由两侧 socket 的 TCP keepalive 和重传超时发现。对端仍可达但连接不再结束时（例如远端静默的代理流，或半关闭后对端不再关闭），普通与原生 TCP 转发共用双向有效载荷空闲回收，超时沿用启动网络命名空间的 conntrack 策略：双向打开时使用 `net.netfilter.nf_conntrack_tcp_timeout_established`，任一方向半关闭后使用 `net.netfilter.nf_conntrack_tcp_timeout_close_wait`；缺失、非法或溢出时分别使用 7440 秒和 60 秒。启动和成功 reload 时重新读取，并同时作用于存量连接。监控器每五秒检查一次，关闭前再次确认。有效载荷和半关闭续期，纯 ACK、keepalive 和重传不续期。DNS、MITM 保留各自的协议生命周期。

节点入口 TCP socket 空闲 15 秒后发送 keepalive，间隔 5 秒，连续三次没有应答后关闭。这可以在约 30 秒内发现空闲连接失联，但不覆盖已有待发数据的连接。普通 TCP socket 在 Linux 6.15 及更新内核上还通过 `TCP_RTO_MAX_MS` 将重传和零窗口探测间隔限制为 15 秒。当对端把窗口收缩到零、同时仍有在途数据时，Linux 使用这个上限的两倍作为接收静默超时阈值；15 秒上限使该阈值保持为 30 秒。在默认 `net.ipv4.tcp_retries2=15` 下，其他已建立连接的黑洞可能需要数分钟才失败，具体取决于重传或探测状态，并不存在统一的 30 秒期限。

持续应答零窗口探测的对端可以保持连接。dae 不设置 `TCP_USER_TIMEOUT`，因为它也会中止这种存活但背压的连接。旧内核及 MPTCP socket（包括已回落为 TCP 的 socket）保留内核重传策略，失败可能更慢。这些 socket 设置不作用于直连、bootstrap DNS 或 UDP socket，不替代路径健康确认，也不修改系统 sysctl。

`mptcp: true` 时，连接节点只对协商成功过 MPTCP 的地址使用 MPTCP。Linux 不记录哪些目的地支持 MPTCP，对端以普通 TCP 应答的连接终身保留 MPTCP socket。因此 dae 按 mark 和 interface 分别对每个节点地址用 MPTCP 拨号，直到有一次这样的连接完成：协商成功的地址继续使用 MPTCP，其余地址改用普通 TCP。回落的探测连接继续使用，不会重新拨号；它保留的 MPTCP socket 无法设置 `TCP_RTO_MAX_MS`，之后连接该地址时使用的普通 TCP socket 则可以设置。探测进行期间发起的连接使用普通 TCP，失败或被取消的探测不记录结果。每次 `dae reload` 都会清空记录，配置未变时也是如此；资源刷新保留记录。直连始终尝试 MPTCP。

`tcp_fast_open: true` 时，经普通 TCP 连接节点的 socket 设置 `TCP_FASTOPEN_CONNECT`，包括 `mptcp` 改用普通 TCP 的地址，以及经这些连接转发的 DNS 和 UDP 流量；MPTCP 连接、直连、UDP socket 和节点地址解析不使用。对一个服务器的首次连接是请求 Fast Open cookie 的完整握手。内核持有 cookie 后，之后的拨号在发出 SYN 之前返回，SYN 随第一次写出发送并携带这些数据，省去一个往返，健康检查测得的延迟也相应减少。节点连接总是先写：TLS 和传输层握手，或随首个载荷、在首次读取前发出的代理请求。因此连接失败改在首次读写时出现，而不是在拨号时。拨号期间完成握手的节点（例如 SOCKS5、HTTP 和经 TLS 的节点）仍在拨号预算内失败。没有这类握手的节点，例如 Shadowsocks，以及不带 TLS、直接经 TCP 的 VMess 或 VLESS，其连接建立沿用内核 SYN 重试策略及 socket 支持的重传设置，而非固定 30 秒期限；转发连接 8 s 内没有应答时仍会触发故障确认。同理，拨号持有 cookie 的不可达节点地址时，不再回落到该节点的其他地址。节点服务器必须启用 Fast Open：`net.ipv4.tcp_fastopen` 的服务端位，以及监听 socket 上的 `TCP_FASTOPEN`。未启用的服务器不下发 cookie，连接保持完整握手。dae 所在网络命名空间的 `net.ipv4.tcp_fastopen` 需包含客户端位（1，默认开启）；内核拒绝该选项时 dae 记录一次日志。

以 benchmark 来看，dae 的代理性能比其他代理程序好一些，但不多。

### 直连原理

一直以来，为了分流，流量需要经过代理程序，经过分流模块之后，再决定是直连还是代理。这样流量需要经过网络栈的解析、处理、拷贝，传入代理程序，再通过网络栈拷贝、处理、封装，然后传出，消耗大量资源。特别是对于 BT 下载等场景，尽管设置了直连，仍然会占用大量连接数、端口、内存、CPU 资源。甚至对于游戏的场景，会由于代理程序的处理不当而影响 NAT 类型，导致连接出错。

dae 在内核的较早路径上就对流量进行了分流，直连流量将直接进行三层路由转发，节省了大量内核态到用户态的切换和拷贝开销，此时 Linux 相当于一个纯粹的交换机或路由器。

> 为了让直连生效，对于高级拓扑的用户，请确保按 [kernel-parameters](../en/user-guide/kernel-parameters.md) 配置后，在**关闭** dae 的情况下，其他设备将 dae 所在设备设为网关时，网络是畅通的。例如访问 223.5.5.5 能够得到“UrlPathError”的响应，且在 dae 所在设备进行 tcpdump 可以看到客户端设备的请求报文。

因此，对于直连流量，dae 不会进行 SNAT，对于“旁路由”用户，这将形成非对称路由，即客户端设备发包时流量通过 dae 设备发送到网关，收包时由网关直接发给客户端设备，绕过 dae 设备。

> 这里的旁路由定义为：1，被设为网关。2，对 TCP/UDP 进行 SNAT。3，LAN 接口和 WAN 接口属于同一个网段。
>
> 例如笔记本电脑在 192.168.0.3，旁路由在 192.168.0.2，路由器在 192.168.0.1。三层逻辑拓扑为：笔记本电脑 -> 旁路由 -> 路由器，且在路由器一侧只能看到源 IP 是 192.168.0.2 的 TCP/UDP 流量，而没有 192.168.0.3 的 TCP/UDP 流量。
>
> 据目前所知，我们是第一个对旁路由进行定义的（笑）。

非对称路由将带来一个优点和一个可能的问题：

1. 会带来性能提升。由于回包不经过 dae，减少了路径，直连性能将变得和没有旁路由一样快。
2. 会导致高级防火墙的状态维护失效从而丢包（例如 Sophos Firewall）。这一问题在家用网络中一般不会出现。

以 benchmark 来看，dae 的直连性能和其他代理程序相比就像个怪物。
