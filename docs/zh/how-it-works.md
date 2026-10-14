# dae 的工作原理

dae 通过 TCX 在 Linux traffic control 的 ingress 和 egress 挂载点加载 [eBPF](https://en.wikipedia.org/wiki/EBPF) 程序，在流量进入 TCP/IP 网络栈之前进行分流，且无需创建 `clsact` qdisc。traffic control 在 Linux 网络协议栈中的位置见下图所示（图为收包路径，发包路径方向相反），其中 netfilter 是 iptables/nftables 的位置。

![](../netstack-path.webp)

## 分流原理

### 分流信息

dae 支持以域名、源 IP、目的 IP、源端口、目的端口、TCP/UDP、IPv4/IPv6、进程名、MAC 地址等对流量进行分流。

其中，源 IP、目的 IP、源端口、目的端口、TCP/UDP、IPv4/IPv6、MAC 地址均可解析 MACv2 帧而得到。

**进程名**通过在 cgroupv2 挂载点侦听本地进程的 socket、connect、sendmsg 系统调用，并读取和解析进程控制块中的命令行来得到的。这种方式会比 clash 等用户态程序对传入的 socket 扫描整个 procfs 来得到进程信息要快得多（后者甚至是 10ms 级的）。启用 WAN 接口流量拦截时，同一组 cgroupv2 程序还用于识别 dae 自身的 socket，因此 cgroupv2 挂载和挂接必须可用。

**域名**通过劫持 DNS 请求，将 DNS 请求的域名与所查 IP 进行关联来得到。尽管这种方式有一些问题：

1. 可能会出现误判。例如需要分流到国内和国外的两个网站拥有同一个 IP，且在短时间内同时被访问，或浏览器有 DNS 缓存。
2. 用户的 DNS 请求必须通过 dae。例如将 dae 设为 DNS，或在 dae 作为网关的情况下使用公共 DNS。

但相比其他方案，这种方案已经是较优解了。例如 Fake IP 方案存在无法通过 IP 分流且存在严重的缓存污染问题，而域名嗅探方案存在只能嗅探 TLS/HTTP 等流量的问题。实际上，通过 SNI 嗅探来进行分流确实是更优选择，但由于 eBPF 对程序复杂度的限制，以及对循环的支持不友好，我们无法在内核空间实现域名嗅探。

因此，当 DNS 请求无法通过 dae 时，基于 domain 的分流将会失效。

> dae 在用户空间对已导入的流量进行域名嗅探。`dial_target_override`（默认 `true`）控制是否使用通过验证的嗅探域名覆盖拨号目标，使代理服务器能够重新解析域名；`sniff_verify_mode`（默认 `loose`）控制域名与 DNS 记录的验证方式。
>
> `reroute_mode`（默认 `while_needed`）控制是否根据用户态补充的信息重新匹配路由；`force` 强制重新匹配已进入用户态的流量，`none` 保留有效的内核路由决定。域名嗅探和重新匹配路由不扩大内核捕获范围。

dae 通过接口上的 BPF 程序进行流量分流。同一接口同时作为 WAN 和 LAN 时，TCX 在 ingress 按 WAN、LAN 顺序执行，在 egress 按 LAN、WAN 顺序执行。已经挂载的 TCX 程序保留优先级，并且必须返回 `TCX_NEXT`，dae 在同一 hook 上的程序才会继续执行。程序根据分流结果决定将流量重定向到私有 Netkit/veth 代理路径或直接放行。

### 代理原理

LAN/WAN 程序会把需要代理的流量重定向到私有 L2 设备对。dae 优先使用 Netkit 原生 hook；内核不支持 Netkit 时使用 veth，并在两端挂载 TCX ingress hook。两条路径都为 dae 网络命名空间内的本地投递准备数据包，再由 BPF SK_LOOKUP 程序从 socket map 中选择 TCP 或 UDP 监听 socket，保留原始目的地址和回包路径。设备类型不改变捕获条件，无关 direct 流量仍在内核直通。

已捕获且最终选择原生 TCP 直连的连接使用两个并行的 Go `io.Copy`，由标准库启用 Linux `splice(2)`。上传方向先写出嗅探缓冲，此时下载方向已在运行。EOF 半关闭目标连接；错误、连接所有者中止或策略变更会关闭两端。MPTCP、协议包装和内核计数不可用的连接使用普通缓冲复制。入口继续通过监听 socket 的 SOCKMAP 和 SK_LOOKUP 投递；已建立的转发连接不加入 SOCKHASH。

Runtime 共用一个监控器，利用 `TCP_INFO.bytes_acked` 和 `SIOCOUTQ` 统计目标 socket 已接纳的有效载荷，排除握手和 FIN。运行中的采样保留单调下界，每个复制方向结束后用实际复制量精确结算，再发送 FIN。全局、设备、status 和 Prometheus 共用这些计数。采样失败时保留已有计数，并暂停该连接的空闲判断；状态查询不会触发采样或关闭连接。

对端不可达由两侧 socket 的 TCP keepalive 和重传超时发现。对端仍可达但连接不再结束时（例如远端静默的代理流，或半关闭后对端不再关闭），普通与原生 TCP 转发共用双向有效载荷空闲回收，超时沿用启动网络命名空间的 conntrack 策略：双向打开时使用 `net.netfilter.nf_conntrack_tcp_timeout_established`，任一方向半关闭后使用 `net.netfilter.nf_conntrack_tcp_timeout_close_wait`；缺失、非法或溢出时分别使用 7440 秒和 60 秒。启动和成功 reload 时重新读取，并同时作用于存量连接。监控器每五秒检查一次，关闭前再次确认。有效载荷和半关闭续期，纯 ACK、keepalive 和重传不续期。DNS、MITM 保留各自的协议生命周期。

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
