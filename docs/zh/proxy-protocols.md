# 其他代理协议

> **Note**: dae 目前支持以下代理协议

每个 `node` 条目只能包含一个分享链接。代理路径请使用[路由配置](configuration/routing.md)中的 group path expression 组合。

- [x] HTTP(S), naiveproxy

  ```
  https://[[user:]pass@]hostname:port/
  ```

- [x] Socks
  - [x] Socks4
  - [x] Socks4a
  - [x] Socks5

  ```
  socks4://[[user:]pass@]hostname:port/
  socks5://[[user:]pass@]hostname:port/
  ```

- [x] VMess(AEAD, alterID=0) / VLESS
  - [x] TCP
  - [x] WS
  - [x] TLS
    - [x] Reality
  - [x] gRPC
  - [x] Meek
  - [x] HTTPUpgrade

  [v2rayN URI Schema](https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2))

  [DuckSoft URI Schema](https://github.com/XTLS/Xray-core/discussions/716)

  REALITY `spx` 的爬取参数接受单个非负整数或升序范围；`p`（填充字节）上限 4096，`c`（并发）和 `t`（每个 worker 的请求数）上限 8，`i`（间隔毫秒）上限 60000，`r`（返回延迟毫秒）上限 5000。省略时为 0，格式错误、重复或越界参数会拒绝节点构建。

  回退爬取每个节点至多运行一个任务，全进程至多 8 个；每个任务最多运行 10 秒，响应体上限 1 MiB。发现的路径仅保留到本次任务结束，最多 256 条、合计 256 KiB，单条及初始 `spx` 上限 4096 字节。任务完成、超时或节点释放时关闭连接。

- [x] Shadowsocks
  - [x] AEAD Ciphers
  - [x] Stream Ciphers
  - [x] simple-obfs
  - [ ] v2ray-plugin
    - [x] Websocket (+TLS)

  [SIP002](https://shadowsocks.org/doc/sip002.html)

  [SIP008](https://shadowsocks.org/doc/sip008.html)

  链接声明不支持的 SIP003 插件时，节点构建返回错误；只有省略插件才使用基础 Shadowsocks 传输。

  SIP002 链接只描述标准 Shadowsocks 连接信息。需要启用 dae 专属功能时，应保持链接不变并使用节点选项：

  ```shell
  node {
    hk: 'ss://LINK' [multiplex: smux, multiplex_max_connections: 10]
  }
  ```

  对订阅中的节点，可以使用展开的订阅描述，并按解析后的节点名称、协议或原始链接进行匹配：

  ```shell
  subscription {
    my_sub {
      link: 'https://example.com/subscription'
      option {
        filter: protocol(shadowsocks) && name(regex: '^HK') [multiplex: smux]
        filter: name(HK-legacy) [multiplex: off]
      }
    }
  }
  ```

  `multiplex` 启用兼容 sing-box 的多路复用（sing-mux）：`smux` 和 `yamux` 同时复用 TCP 和 UDP；`smux-udp-passthrough` 和 `yamux-udp-passthrough` 仅复用 TCP，UDP 继续使用底层代理协议；`off` 显式禁用复用。sing-box 服务端只需设置 `multiplex.enabled` 即可接受这两种协议，无需其他服务端配置。

  smux 的每个 session 共用一个 4 MiB 接收缓冲区，一个读取停滞的流（例如暂停的视频）会让同一 session 上的所有其他流停顿。发送像 fq_codel 分配链路那样在流之间按字节分配：刚有数据要发的流优先，游戏或 DNS 的数据报在下一个可调度的帧边界优先发送，而不排在大流量上传的队列之后。每个流最多排队 64 KiB 的实际缓冲区容量，后续写入先填满已有帧，只有该流自己的写者等待空间。在途批次继续持有并计账其缓冲区；批次可以跨帧边界填满，但未写完的帧必须先续写，不能插入其他帧。关闭流在 FIN 实际写完前仍持有发送状态；已有 64 个关闭流等待排空时，session 暂停接受新流，不丢弃已接受的尾部。每次承载写入最多发送 64 KiB，由正常写入提供反压，并设置 `netproxy.DialTimeout` 截止，超时终止 session。空闲发送器不写入，也不更新截止时间。smux 不调整承载的 TCP 发送队列；公平调度只作用于仍在用户态队列中的数据，不能重排在途批次或承载已接纳的字节。UDP 数据报从不等待连接：每个 UDP socket（smux 流）最多排队 64 KiB、每个 session 最多 256 KiB；超出时丢弃该流或 session 中积压最多的流最早的数据报，因此未排队的流总能放入自己的数据报。数据报持续排队超过 5 ms、且超出基于速率估计的公平份额等待时，CoDel 会丢弃其中一部分。这个估计不保证按平均公平份额发送就不会丢包，尤其是在批次或可靠流帧较大时。所有丢弃都与其他 UDP 丢包一起计数，每个发出的数据报的等待时长也会记录（见[指标](configuration/metrics.md)）。回包由 session 的接收循环直接发给客户端；不能立即发送的回包（例如来自新地址的第一个）与同一 UDP socket 之后的回包一起进入最多 128 个的队列，超出的回包被丢弃并同样计数。yamux 按流做流量控制，流之间互不阻塞。yamux 流在被快速读取时下载窗口最多增长到 8 MiB，RTT 100 ms 时约 330 Mbit/s，200 ms 时约 170 Mbit/s；同一 session 的所有流共享 32 MiB 的窗口增长额度，足够 4 个流达到最大窗口，流在关闭前一直占用已增长的额度；关闭的流若 5 秒内未被服务端关闭则被重置。剩余额度不足一个最大窗口的 session 视为已满载，新流优先使用其他 session。所有 session 都到达这一状态且 session 数已达 `multiplex_max_connections` 时，新流停留在初始的 256 KiB 窗口，RTT 100 ms 时约 20 Mbit/s，200 ms 时约 10 Mbit/s，直到已增长的流关闭。上传受服务端固定的 256 KiB 窗口限制，RTT 100 ms 时单流约 20 Mbit/s。yamux session 还会每 30 秒互发一次保活 ping。

  启用复用的节点保持一个 session（即一条独立的外层 TCP），并按需增加，默认最多 4 个；可通过 `multiplex_max_connections` 设置为 1 到 16。session 按 lane 分开，使每类流量只与同类共用外层连接：交互 UDP（游戏、DNS、通话）、QUIC（嗅探为 QUIC 的 UDP）和 TCP。外层连接上丢一个包会让其上所有流停顿一个往返，TCP 读者停读会让整个 smux session 停顿；不与它们共用的游戏两者都不受影响。session 取其第一个用户流的 lane；smux 在最后一个流结束且发送队列和在途数据、FIN 全部排空后重新成为热备。已预留但尚未入队的连通性检查也不算干净热备；忙碌的无标签 session 仅在没有其他选择时回落使用。排空事件通知既有恢复协调器收敛，不单独建立恢复循环。没有 session 的 lane 取用热备，同时立即请求新的热备，因此晚开始的 lane 也能落在干净的 session 上；默认的 4 个正好是每个 lane 一个加一个热备。session 更少或热备尚未补上时，流使用其他 lane 的 session：交互 UDP 优先 QUIC 的，其次 TCP 的；其余 lane 只在别无选择时才用交互 session；这样放置的流一直留在原处。可用接收容量优先于 lane 归属：本 lane 饱和时，优先使用健康热备或其他 lane 的可用 session。所有可用 session 都饱和时，仍可共用其中一个，同时在连接数上限内请求新 session；这类饱和触发的请求可以使用任意空位。普通负载下，某个 lane 的 session 都已承载至少 4 个用户流时，只能在为每个没有 session 的 lane 和缺失的热备各留一个位置之后的空位里请求新 session，同一时间只请求一个；因此只有 TCP 的节点在默认的 4 个时只用一个 TCP session，5 个时用两个，6 个时用三个。连通性检查优先使用交互 session，其次热备，从不改变 lane，既不会增加 session，也不计入这 4 个流。额外的 session 连续 60 秒没有用户流且另有可用 session 时关闭，但只要还有带 lane 的 session，最后一个热备就保留；空闲时断开的额外 session 不再重建，但还有活跃 lane 时，最后一个热备会请求恢复。多 session 可以让多个并发连接分散到不同的 TCP 拥塞窗口，但不会提高单个内层 TCP 连接的吞吐量。

- [x] ShadowsocksR

- [x] Trojan
  - [x] Trojan-gfw
  - [x] Trojan-go

  [trojan/trojan-go URI Schema](https://p4gefau1t.github.io/trojan-go/developer/url)

- [x] Tuic (v5)

  [Tuic URI Schema](https://github.com/daeuniverse/dae/discussions/182)

- [x] Juicity

  [Juicity URI Schema](https://github.com/juicity/juicity?tab=readme-ov-file#link-format)

- [x] Hysteria2

  [Hysteria2 URI Schema](https://v2.hysteria.network/zh/docs/developers/URI-Scheme)

- [x] AnyTLS

  [AnyTLS URI Schema](https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md)

- [x] Group 级代理路径

  使用 group path expression 组合不同协议。

有其他需求的，一种方式是通过外接其他代理程序来扩展协议支持。下面给出外接 naiveproxy 的例子。

尽管 dae 等代理程序支持 HTTPS 协议，但由于并不使用 chromium 网络栈，削弱了 naiveproxy 的伪装效果，因此可以选择外接 naiveproxy 程序来实现。

1. 启动 naiveproxy：

   样例使用 naiveproxy 开启一个 HTTP 监听端口。注意，HTTP 代理不支持代理 udp 流量，所以如果你外接其他代理程序，建议优先考虑使用 socks5 端口。

   ```bash
   naiveproxy --listen=http://127.0.0.1:1090 --proxy=https://yourlink
   ```

2. 在 dae 配置的 node 一节中，新增一行：`http://127.0.0.1:1090`，并记得在所使用的组中使用该节点。

3. 如果你绑定了 WAN 接口，即在 `global.wan_interface` 填写了内容，增加以下 rules 控制项，并将 direct 规则放在 routing 一节的靠上位置，以避免流量从 dae 流向 naiveproxy 之后再次流向 dae，造成回环：

   ```shell
   routing {
       rules {
           pname(naiveproxy) -> must
       }
       pname(naiveproxy) -> direct
       # 其余路由和 fallback ...
   }
   ```

   这里的 pname 的含义是进程名。你可通过启动时的命令，或运行时通过 `ps -ef` 命令或者观察 dae 的日志来确定 naiveproxy 的进程名。`must` 跳过自动 DNS 接管，靠前的 `direct` 规则选择直连。应避免让该进程命中显式 bump、MITM 或 DNAT 捕获，以保留内核直通。

   只绑定 LAN 接口的用户不需要做这一步。
