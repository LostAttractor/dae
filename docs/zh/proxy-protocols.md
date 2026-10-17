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

  `multiplex: smux` 为 TCP 和 UDP 启用兼容 sing-box 的 smux；`multiplex: smux-udp-passthrough` 仅复用 TCP，UDP 继续使用底层代理协议；`multiplex: off` 显式禁用复用。启用 smux 后，每个节点默认按需建立最多 4 个 session（即 4 条独立的外层 TCP）；可通过 `multiplex_max_connections` 设置为 1 到 16。多 session 可以让多个并发连接分散到不同的 TCP 拥塞窗口，但不会提高单个内层 TCP 连接的吞吐量。

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
