# 客户端协议

outbound 仅提供客户端，使用 `net.Conn`、`net.PacketConn`、`DialContext` 和 `ListenPacket`。测试中的本地对端只验证协议线格式。

## 生命周期

- 无需等待应答的协议（SS、SS2022、流加密 SS、VMess、VLESS/Vision、Trojan、Juicity、TUIC、Hysteria2）在 `DialContext` 中不发送目标请求，请求头与首次 `Write` 的数据在同一次底层写入中发出。TCP 流在首次写入前 `Read` 时先发送请求头，服务端先说话的协议因此可用，Vision 随请求头发送一个空的长填充记录；首次写入前 `CloseWrite` 时，请求头与协议的结束记录（VMess 结束块、Vision PaddingEnd 记录）一同发送。UDP 流的请求等待首个数据报。sing-mux 流的请求同样随首次写入发送，TCP 流首次读取前先发送。代理出站的 TCP relay 在 setup 中把嗅探到的数据作为首次写入，受拨号预算约束。
- SSR、SOCKS5、HTTP 等需要应答的交换由 `protocol.Handshake` 在返回前完成，它管理初始交换、取消、deadline 清除及连接交接。请求发送完成不代表目标已确认连接成功。
- TUIC、Hysteria2、Juicity 按节点缓存 TLS 会话，重连时恢复会话。Hysteria2 与 Juicity 不使用 0-RTT：Hysteria2 的认证是 HTTP/3 POST，http3 不在 0-RTT 中发送它，其他请求都等待认证；Juicity 参考服务端不接受 0-RTT。
- TUIC 节点可选启用 0-RTT（见下表），默认关闭。持有允许早期数据的会话票据时，重连不等握手完成即可分配，CONNECT 与首个载荷、UDP 数据报在 0-RTT 中发出；没有票据时与普通握手相同。认证 uni 流在成员就绪前预留，避免 QUIC 模式 UDP 包占满额度后无法认证；令牌来自完整握手的 TLS exporter，握手完成后才发送；TUIC v5 规范要求服务端在认证前只接收命令头并暂停，认证后继续。
- TUIC 流的首次底层写入在服务端接受或拒绝早期数据后才返回。服务端拒绝时丢弃整个早期流且不作处理，握手前也无数据可读，因此该写入在 1-RTT 连接上的新流中重发，读取和 deadline 随之转移；拒绝与握手完成之间，TCP 拨号等待连接恢复，不因重置流表的临时零额度请求补容；恢复后的 uni 流先为认证重新预留。会话继续认证，拒绝不计为节点故障。被拒绝的 0-RTT UDP 数据报按 UDP 语义丢失；QUIC 模式 UDP 包耗尽 uni 流额度时按承载容量丢包，不关闭成员。
- 0-RTT 数据可被链路上的攻击者重放。重放的连接无法完成握手，也就无法认证：按规范在认证前暂停命令的服务端不会执行重放的命令；认证前就执行命令的服务端会再次连接目标并重发首个载荷。
- 共享会话 owner 管理分配、实际依赖 lease 和关闭回收。Hysteria2 跳端口保持稳定 lease，正常轮换不使整个会话失效。状态传播见 [错误与恢复](relay-error-recovery.md)。
- `ListenPacket` 支持多个目标；VLESS、普通 VMess 和 AnyTLS 按目标复用子流，共用关联的关闭与故障信号。AnyTLS 每流最多缓存 1 MiB 未读数据，超限只关闭该流。
- gRPC 流绑定实际承载连接的 lease；GOAWAY 允许旧流排空，父连接 Abort 只终止依赖它的流，重连仍由 gRPC 执行。
- 支持写半关时发送 FIN、保留反向读取；无半关能力时使用 relay 排空宽限。失败请求不等待重连、不重放数据。
- 同步编码可用 `BytesBuffer`；异步 HTTP 请求和 gRPC Send 必须持有独立数据，库仍可能读取的内存不能提前归还池。

## 配置与边界

| 协议 | 当前约束 |
| --- | --- |
| HTTP / WS | HTTP 代理使用 CONNECT，传输模式使用 PUT；WS 使用 HTTP/1.1 Upgrade |
| VMess | 请求头仅 AEAD（`alterId=0`）；正文支持 `aes-128-gcm`、`chacha20-poly1305`，空值或 `auto` 按硬件选择；nonce 用尽终止流 |
| VMess UDP | 普通模式按目标复用子流；packet-address 模式只接受 IP，固定域名目标在 DialContext 内按调用者 context 解析 |
| VLESS / REALITY | VLESS encryption 仅空值或 `none`；REALITY 仅 VLESS+TCP |
| SSR | 标准 `ssr://` Base64 URL 链接，协议与混淆名称使用小写 |
| Trojan | 额外 SS 层仅加密，不插入 SOCKS 目标头；查询键使用 `allowInsecure`、`sni`、`serviceName` |
| TUIC | 仅 v5；`reduce_rtt=1` 启用 0-RTT，也接受 sing-box 的 `zero_rtt_handshake`，导出为 `reduce_rtt` |
| gRPC / Meek | gRPC 显式配置 TLS，未配置则为明文 H2；物理连接恢复由库管理；Meek 每次响应上限 1 MiB，POST 失败不重发 |

未实现的加密、传输组合及 Hysteria2 obfs 参数明确报错。

回归使用本地加密对端及真实 TLS、HTTP/2、gRPC、QUIC 连接；Vision 的 REALITY 包装测试不代表 REALITY 服务端鉴权互通。验证命令见 [错误与恢复](relay-error-recovery.md#验证)。
