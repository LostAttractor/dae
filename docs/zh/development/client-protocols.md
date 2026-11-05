# 客户端协议

outbound 仅提供客户端，使用 `net.Conn`、`net.PacketConn`、`DialContext` 和 `ListenPacket`。测试中的本地对端只验证协议线格式。

## 生命周期

- 无需等待应答的协议（SS、SS2022、流加密 SS、VMess、VLESS/Vision、Trojan、Juicity、TUIC、Hysteria2）在 `DialContext` 中不发送目标请求，请求头与首次 `Write` 的数据在同一次底层写入中发出。TCP 流在首次写入前 `Read` 时先发送请求头，服务端先说话的协议因此可用，Vision 随请求头发送一个空的长填充记录；首次写入前 `CloseWrite` 时，请求头与协议的结束记录（VMess 结束块、Vision PaddingEnd 记录）一同发送。UDP 流的请求等待首个数据报。sing-mux 流的请求同样随首次写入发送，TCP 流首次读取前先发送。代理出站的 TCP relay 在 setup 中把嗅探到的数据作为首次写入，受拨号预算约束。
- SSR、SOCKS5、HTTP 等需要应答的交换由 `protocol.Handshake` 在返回前完成，它管理初始交换、取消、deadline 清除及连接交接。请求发送完成不代表目标已确认连接成功。
- TUIC、Hysteria2、Juicity 按节点缓存 TLS 会话，重连时恢复会话；请求均在握手完成后发送，不使用 0-RTT。
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
| gRPC / Meek | gRPC 显式配置 TLS，未配置则为明文 H2；物理连接恢复由库管理；Meek 每次响应上限 1 MiB，POST 失败不重发 |

未实现的加密、传输组合及 Hysteria2 obfs 参数明确报错。

回归使用本地加密对端及真实 TLS、HTTP/2、gRPC、QUIC 连接；Vision 的 REALITY 包装测试不代表 REALITY 服务端鉴权互通。验证命令见 [错误与恢复](relay-error-recovery.md#验证)。
