# 客户端协议

outbound 仅提供客户端，使用 `net.Conn`、`net.PacketConn`、`DialContext` 和 `ListenPacket`。测试中的本地对端只验证协议线格式。

## 生命周期

- `protocol.Handshake` 管理初始交换、取消、deadline 清除及连接交接。SS、SS2022、SSR、VMess、VLESS、Trojan 返回前发送目标请求；发送完成不代表目标已确认连接成功。
- 共享会话 owner 管理分配、实际依赖 lease 和关闭回收。Hysteria2 跳端口保持稳定 lease，正常轮换不使整个会话失效。状态传播见 [错误与恢复](relay-error-recovery.md)。
- 支持写半关时发送 FIN、保留反向读取；无半关能力时使用 relay 排空宽限。失败请求不等待重连、不重放数据。
- 同步编码可用 `BytesBuffer`；异步 HTTP 请求和 gRPC Send 必须持有独立数据，库仍可能读取的内存不能提前归还池。

## 配置与边界

| 协议 | 当前约束 |
|---|---|
| HTTP / WS | HTTP 代理使用 CONNECT，传输模式使用 PUT；WS 使用 HTTP/1.1 Upgrade |
| VMess | 请求头仅 AEAD（`alterId=0`）；正文支持 `aes-128-gcm`、`chacha20-poly1305`，空值或 `auto` 按硬件选择；nonce 用尽终止流 |
| VMess UDP | 每包地址只接受 IP；固定域名目标在 DialContext 内按调用者 context 解析 |
| VLESS / REALITY | VLESS encryption 仅空值或 `none`；REALITY 仅 VLESS+TCP |
| SSR | 标准 `ssr://` Base64 URL 链接，协议与混淆名称使用小写 |
| Trojan | 额外 SS 层仅加密，不插入 SOCKS 目标头；查询键使用 `allowInsecure`、`sni`、`serviceName` |
| gRPC / Meek | gRPC 显式配置 TLS，未配置则为明文 H2；物理连接恢复由库管理；Meek 每次响应上限 1 MiB，POST 失败不重发 |

未实现的加密、传输组合及 Hysteria2 obfs 参数明确报错。`seed-cfb` 已移除。

回归使用本地加密对端及真实 TLS、HTTP/2、gRPC、QUIC 连接；Vision 的 REALITY 包装测试不代表 REALITY 服务端鉴权互通。验证命令见 [错误与恢复](relay-error-recovery.md#验证)。
