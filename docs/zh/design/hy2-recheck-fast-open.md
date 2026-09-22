# HY2 recheck 与 FastOpen 失败处理：简化设计

本文描述已实现的简化方案：围绕现有检查循环和 Lease 生命周期，及时请求检查、限制 FastOpen 应答等待，并对失败的当前连接发送 RST。

只维护节点级健康状态，使用已有的单一 canonical 模式 probe。

## 1. recheck：用现有 confirming 状态作为合并窗口

规则只有三条：

1. 节点 healthy 时，首个合格的上游错误立即请求检查，并进入 confirming。
2. confirming 期间的错误合并进当前检查，不重启检查、不重复增加失败代次。
3. 节点 unhealthy 或正在恢复时，业务错误不重置已有重试退避。

检查成功回到 healthy，失败转为 unhealthy。继续使用现有 pending 标志、`failureGeneration`、`ReadinessVersion` 和单个检查循环。

这个状态窗口本身承担并发合并；取消上一版的额外 5 秒冷却、冷却尾沿和错误时间线。若错误持续发生但每次检查都快速成功，仍可能反复请求检查；本版只保证单节点不并行执行检查，不声称提供额外的每秒次数限制。

### 哪些错误触发

| 错误 | 行为 |
|---|---|
| 异常上游读写错误、上游操作超时、FastOpen 应答超时或协议错误 | 请求确认检查 |
| 明确的调用方取消/调用方 deadline、本地清理、目标拒绝、已知容量限制 | 处理当前操作，不请求节点确认 |
| 正常 EOF | 正常半关闭 |
| owner 已确认 QUIC 连接失效 | 直接进入已有 Session 故障与恢复流程 |

实现重点是去掉 `ScopeUnknown` 与 `!timeout` 的一刀切限制，而不是让每个错误直接把节点判死。继续使用现有 Failure 的来源、范围和原因；FastOpen 自身设置的应答超时归为协议侧错误，不能标成调用方取消。

来源不明确的上游超时可以多做一次确认检查，其本身没有关闭共享会话的权限。已经证明来自调用方或本地清理的错误仍被过滤。认证/证书错误沿用现有确认与配置阻断逻辑。

所有健康检查统一走现有流程：同一种模式，失败时最多重试一次，每次使用现有 8 秒预算。保留已有的旧结果校验，检查自身的错误不递归请求检查。

## 2. FastOpen：首次 Read 中完成有界的应答读取

保留目前在首次 `Read` 中解析代理应答的结构。给这次解析增加最多 8 秒的内部 read deadline：

```text
首次 Read
  → 保存应答截止时间 now + 8s
  → 有效 read deadline = 内部截止时间与调用方 deadline 中较早者
  → 读取代理应答
      ├─ 成功：Established，恢复最新的调用方 read deadline
      └─ 失败：保存错误，Abort 当前 stream，取消该 stream 的 I/O
```

`SetReadDeadline` 保存调用方的最新值。应答读取期间，有效值始终取它与固定内部截止时间中较早者；调用方修改或清除自己的 deadline，都不能延长内部 8 秒预算。应答成功后恢复最新调用方 deadline。状态与 deadline 更新使用小范围锁，锁不能跨越阻塞的网络读取。

更短的调用方 deadline 若中断应答解析，沿用当前实现的终结错误语义：关闭本条连接，不尝试恢复读到一半的协议头；该错误标记为调用方来源，不触发节点确认。内部预算耗尽则请求确认。

### 明确的简化边界

8 秒从实际开始读取应答算起，不再要求“发送请求后，即使从不调用 Read 也必须在 8 秒终止”。正常 DAE TCP relay 在连接返回后立即启动上游读取，因此真实转发路径仍能及时发现 FastOpen 黑洞。

完全不调用 Read 的独立消费者依赖 Close 或已有 QUIC 存活机制结束连接。这样无需后台应答 reader、额外 watchdog，也不会因为应答已经到达但尚未被应用读取而误报超时。

请求头发送仍受现有 DialContext/Handshake 预算限制。应答 deadline 在实际 Read 时安装，不与 Handshake 返回前清除 deadline 的动作竞争。

## 3. reset/close：只终结已经失败的逻辑连接

FastOpen 失败统一经过一个小的失败收尾函数：

```text
保存终结错误
  → 当前 stream 的 Lease.Abort(cause)
  → CancelRead / CancelWrite
  → relay 收到 Abort，对客户端 TCP 设置 RST 并关闭
  → 后续 Close 幂等释放资源
```

- 后续 Read/Write 返回已保存的终结错误，不再接受新数据。
- 目标拒绝同样终止当前连接并发送 RST，但不请求节点确认。
- 应答成功后的正常 EOF 继续半关闭，允许反向排空。
- 普通调用方 Close 走本地清理；清理不能覆盖已经保存的失败原因。
- 不重放失败连接的数据，不在同一个客户端连接上重新拨号。

### 必须保留的一处顺序修正

当前 QUIC 包装器可能先对 stream 执行 `Invalidate`，而 Lease 的首次失效会固定关闭方式，后续 Abort 无法升级它。

在 HY2 自己的 QStream 错误入口，对真正不可恢复的单流错误先执行带正确来源和资源信息的 stream Abort，再交给现有通用错误包装逻辑；目标拒绝和应答解析失败也直接走上述失败收尾函数。已有本地关闭来源必须保留。

这个修正局限于 HY2，不需要增加通用 owner 回调接口，也不改变整个 Lease 系统的首次失效规则。共享 QUIC 错误仍由已有资源 owner 的 `handle.Abort` 处理。

## 4. 节点故障与共享 QUIC 重建分开

```text
业务错误 → recheck 失败 → unhealthy，选择器可以切出节点

QUIC owner 检测到连接终止 → 现有 Abort/cleanup/Connect 流程
```

本版不让健康检查器主动销毁仍显示 connected 的共享 QUIC 会话，也不新增跨 Session/Runtime 的 reset 接口。失效会话由现有 QUIC 存活检测和资源 owner 回收。

取舍是：节点可以先变为不可用，但共享会话重建可能仍需等待 QUIC 自身超时。前面的全黑洞实验中，该通知约在 30 秒出现；这不是所有网络条件下的硬性上限。

在正常 relay 及时开始读取、且检查没有排队的情况下，预算时序为：

```text
约 8 秒内：FastOpen 应答超时，当前 TCP RST，请求确认
随后最多约 16 秒：沿用现有两次 probe 确认节点故障
QUIC owner 若更早确认连接死亡：立即走已有故障与恢复路径
```

与上一版相比，不再承诺 16 秒内完成节点确认并主动重建共享会话；保留简单的所有权边界。

## 5. 修改范围与验收

主要修改集中于：

- `component/outbound/dialer/recovery.go`：调整错误是否值得请求确认的条件。
- `third_party/outbound/protocol/hysteria2/client/tcp.go`：应答 read deadline、错误保存、单流 Abort 与后续 I/O 拒绝。
- `third_party/outbound/protocol/hysteria2/internal/utils/qstream.go`：在默认 Invalidate 之前处理不可恢复的 HY2 单流错误。

复用现有调度器、健康检查次数、Session 恢复和 relay RST 路径。需要验证的关键场景：

1. 多个业务错误只触发一个在途确认；旧检查成功不能清除后来的确认请求。
2. 上游超时能请求确认；明确目标拒绝、调用方取消和本地清理不触发。
3. relay 的长 read deadline 不能覆盖 FastOpen 的 8 秒应答预算；成功后恢复最新应用 deadline。
4. 真实 TCP 客户端在 FastOpen 终结失败时收到 ECONNRESET，成功后的正常 EOF 为 FIN。
5. 底层先遇到 stream reset 时仍可正确 Abort；单流失败不关闭共享 QUIC 或兄弟 stream。
6. UDP 黑洞下，当前连接失败能请求检查，probe 失败能转为 unhealthy，QUIC owner 后续仍正常恢复。
7. 并发 Read/Write、deadline 更新、Close 和资源故障没有数据竞争，原始错误不被清理覆盖。
