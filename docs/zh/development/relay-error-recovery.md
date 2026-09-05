# Relay 错误与恢复

路由只选择就绪节点。失败 relay 结束，后台恢复供后续请求使用，不等待或重放业务数据。

## 职责与传播

- **协议 owner / Session** 管理实际共享资源、分配能力及连接恢复。资源故障时先关闭分配入口，再通知依赖者并清理资源。
- **Lease** 记录建立连接时的实际依赖。`Abort(cause)` 发出强制终止指令，`Invalidate(cause)` 仅使依赖失效。两者通过 `Done` 通知；终止原因与动作只确定一次。
- **Runtime** 拥有整条协议链，透传连接的 lease。`Retire` 停止新操作，已有连接结束后再释放链。
- **DAE** 根据 Session 状态选择节点，调度 `Session.Connect` 和健康检查；relay 负责传输、半关及执行中止指令。

```text
outbound 协议 Read/Write/observer
  ├─ 确认共享资源失效 → owner 禁止新流、Lease.Abort(cause)
  │                     ├─ 实际依赖子树 → Runtime 返回连接的 DependencyLease
  │                     │                → relay 收到信号 → RST 客户端 lConn
  │                     └─ 发布 StateEvent → DAE WatchState → 恢复调度与节点状态
  └─ 返回 Failure → DAE relay 收集双向错误及方向/操作
                    → recordDataPlaneError → Dialer.ReportDataPlaneError
                    → 记录失败；未知上游错误触发确认探测
```

`Failure` 保存协议层、影响范围、来源、操作及原始错误；`Failures` 遍历全部并列原因，避免 timeout 掩盖其他错误。错误用于诊断，强制终止由 owner 的 `Abort` 信号授权。

## 行为边界

| 观察 | 处理 |
|---|---|
| 正常读 EOF | 优先 CloseWrite，继续反向传输；不支持则使用排空宽限 |
| Write EOF、其他读写错误、半关错误 | 结束当前 relay，保留错误；CloseWrite 返回 ErrUnsupported 时按不支持半关处理 |
| 客户端 reset、目标失败、QUIC/H2 流 reset | 影响当前连接或流，不据此宣告代理共享连接死亡 |
| owner 发出 Abort | 只终止实际依赖子树；relay 在关闭客户端 lConn 前设置 SetLinger(0)，无需等上游读写返回 |
| H2 GOAWAY | 停止新分配，保留允许继续的旧流，补充连接 |
| 操作 timeout、容量不足 | 不直接判定共享连接死亡；QUIC connection timeout 已是连接终止事实 |
| 有证据的认证/证书错误 | 阻断常规快速重试并显示配置原因 |

不支持半关时，反向传输有固定 10 秒排空宽限。正常 EOF 与普通依赖失效不授权主动 RST。gRPC 的逻辑就绪状态也不能证明某条物理连接已失效；Meek 尚无固定依赖 lease。

仅过滤有来源证据的本地主动清理错误。QUIC 致命错误也可能匹配 `net.ErrClosed`，不能因此将其忽略。

## 恢复与状态

- `ResourceRef` 区分资源代次，旧 handle 不能修改替代资源。`ReadinessVersion` 区分分配能力，旧探测不能更新新版本；`Seq` 只是通知序号。
- DAE 按发布者和 episode 记录事故。重复错误不重计数、不刷新退避；容量补充失败不撤销仍可用连接的健康证明。
- status 的恢复动作是 connect、verify 或 replenish，阶段来自实际调度，`retry_at` 与含 jitter 的真实定时器一致。gRPC 的物理连接恢复由库管理，不再添加外部重连循环。

## 验证

在 dae 模块中执行，复用实际 submodule 依赖：

```sh
nix-shell --run 'make'
nix-shell --run 'go test ./... -count=1'
nix-shell --run 'go test -race github.com/daeuniverse/outbound/... -count=1'
nix-shell --run 'go test -race -tags dae_splice ./component/outbound/... ./common/stats ./control ./control/internal/splice ./cmd -count=1'
```

测试覆盖真实 TCP 的半关/RST、QUIC 双流隔离、依赖失效、旧代次、恢复时序和容量补充。`make` 编译 eBPF；用户态测试不替代特权 eBPF 集成测试。客户端约束见 [客户端协议](client-protocols.md)。
