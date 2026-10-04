# Relay 生命周期与恢复

## 所有权与错误

- outbound 的 Session 管理共享连接；owner 通过 `Lease.Abort(cause)` 禁止新分配并终止依赖它的 relay，通过 `StateEvent` 通知 DAE 更新状态和安排恢复。
- `Runtime` 拥有整条协议链。`Dialer()` 提供数据操作，`Session()` 返回可选控制器；`Retire()` 停止新操作，等待已保留的连接释放资源。
- 一个控制平面内，`DialerSet` 按完整路径的传输、入口和探测配置复用 `pathRuntime`。后者拥有唯一的连通性 worker、Session 状态和恢复调度；`Dialer` 是组内成员，持有独立的统计身份、延迟计算及组回调。
- 成员的监测需求取并集，手动探测按运行时合并。通知在运行时锁外发送，组关闭只释放自己的成员；最后一个成员才停止 worker，保留调用者与已有连接继续按租约排空。新增组激活前不接收共享回调或发布统计，激活时继承已观测状态。
- `Failure` 描述协议、范围、来源和操作，用于日志、统计与确认探测。错误标签本身不授权关闭整个节点；只有 owner 的 Abort 才执行关联连接终止。

正常 EOF 优先 `CloseWrite`，保留反向传输；不支持半关时最多排空 10 秒。Abort 立即使用户态 TCP 对客户端 RST，UDP 释放 endpoint。`Invalidate` 仅停止新分配，不能掩盖后来收到的设备或组策略 Abort。

仅过滤有来源证据的本地主动清理错误。目标失败、单流 reset 和操作超时不自动判定共享连接死亡；QUIC 连接终止等事实由协议 owner 处理。

健康节点的异常上游错误（包括超时、单流错误）可请求确认探测，已有 `confirming` 状态合并并发报告；明确的调用方取消、目标拒绝和容量限制不请求确认。HY2 FastOpen 在首次 `Read` 中限制应答等待，默认最多 8 秒；应答终结失败 Abort 当前 stream，使 relay 对客户端发送 RST。共享 QUIC 会话仍由资源 owner 回收和恢复。具体规则见 [HY2 recheck 与 FastOpen 失败处理](../design/hy2-recheck-fast-open.md)。

## UDP 与连接策略

UDP 以 `sip/sport` 固定首包路由和节点。改变目的地址或节点可用性不会重选已有 endpoint。双向空闲 60 秒、不可恢复错误或主动关闭结束生命周期；后续报文可以用同一源端口重新开始，不重放失败数据。DNS 劫持独立按请求处理，已有普通 UDP 会话发往 53 端口仍沿用原决策。

内核保存直连及初始化决策，用户态 endpoint 单独持有源端口绑定。不同原始目的地址的 IP 重写使用独立套接字，共用节点、空闲计时和终止信号。MITM 和重写会话通过 Retain 保留所选 dialer，允许 reload 后继续使用它。

HTTP/3 仅接管首目标经完整 ClientHello 确认的 `h3`。纯检查保留原路由；请求改写按最终 HTTP 目标选择上游，连接池按节点、mark、目标和策略代次隔离。请求路由模式不接受同源 UDP 向其他目的地址迁移。实际上游的资源、组策略或设备路由 Abort 会关闭客户端；单次 HTTP 请求错误不扩大为节点故障。重载排空期间只向已有 HTTP/3 目标交付报文，不创建新会话。

`no_connectivity_behavior: direct` 建立并固定 direct fallback，保留原组归属；`block` 丢弃且不建立转发会话。以下策略均默认 `keep`，可配置为 `close`：

| 配置 | 关闭范围 |
|---|---|
| group `reselect_behavior` | 选择从 A 变为 B 时，该组对应网络类型的旧连接，包括 fallback；手动 selector 同样生效，`random` 不支持 close |
| global `route_change_behavior` | 设备加入/退出被路由引用的 client set 时，该 MAC 的全部旧转发连接；fallback 恢复时，仅原组对应网络类型的 fallback 连接 |

设备策略覆盖 TCP/UDP、IPv4/IPv6、直连、代理及 MITM，API 自身除外。通过 MAC 代次识别旧连接，无需逐条重算路由。API 与运行时设置文件均在提交成功后推进代次；重复操作、未引用的集合和失败回滚不触发关闭。

用户态 TCP 立即 RST；内核直连 TCP 下次发送时交给透明监听入口拒绝旧流，失效首片丢弃。UDP 等旧 endpoint 释放绑定后建立新生命周期，过期代次的初始化报文丢弃。正常 reload 交接设备和同名组的连接归属；未完成初始化的 UDP 会话结束。

## 恢复调度

路由只选择就绪节点。失败 relay 结束，后台恢复只供后续请求使用。`connectivity_check.go` 的单个调度循环串行执行健康检查、容量补充和能力探测，发布执行状态和 `retry_at`；探测与状态处理分别位于 `connectivity_probe.go`、`connectivity_state.go`。

共享资源故障按实际依赖子树终止，容量补充保留健康兄弟连接。混合链由第一个未就绪依赖决定恢复执行者；库自行恢复时 DAE 不重复重连。认证/证书错误阻断快速重试，等待环境变化或显式重查。

日志由 DAE 的状态处理层记录：`info` 展示选中节点和恢复结果，`warn` 展示从可用转为不可用或重试被配置问题阻断，`error` 表示路由状态发布失败。单次探测失败、重试和容量补充属于 `debug`，成功的周期探测与拥塞采样属于 `trace`。正常关闭不告警，不输出节点分享链接或认证数据。

## 验证

```sh
nix-shell --run 'make && go test ./...'
nix-shell --run 'go test -race -tags dae_splice ./component/outbound/... ./control ./cmd'
nix-shell --run 'go test -race github.com/daeuniverse/outbound/...'
```

用户态测试不能替代特权 eBPF 测试。协议约束见 [客户端协议](client-protocols.md)。
