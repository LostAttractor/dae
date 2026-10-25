# Relay 生命周期与恢复

## 所有权与错误

- outbound 的 Session 管理共享连接；owner 通过 `Lease.Abort(cause)` 禁止新分配并终止依赖它的 relay，通过 `StateEvent` 通知 DAE 更新状态和安排恢复。
- `Runtime` 拥有整条协议链。`Dialer()` 提供数据操作，`Session()` 返回可选控制器；`Retire()` 停止新操作，等待已保留的连接释放资源。
- 一个控制平面内，`DialerSet` 按完整路径的传输、入口和探测配置复用 `pathRuntime`。后者拥有唯一的连通性 worker、Session 状态和恢复调度；`Dialer` 是组内成员，持有独立的统计身份、延迟计算及组回调。
- 成员的监测需求取并集，手动探测按运行时合并。通知在运行时锁外发送，组关闭只释放自己的成员；最后一个成员才停止 worker，保留调用者与已有连接继续按租约排空。新增组激活前不接收共享回调或发布统计，激活时继承已观测状态。
- `Failure` 描述协议、范围、来源和操作，用于日志、统计与确认探测。错误标签本身不授权关闭整个节点；只有 owner 的 Abort 才执行关联连接终止。

正常 EOF 优先 `CloseWrite`，保留反向传输；不支持半关时最多排空 10 秒。Abort 立即使用户态 TCP 对客户端 RST，UDP 释放 endpoint。`Invalidate` 仅停止新分配，不能掩盖后来收到的设备或组策略 Abort。

关闭不丢弃已接受的数据：连接的 `Close` 保留 `Write` 已接受的字节和 `CloseWrite` 发出的 FIN，仍在进程内队列中时，由连接自身最多等待 `netproxy.CloseLinger`（5 秒）写出，或交给持有队列的资源。`Runtime` 退役后，最后一个连接关闭即关闭整条链，因此 `Layer.Resources` 只在全部租约释放后关闭；在载体上承载多路流的资源先将排队帧交给载体，同样以 `CloseLinger` 为上限；载体已失败或 owner 已 Abort 时立即关闭。之后立即关闭载体时，若载体在 `Close` 时 reset（如前一跳的流，或仍有未读数据的 TCP 连接），对端尚未读取的帧仍会丢失；sing-mux 会话因此先半关载体并等待对端 EOF，共用同一上限，anytls 会话和 HTTP/2 CONNECT 连接池仍立即关闭载体。上限按层计算：载体自身也需等待时，两层依次等待。HTTP/2 CONNECT 上游仅在已半关且响应已结束时先等待 END_STREAM 写出，最多 `CloseLinger`；交换未完成时（包括 Abort）立即 reset。Abort 只对客户端立即生效：relay 先 RST 客户端，再同步关闭上游，meek 上游仍先 POST 已接受的字节，最多 `CloseLinger`，期间占用该 relay 及上游资源。

仅过滤有来源证据的本地主动清理错误。目标失败、单流 reset 和操作超时不自动判定共享连接死亡；QUIC 连接终止等事实由协议 owner 处理。

健康节点的异常上游错误（包括超时、单流错误）可请求确认探测，已有 `confirming` 状态合并并发报告；明确的调用方取消、目标拒绝和容量限制不请求确认。HY2 FastOpen 在首次 `Read` 中限制应答等待，默认最多 8 秒；应答终结失败 Abort 当前 stream，使 relay 对客户端发送 RST。共享 QUIC 会话仍由资源 owner 回收和恢复。路径健康、能力发现和存活状态的模型见[出站连通性与故障转移](../design/outbound-connectivity.md)。

## HY2 FastOpen

### 应答期限

首次 `Read` 开始解析代理应答时，设置最多 8 秒的内部 read deadline。有效 deadline 始终取内部期限与调用方期限中较早者；调用方延长或清除期限不能延长内部预算。应答成功后恢复最新的调用方 read deadline。

更短的调用方 deadline 中断解析时，关闭当前连接，不恢复读到一半的协议头。该错误保留调用方来源，不触发路径确认。内部预算耗尽属于协议侧错误，会请求确认。

8 秒从实际读取应答开始计算。正常 TCP relay 在连接返回后启动上游读取；从不调用 `Read` 的独立消费者依赖 `Close` 或 QUIC 存活机制结束连接。请求头发送受 DialContext/Handshake 的预算约束。

### 单流终止与共享会话

FastOpen 终结失败保存原始错误，Abort 当前 stream 的 Lease，并取消该 stream 的 I/O。relay 收到 Abort 后关闭连接并向 TCP 客户端发送 RST。后续读写返回保存的错误，`Close` 幂等释放资源。目标拒绝同样终止当前连接，但不触发路径确认；成功后的正常 EOF 继续半关闭。

不可恢复的 HY2 单流错误先执行带来源和资源信息的 stream Abort，再进入通用错误包装。单流失败不关闭共享 QUIC 或兄弟 stream，也不重放业务数据。共享 QUIC 失效由资源 owner 执行 Abort、cleanup 和 Connect。

健康检查不会主动销毁仍显示 connected 的共享 Session。无排队时，FastOpen 内部应答等待最多 8 秒，随后两次确认探测各受现有 8 秒预算约束；排队与共享会话恢复另受各自生命周期控制，不能据此承诺固定的整体恢复时限。

## UDP 与连接策略

UDP 以 `sip/sport` 固定首包路由和节点。改变目的地址或节点可用性不会重选已有 endpoint。双向空闲 60 秒、不可恢复错误或主动关闭结束生命周期；后续报文可以用同一源端口重新开始，不重放失败数据。DNS 劫持独立按请求处理，已有普通 UDP 会话发往 53 端口仍沿用原决策。

内核保存直连及初始化决策，用户态 endpoint 单独持有源端口绑定。不同原始目的地址的 IP 重写使用独立套接字，共用节点、空闲计时和终止信号。MITM 和重写会话通过 Retain 保留所选 dialer，允许 reload 后继续使用它。

HTTP/3 仅接管首目标经完整 ClientHello 确认的 `h3`。纯检查保留原路由；请求改写按最终 HTTP 目标选择上游，连接池按节点、mark、目标和策略代次隔离。请求路由模式不接受同源 UDP 向其他目的地址迁移。实际上游的资源、组策略或设备路由 Abort 会关闭客户端；单次 HTTP 请求错误不扩大为节点故障。重载排空期间只向已有 HTTP/3 目标交付报文，不创建新会话。

组无可用节点时按 `no_connectivity_behavior` 降级，状态模型见[出站连通性](../design/outbound-connectivity.md#无可用节点降级)：`block` 丢弃且不建立转发会话；`direct` 固定为直连，连接属于原组的 fallback 代次。以下策略均默认 `keep`，可配置为 `close`：

| 配置 | 关闭范围 |
| --- | --- |
| group `reselect_behavior` | 选择从 A 变为 B 时，该组对应网络类型的旧连接，包括 fallback；手动 selector 同样生效，`random` 不支持 close |
| global `route_change_behavior` | 设备加入/退出被路由引用的 client set 时，该 MAC 的全部旧转发连接；fallback 恢复时，仅原组对应网络类型的 fallback 连接，包括内核直连转发的 fallback 流 |

任一策略为 `close` 时，删除组也结束它的 fallback 连接。reload 把策略改为 `keep` 后，此前可结束的 fallback 连接不再随恢复或改选关闭，删除组时仍结束。

设备策略覆盖 TCP/UDP、IPv4/IPv6、直连、代理及 MITM，API 自身除外。通过 MAC 代次识别旧连接，无需逐条重算路由。API 与运行时设置文件均在提交成功后推进代次；重复操作、未引用的集合和失败回滚不触发关闭。内核设备代次表整体替换发布；在任何设备拥有代次之前（例如 `route_change_behavior: keep`）不发布该表，报文无需查询。

用户态 TCP 立即 RST；内核直连 TCP 下次发送时交给透明监听入口拒绝旧流，失效首片丢弃。设备代次变化后，UDP 等旧 endpoint 释放绑定后建立新生命周期，过期代次的初始化报文丢弃；fallback 令牌撤销后，内核直连 UDP 的路由缓存失效，下一报文重新路由。正常 reload 交接设备和同名组的连接归属；UDP 初始化可在旧代宽限期内完成，期满仍未完成的会话结束。

## Reload 与停止

`Runtime` 持有监听循环、跨代 TCP socket 集合、UDP endpoint、共享连接 maps 和内核挂载；各平面的 tracker 只管理接入与 setup，`BPFState` 持有该代程序和私有规则 maps。普通 reload 保留已建立的普通 TCP。`reload --abort` 和正常停止覆盖所有存活代际，先对客户端 socket 设置 RST 并关闭，等待 socket 关闭完成后才释放内核回包路径；不等待上游协议对象排空。终止信号的进程级超时限制无法完成的清理。

未改变的接口复用 TCX、内部 Netkit/veth 链路和 SK_LOOKUP 挂载。候选完整准备私有规则环境后，TCX 原位更新程序，逐接口切换期间两代都可接入；不暂停新路由决策。16 字节 TCP 长期状态独立于配置代，未捕获的 direct 仍内核直通。有界交接保存完整结果、30 秒有效期和 SYN 序列号；常驻接入循环将旧代握手交回原配置处理，过期或被 LRU 淘汰的交接才拒绝。旧代 UDP 缓存不能解释为新代出站编号。宽限期后 MITM 请求先排空再关闭连接，DNS TCP 随旧 DNS relay 关闭；后续 reload 等待上一代退役，限制同时保留的配置资源。

MITM 上游清理同步检查资源和组策略的 Abort 原因，再结束客户端依赖 lease；HTTP transport 的快速关闭不能将已经发生的共享会话故障覆盖为普通清理。

## 恢复调度

路由只选择就绪节点。失败 relay 结束，后台恢复只供后续请求使用。`connectivity_check.go` 的单个调度循环依次执行健康检查、容量补充和后台能力探测，路径存活后，选举和升级的单次测试按网络模式并发，发布执行状态和 `retry_at`；探测与状态处理分别位于 `connectivity_probe.go`、`connectivity_state.go`。

共享资源故障按实际依赖子树终止，容量补充保留健康兄弟连接。混合链由第一个未就绪依赖决定恢复执行者；库自行恢复时 DAE 不重复重连。认证/证书错误阻断快速重试，等待环境变化或显式重查。

日志由 DAE 的状态处理层记录：`info` 展示选中节点和恢复结果，`warn` 展示从可用转为不可用或重试被配置问题阻断，`error` 表示路由状态发布失败。单次探测失败、重试和容量补充属于 `debug`，成功的周期探测与拥塞采样属于 `trace`。正常关闭不告警，不输出节点分享链接或认证数据。

## 验证

```sh
make
go test ./...
go test -race ./component/outbound/... ./control ./cmd
go test -race github.com/daeuniverse/dae/pkg/outbound/...
```

用户态测试不能替代特权 eBPF 测试。协议约束见 [客户端协议](client-protocols.md)。
