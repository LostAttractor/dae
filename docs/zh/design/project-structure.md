# 项目组织结构

| 目录 | 职责 |
| --- | --- |
| `cmd` | 命令、启动、重载和生成的插件表 |
| `config` | 用户配置解析与校验 |
| `control` | 控制面、TCP/UDP 转发、内核资源交接；eBPF 位于 `kern` |
| `component/routing`、`outbound` | 路由规则、目的地址计划、出站选择 |
| `component/network`、`sniffing` | 接口管理与协议嗅探 |
| `component/mitm` | HTTP/TLS、插件生命周期；`plugin` 是公开 API，`surge` 实现 sgmodule，`ca` 管理证书 |
| `component/api` | 管理 API 和页面，通过接口调用控制面 |
| `component/dns`、`settings`、`clientset` | DNS、设置持久化、客户端集合 |
| `pkg`、`common`、`trace`、`third_party` | 基础代码、追踪工具和固定版本依赖 |

MITM 是可选组件，业务插件的实现、测试和文档在独立仓库维护。
[mitm_plugins.cfg](../../../mitm_plugins.cfg) 经 `make` 生成
`cmd/mitm_plugins_generated.go`，Setup 表随启动和重载传递。
插件依赖[公开 API](../../../component/mitm/plugin/README.md)，宿主持有传输资源。

原生 [rules / DNAT](../configuration/destination-rules.md) 与 Surge `[Host]`
共用拨号目标重写，独立于 DNS 应答处理。

## 流量控制与路由编译

`rules {}` 与 `routing {}` 共用过滤条件解析，执行顺序为目的地址处理、flow 控制、出站选择。DestinationProgram 的内核捕获保留完整过滤条件；命中 DNAT/Host 或请求型 HTTP 候选后，在旧目标产生 block、mark、must 决定之前交接。用户态按新目标执行 FlowProgram 和 RoutingProgram，保留原来源、接口、进程与 MAC。API 精确直通仅作用于原始入口，不因派生 HTTP 请求重新触发。

`routingInput` 统一构造不可变来源身份与本次有效目标。DNAT/Host 改写 IP 后保留逻辑域名，按新目标选路一次，出站选择不会撤销映射。未启用 `use-local-host-item-for-proxy` 的 Host 模块会收到兼容性提示，路由执行不依赖该参数。`HTTPScope{Scope, PreserveRoute}` 在同一项中声明捕获范围及处理方式；请求型 scope 先执行 HTTP 中间件，再为最终 URL 选择路由。纯检查保留原有效路由，scope 或客户端未准入时执行普通路由。

`route.go` 管理路由阶段与纯策略结果，`routing_input.go` 统一输入构造，`route_dial.go` 选择节点和 mark，`route_log.go` 记录路由。HTTP 转发与辅助请求共用 `http_target.go` 的地址解析及候选迭代器，`http_route_plan.go` 在查连接池之前决定完整拨号计划，`http_dial.go` 仅对实际建立的上游连接计量。原 authority 使用截获 IP，其他 authority 通过 dae DNS 解析。HTTP/3 转发匹配 UDP 规则，辅助 HTTP 请求独立匹配 TCP 规则。派生请求的目的地址谓词使用其自己的协议。

`planned_transport.go` 按 authority、实际地址、节点、出站、mark、协议与回退状态隔离连接池，最多缓存 32 个池；淘汰时保留在途响应直至结束，避免中断 HTTP/3 并发流。本地响应不建立上游连接，block 不能通过复用旧连接绕过。HTTP/3 不在握手失败后自动回退 TCP。

未命中功能范围的 direct 流量继续在内核直通，缺少 DNS 映射不触发宽泛捕获。

内核以 `control_plane_routing` 表示未决路由，无独立的 `route_pending` 字段；删除重复状态后完整结果仍为 40 字节。编译后的目的地址谓词只保留指令范围和目标 IP，不持有源配置 AST。`RouteParam.destination` 使用有效地址表示已选定目标，UDP association 连初次未命中时的原地址也固定保存，节点替换时按当前策略选路与校验嗅探域名。`destination_udp.go` 集中处理地址还原与 ownership。

回归测试覆盖 Host 在 direct/proxy 上的一致改写、原始入口 API 直通和重写目标不能重新进入 API 直通。`TestDestinationUDPReplacementKernelIntegration` 通过实际 UDP 处理入口与私有 BPF maps 同时替换规则和节点，验证已改写与初次未命中两种会话的目标固定、mark 使用新策略。捕获回归直接检查 SSH、无关 HTTPS 和缺少 DNS 映射的内核判决。
