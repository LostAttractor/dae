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

路由代码按编译、谓词求值和执行分工：

| 文件 | 职责 |
| --- | --- |
| `control/routing_profile_compiler.go`、`routing_matcher_builder.go` | 展开片段与策略，收集和共享谓词资源，校验完整程序 |
| `control/routing_instruction.go` | 指令标志、动作生成和相对跳距编码 |
| `control/routing_predicate.go` | 用户态谓词求值，按需准备域名位图和 LPM 查询键 |
| `control/routing_matcher_userspace.go`、`routing_matcher_kernspace.go` | 构建与执行用户态匹配器，或向内核发布已编译程序 |
| `control/kern/routing_abi.h` | 内核指令布局、谓词资源和策略 maps |
| `control/kern/routing.h` | 内核策略选择、三态求值和控制动作执行 |
| `control/kern/tproxy.c` | 报文解析、连接归属、路由缓存与转发 |

`rules {}` 和 `routing {}` 共享过滤条件解析、别名和数据集展开，编译成三个独立的逻辑程序，依次执行：

- `DestinationProgram`：内核按完整过滤条件捕获候选，命中后立即交接，避免用旧地址提交路由。用户态匹配原始连接并选定首个 DNAT/Host 目标；原始五元组保留用于身份和回包，新目的地址成为后续程序的输入。不在内核直接修改报文地址。
- `FlowProgram`：累积 `must`、`bump` 和 HTTP 捕获标志。动作使用独立字段，不占用出站编号；控制段末尾统一处理用户态路由要求。共享 IP 导致的 must 歧义不会提前终止控制段，后续确定性 must 和捕获仍然生效。
- `RoutingProgram`：使用重写后的目的地址、地址族和原始来源/接口/进程/策略选择出站及 mark；`must` 同样由新上下文计算。DNAT 与 Surge Host 都在选路前确定目标，不因出站选择撤销映射；新目标上的 block 保持拒绝。

内核仍使用一张 `routing_map`，顺序为 API 精确直通前缀 → DestinationProgram 捕获段 → FlowProgram（包含结束指令）→ RoutingProgram。Go 编译结果记录各段边界，`BuildKernspace` 只上传内核段。DestinationProgram 的精确匹配指令存放在 Go 指令表的用户态后缀，运行时在 FlowProgram 之前单独求值；TCP 连接和活动 UDP 会话复用已经选定的目标。内核段沿用 `MAX_MATCH_SET_LEN` 上限，用户态目的地址段独立检查容量，上限为它的两倍。

内核以 `control_plane_routing` 表示未决路由，无独立的 `route_pending` 字段；本分支的 `profile_id` 位于偏移 36，`no_sniff` 位于偏移 43，`route_epoch` 位于偏移 48，完整结果为 56 字节。编译后的目的地址谓词只保留指令范围和目标 IP，不持有源配置 AST。`RouteParam.destination` 使用有效地址表示已选定目标，UDP 源生命周期固定首次选定的节点、路由及目的地址规则；规则或节点更新不改变已有生命周期，故障结束后同一源端口可按当前规则重新建立。`destination_udp.go` 处理应答地址还原，`udp_binding.go` 管理源绑定。

回归测试覆盖 Host 在 direct/proxy 上的一致改写、原始入口 API 直通和重写目标不能重新进入 API 直通。`TestDestinationUDPReplacementKernelIntegration` 通过实际 UDP 处理入口与私有 BPF maps 同时替换规则和节点，验证已改写与初次未命中两种生命周期在故障前固定目标和 mark，结束后才采用新规则及节点。捕获回归直接检查 SSH、无关 HTTPS 和缺少 DNS 映射的内核判决。
`routingInput` 是目的地址谓词和后续路由共用的输入，统一从原始来源、接口、进程、MAC、DSCP 和策略构造；调用方传入本次目标和实际请求协议，无需中间 context 或改写内核记录的协议字段。`RouteParam.Dest` 保留本次匹配的原目标，`destination` 只保存已选定的有效地址，`effectiveDestination()` 提供后续路由和拨号的目标。UDP 建立源生命周期时保存首次 profile 和目的地址匹配器；后续目的地址复用这套规则，已匹配的目的地址（包括未命中改写的原地址）保持不变。只有生命周期结束后，新报文才按当前接口策略和配置重新选路。

`routeDestination` 从 FlowProgram 开始求值一次，生成纯 `routeDecision` 后再选择拨号器。出站、block 和连通性回退都不改变已选定目标；block 由转发入口阻止拨号。IP 重写保留逻辑域名与 Host/SNI，不递归执行 DNAT，也不重新触发 API 入口直通。Surge Host 与原生 DNAT 使用相同语义；模块解析器对未启用 `use-local-host-item-for-proxy` 的 Host 模块发出兼容性提示，路由执行不依赖该参数。

插件用 `HTTPScope{Scope, PreserveRoute}` 将捕获范围与路由属性放在同一项中；默认在 HTTP 处理后选路，纯检查显式声明 `PreserveRoute: true`。无需维护第二份 scope 列表、比较两个列表或区分 nil 与空列表。Surge 按模块将脚本、URL Rewrite 和 Map Local 归入请求路由，域名、端口与排除条件保持原样。内核在目标处理前缀捕获这些候选，以 `control_plane_routing` 表示需要用户态决定出站，无独立的路由待定字段；完整结果为 56 字节。普通 MITM 保留有效内核路由。客户端准入独立于最终上游路由，已准入的请求先执行 rewrite，再根据最终目标决定 block/direct/proxy；未准入或精确范围未命中时执行普通连接路由。

控制面的职责按文件划分：`route.go` 决定复用或重算路由并提交纯策略结果，`routing_input.go` 统一输入构造，`route_dial.go` 选择节点与带 mark 的拨号器，`route_log.go` 记录路由。`destination_matcher.go` 选择 IP 目标，编译后的谓词只保留指令范围和目标 IP，不持有源配置 AST；`destination_udp.go` 处理回包地址还原，`udp_binding.go` 管理源生命周期的内核绑定。`mitm.go` 负责插件接入和连接准入；`http_target.go` 共用目标解析、DNS 候选与 DestinationRule 求值，`http_route_plan.go` 构建逐请求计划，`http_dial.go` 负责实际上游拨号与统计。`mitm_download.go` 仅管理后台客户端生命周期和 daemon 身份。HTTP Host 只接受 planner，不再保留 dial-only 或可变参数兼容入口。

HTTP 的最终请求和脚本子请求通过同一计划构建逻辑，在连接池查找前选择目标及路由。HTTP/3 转发匹配 UDP 规则，脚本子请求独立匹配 TCP 规则；二者都在改写后匹配 DestinationRule，保留原来源与接口策略。原 authority 使用被截获的 IP，其他 authority 经 dae DNS 形成候选 IP，再执行 DestinationRule、flow 和 routing。请求型范围即使只改路径，也要在 HTTP 处理后首次确定路由；纯检查才复用已有决定。每个原始连接拥有独立的池，池键包含 URL/TLS authority、候选拨号地址、出站、节点、mark 和回退状态；最多缓存 32 个可复用池；`planned_transport.go` 保留被淘汰池的在途响应，响应结束后关闭池，避免中断 HTTP/3 并发流。连接关闭时统一释放所有池。HTTP 请求在查池前收集完整候选计划，后台下载从同一个候选迭代器按需取地址、连接成功即停止。block 终止候选序列，不会因重试绕过。TCP 候选连接的失败重试发生在发送 HTTP 数据之前；HTTP/3 不因握手失败隐式回退 TCP；字节统计归属实际上游连接。未知主机名沿用有效 IP 的 DNS 映射，歧义无法消除时拒绝；显式 IP URL 不借用其他逻辑域名的映射。

共享规则池中的 `match_set` 保持 24 字节，每套接口策略用 `uint16` 指令索引描述执行顺序。编译器直接生成动作，不再先用出站编号表示 OR/AND 后二次转换。非终结指令的 `mark` 字段只保存一个正向跳距：OR 确定命中后跳到子句尾，执行该子句的取反和后续动作；AND 确定失败后直接跳到下一条规则，跳过整条失败规则的剩余谓词和动作。动作类型本身决定字段含义，无需额外标志或旧编码回退。规则片段只在完整规则之间拼接，因此复用片段无需重写跳距，也不增加策略表大小。接口监听更新只修改匹配值，保留跳转元数据。

执行器将谓词求值与动作执行分开。子句使用未命中、歧义、确定命中三个状态，OR 取较强结果，取反不改变歧义；完成的 AND 子句只需累积一个歧义标志，失败立即结束整条规则，无需“已失败”状态。`must` 同样使用三态，确定的 must 覆盖此前不确定的 must，控制段结束时统一判断。程序计数器和少量 `volatile` 状态保留在包的执行上下文中，限制验证器对跨迭代状态的细化。编译器保证完整规则结构及出站参数合法性，内核继续检查策略、指令、域名索引和跳距边界。

用户态执行相同的三态逻辑和单跳距指令，供普通路由和目的地址谓词共用。跳距在完整规则内计算，AND 失败可恰好跳到当前 span 末尾，再由下一个 span 继续；零跳距和越界跳距返回错误。用户态只在实际执行相关谓词时查询域名位图或构造对应 LPM 键，同一次求值复用结果，纯端口和短路路径无需准备这些资源。

域名位图按独立的域名条件 ID 编号，不再使用指令行号。重复域名条件（包括取反条件使用的同一正向集合）共用一个 ID；静态 LPM 集合也可跨程序复用。内核在一个包首次执行域名条件时取得域名映射快照，其余条件复用同一对位图；未找到映射也会记住，下一包重新查询。动态 `client()` 集合使用独立槽位，避免成员更新修改静态匹配条件；接口变更同步两端，用户态目的地址指令不会写入内核表。

UDP 路由缓存按源 IP 和源端口标识生命周期，24 字节键不含目的地址和策略。32 字节决策保留首次入口的出站、mark、must、捕获标志、接口、profile、MAC、DSCP、协议、no_sniff 和设备路由版本，命中时恢复这份身份。加上过期时间、定时器、锁和关闭标志，缓存值为 64 字节；相比携带完整 56 字节结果的 88 字节缓存，65536 项少存储 1.5 MiB 值数据。PID 和进程名当前不由内核写入路由结果，进程谓词独立查询 socket cookie 映射，因此缓存也不重复存储零值。direct 仍保持内核直通，UDP 空闲超时、设备路由版本失效、用户态源绑定和生命周期结束后的重新选路沿用上游流程。

加载沿用 `Prepare → Activate`：先在内存中完成编译和校验，重载时在旧控制面停止后继承域名记录、重算新条件位图，再发布内核表和绑定接口。规则表、域名位图与 LPM 资源必须属于同一份配置。

任何未命中显式捕获或用户态路由要求的 direct 流量继续保持 eBPF 直通。正向域名条件缺少 DNS 映射时不补全流量捕获；内核只选候选连接，MITM/Host 的实际主机名判断仍在用户态完成。
