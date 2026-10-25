# 项目组织结构

dae 以 eBPF 数据路径为基础，仅将代理流量、DNS 和明确规则命中的高级功能流量导入用户态。组件按规则编译、控制面发布、协议资源和业务处理划分职责，保持普通 direct 流量的内核直通路径。

| 目录 | 职责 |
| --- | --- |
| `cmd` | 命令参数、信号客户端和程序入口组装 |
| `internal/compiledplugins` | 由本地构建配置生成的插件注册表 |
| `internal/daemon` | 启动、资源加载、差异重载、服务发布与关闭 |
| `config` | 用户配置解析与校验 |
| `control` | 控制面、TCP/UDP 转发、内核资源交接；eBPF 位于 `kern` |
| `component/routing`、`outbound` | 路由规则、目的地址计划、出站选择 |
| `component/network`、`sniffing` | 接口管理与协议嗅探 |
| `component/ca` | CA 读写、原子初始化、公开导出与叶证书缓存；daemon 管理其生命周期，API 和 MITM 共用 |
| `component/mitm`、`component/pluginhost`、`component/plugin` | 协议连接宿主、独立插件实例/后台任务/存储/指标所有权、公开 API |
| `plugins/surge`、`plugins/dns-cache`、`plugins/dns-router` | sgmodule、DNS 应答缓存和 DNS 解析策略及传输 |
| `pkg/outbound` | 客户端协议、传输、拨号链和会话基础能力；不依赖 dae 控制面或业务插件 |
| `pkg/config_parser` | 配置解析基础能力；`grammar` 保存语法，`internal/dae_config` 保存生成的 Go 解析器 |
| `api`、`api/client` | 公开数据契约与独立 HTTP/Unix 客户端 |
| `client/cli`、`client/status` | 终端命令与 API 状态展示 |
| `web`、`internal/webui` | 独立前端源码与构建、产物嵌入及静态托管 |
| `internal/apiserver` | TCP/Unix 监听、HTTP 路由、鉴权、请求校验与重载等待；通过存储接口调用控制面 |
| `component/settings`、`component/clientset` | 设置持久化、客户端集合 |
| `pkg`、`common`、`trace`、`third_party` | 基础代码、追踪工具和固定版本依赖 |

出站运行时的状态和所有权见[出站连通性与故障转移](outbound-connectivity.md)，管理面的信任边界见[API 鉴权与访问控制](api-access-control.md)。

## 仓库与依赖边界

自有 Go 代码使用根目录的 `go.mod` / `go.sum`，核心、CLI、协议库、解析器和业务插件在同一提交中维护，随 dae 统一发版。根目录的文档工具与 `web/` 共用 pnpm workspace 和根 `pnpm-lock.yaml`，pnpm 版本由根 `package.json` 的 `packageManager` 固定。Web 保留独立构建入口，通过 API 契约与 Go 代码协作，不依赖 Go 工具链。第三方 submodule 不纳入 pnpm workspace。

`third_party/quic-go`、`third_party/quickjs-go` 和 `kern/headers` 是固定提交的第三方依赖。fork 的上游同步与库内修改在独立仓库维护，主仓库更新引用并验证集成行为。日常自有代码开发不需要 `go.work`；外部插件或 fork 联调可使用本地 workspace。

仓库边界不代替包的职责边界。`component/outbound` 管理出站选择和运行状态，依赖 `pkg/outbound` 的拨号能力；协议库不反向引用控制面。宿主通过 `component/plugin` 契约调用插件，具体实现只在入口组装。CLI 只依赖 API、轻量展示包和插件客户端，Web 通过 HTTP API 访问服务。依赖检查约束这些方向。

`pkg/proxylink` 提供无运行时依赖的链接标签与 Base64 解析，供协议库、订阅和配置共用。出站协议库可以独立构造、拨号和关闭，依赖检查仅允许它引用明确列出的基础包。

## 插件

MITM 是可选组件，自有业务插件的实现、测试和文档在 `plugins/` 维护。
复制 [plugins.cfg.example](../../../plugins.cfg.example) 为本地 `plugins.cfg` 选择插件；没有本地配置时使用示例。
示例默认仅启用 Surge，DNS cache 和 router 保留为注释，按需在本地配置中启用。编译选择不创建运行时实例，也不扩大流量捕获范围。
`make` 生成 `internal/compiledplugins/plugins_generated.go`，完整 Definition 表（静态校验、资源准备、工厂和命令）随启动和重载传递。
本地选择和生成的注册表不纳入版本控制。插件报告类型、Schema 和客户端展示属于插件自己的 `api` / `client` 包，本体仅传递通用报告与服务。
插件依赖[公开 API](../../../component/plugin/README.md)，宿主持有传输资源。

进程 `Runtime` 持有共享的网卡监听器和接口名称缓存。各控制面及 DNS router 实例通过独立 scope 注册回调；scope 关闭会撤销并排空自己的订阅，源监听器在全部配置代退出后关闭。插件的 scope 可随未变化的实例跨 reload 复用，不绑定某个控制面的关闭时机。

原生 [rules / DNAT](../configuration/destination-rules.md) 与 Surge `[Host]` 的字面 IP 条目共用拨号目标重写；域名条目通过 DNS 插件应答。

## TCP 转发

连接准备与持续转发分离。DNS、MITM 接管连接并使用各自的协议生命周期；普通转发由同一个协调循环管理双向复制、半关闭、排空、中止与空闲关闭。

| 文件 | 职责 |
| --- | --- |
| `control/tcp.go` | 嗅探、路由、协议接管选择和上游拨号 |
| `control/tcp_relay.go` | 接管分派、统计生命周期及双向复制协调 |
| `control/tcp_copy.go` | 连接对的端点、依赖与进度；统一复制结果、计数结算和半关闭 |
| `control/tcp_splice.go` | 原生 TCP 能力检查、嗅探前缀写出及标准库 `io.Copy` |
| `control/tcp_counters_linux.go`、`tcp_monitor.go` | 内核写入计数及 Runtime 共用的活动采样、空闲策略 |
| `control/tcp_lifecycle.go` | 配置代际的连接准备跟踪、共享连接所有权与中止 |

复制前检查两端 socket 和计数能力，再一次性选择原生或缓冲复制。原始连接包装始终负责关闭和释放资源；原生 socket 仅用于复制和采样。两个方向各自结算计数后发送 FIN，协调循环等待双方结束。复制实现不持有路由配置，也不决定连接何时中止。

## DNS

核心的 `dns_relay.go` / `dns_stream.go` 透明转发 TCP/UDP 53，`dns_observer.go` 在交付前登记应答证据（包括缓存回放），插件 observer 在成功交付后观察。报文通过 `netutils.UnpackDnsMessage` 严格解析后才能进入插件和证据观察。域名证据按职责组织：

| 文件 | 职责 |
| --- | --- |
| `control/domain_registry.go` | 共享 pair 的域名/IP 双向索引，DNS 批量登记、验证、期限延长与时间 GC |
| `control/domain_projection.go` | 按 IP 局部生成 AND/OR，容量选择和内核发布 |
| `control/domain_activity.go` | 活动规范化、合并队列及批次应用、精确 pair/IP 续期 |
| `control/domain_activity_conn.go` | TCP/UDP I/O 观察适配，保留半关闭能力 |
| `control/domain_registry_lifecycle.go` | 一个后台循环应用活动、执行 GC 和持久化写入，关闭与 reload 继承 |
| `control/domain_registry_disk.go` | 二进制基线与日志的编解码、续期窗口、压实和崩溃恢复 |

用户态暂不设容量上限，内核是按完整 IP 状态聚合、排序后的有容量子集。详见[DNS 设计与 TODO](../configuration/dns.md)。高级解析策略与传输位于 `plugins/dns-router`，完整应答缓存位于 `plugins/dns-cache`，均可选编译与配置。请求顺序为 Surge → router → 核心中继；cache 在实际上游交换处生效，不受声明位置影响。

### 传输生命周期

核心 `dnsStream` 持有客户端 TCP 连接，按 ID 和问题关联响应；AXFR/IXFR 首帧交付后才转发后续帧。router 的 `transport.Exchange` 拥有单次上游查询的上下文、应答副本和 socket，查询之间不共享连接。并发 UDP 查询使用独立 socket；普通 TCP 查询在连接中断后最多换一个连接重试，不在存活 stream 上重传。TLS 传输校验上游主机名，DoQ 处理 padding、FIN 和协议错误。

核心 UDP 中继从已有缓冲池借用最大报文尺寸的接收缓冲，读取后按实际长度复制应答。返回的 `DNSResponse.Wire` 独立拥有字节，临时缓冲在本次中继返回时归还；后续查询复用缓冲不会改变已经交给插件或交付端的应答。

家族偏好探测使用独立的时间预算和 TCP 连接，其取消不会关闭客户端的共享流。查询失败或取消时不发布应答副本；I/O worker 负责释放连接，取消返回不等待阻塞的 outbound `Close`。

缓存按应答的 `ReceivedAt` 老化 TTL。核心在登记证据前为缺失的时间戳填入交付时间；缓存命中保留原始时间戳，每次交付独立刷新 Registry 的保留期限。

### 证据生命周期

每个域名拥有一份 bitmap，域名索引和 IP 索引引用同一份 pair 期限。活动观察仅延长已有记录，期限更新取最大值；单调评估时间水位防止延迟观察重新引入已回收的证据。IP 节点保存其全部关联域名及 AND/OR、优先级；全零 bitmap 也参与 AND，以表示共享地址上的域名歧义。

每个域名记录保存其全部地址期限的下界，Registry 按下界把记录组织为最小堆，GC 只弹出下界已到的记录并扫描其地址。续期可以留下偏早的下界，扫描时删除到期地址并从剩余期限重新计算；新增 pair 立即降低所属记录的下界，冷恢复和重载安装记录后整体建堆。pair 新增或删除时按 IP 重算聚合，续期只提高期限和相关优先级。一次 DNS 应答批量更新所有关联关系后，每个受影响 IP 只发布一次完整状态。内核驻留选择独立读取 IP 聚合，已驻留 IP 的纯续期无需重写位图。应用观察时推进时间水位并检查到期回收。

首次活动和 DNS 登记同步完成，持续 TCP/UDP I/O、MITM 和 splice 活动使用共享合并队列，每个 `(IP, 域名或空串)` 只保存最大的观察时间。TCP 回调构造时规范化身份，流量观测适配器用于入口已接受的 TCP 连接，保留其原生 socket 和 `CloseWrite` 能力；UDP 按原始目标保存规范化键，首个目标保留嗅探名，其他目标使用 IP。持续 I/O 按连接（UDP 按目标）节流，每秒最多入队一次：TCP 回调用相对进程内单调基准的原子截止时间，无锁判断；UDP 在已持有的端点锁内比较上次入队时间。首次活动不节流。

所有观察共用一个合并队列和一把队列锁。消费者先取得 Registry 锁，再短暂取得队列锁，交换两个可复用 map 后释放队列锁。续期、GC 和内核发布在队列锁之外执行，入队不等待这些 Registry 操作；所有目标共用一次批次边界。

所有者在发布 Registry 前调用一次 `Start`，一个后台循环每秒尝试应用活动并检查续期窗口是否到期，每分钟检查 GC，负责结束续期窗口和压实；新 pair 由创建它的变更自行追加。激活成功后才开始写入。DNS 登记、GC、续期窗口结束和 reload 复制也先应用此前排队的活动，避免回收抢先删除已有证据，或把较早的未知 pair 活动用于新登记。验证和状态读取不消费队列。

关闭在队列锁的临界区中标记退休并截取最后一批活动，按旧窗口应用，停止后台循环后由关闭方写入最后一个续期窗口。普通关闭清空队列的所有者，交接则保留指向退休 Registry 的句柄并继续接收活动；队列所有者和交接状态均由队列锁管理，Registry 的关闭状态由 Registry 锁管理。新 Registry 复制 pair 及原期限，建立双向索引，按当前规则安装 bitmap，切换共享活动句柄，再以新窗口应用截取的交接队列并执行 GC，最后生成全部 IP 聚合。后续入队不等待聚合与内核发布。

冷恢复和重载的记录安装都只用于尚未发布的新 Registry，使用构造时分配的空索引。磁盘恢复在完整校验基线并重放日志后发布记录，调用方持有控制面生命周期锁以排除并发关闭。重载由控制面的单一所有者调用 `ForkFrom`：先停止前驱的后台循环，再移交持久化状态，复制证据（保留 pair 序号）和待处理活动，安装候选内核投影，成功后交接共享活动队列。前驱可继续服务已有连接，无需预先完全关闭；安装失败时保留前驱队列并恢复其周期任务。

持久化状态由拥有文件的 Registry 持有，随 reload 移交，包括当前窗口的到期时间。每次变更在 Registry 锁内只做 O(1) 的工作：为新 pair 分配序号并排入待写列表，或在当前续期窗口中登记一次被续期的 pair；窗口结束时按各 pair 的最终截止时间决定列出序号还是记录精确值。编码和全部 I/O 都在 Registry 锁外完成，日志写入者由一把专用写入锁串行化：创建 pair 的变更用 TryLock 取锁并写出待写列表，取锁失败时由持锁者或后台循环代为写出，不等待压实；持锁者在 Registry 锁内确认待写列表为空后才释放写入锁。fdatasync 不持写入锁，压实全程持有。每个写入者在持锁期间按序号顺序取出待写列表并先写新 pair 帧，再写续期帧，因此日志中引用序号 k 的续期总在创建 k 的帧之后。reload 在移交文件期间持有写入锁，候选 Registry 被接纳前不写入；被拒绝时归还文件和当前窗口。格式、恢复语义与误差上界见 [持久化和诊断](../configuration/dns.md#持久化和诊断)。

Runtime 用一把专用读写锁排序 DNS 证据扇出与 reload：`ForkFrom` 及随后把新代加入服务代集合时持有写锁，扇出持有读锁，因此每个已交付的应答要么先于证据复制写入前驱，要么同时到达新代。扇出只在 Runtime 锁内复制代列表，复制证据也不持有 Runtime 锁，Registry 停顿不会传导到 UDP 入口和 TCP 接入。应答只解析一次，各代按自身规则生成 bitmap。

### 内部解析

`common/netutils/resolver.go` 封装 dae 内部解析：稳定的标准库解析器指针、可原子替换的服务器/路由策略，以及独立的节点引导解析器。`global.dns_resolver` 可覆盖内部服务器；未配置则使用系统 DNS。`internal/daemon` 在监听器就绪和重载提交时切换策略，`control/daemon_dial.go` 提供 dae 进程身份及路由 DNS 拨号，复用 `route_dial.go` 的地址选择和 `dns_upstream.go` 的传输生命周期。代理链和订阅加载使用各自注入的 bootstrap direct dialer，候选准备不替换活动全局拨号器。

解析器安装统一由 `InstallDefaultResolver` 完成校验、构造和发布，底层创建带 mark 的 socket dialer，复用 outbound 的 `SoMarkControl`。direct 使用调用方注入的解析策略，省略时使用 `net.DefaultResolver`。每个 direct 实例持有一个 `net.Dialer`，TCP、连接型 UDP 和无连接 UDP 共用它的 resolver 与 socket Control；无连接 UDP 由 `net.ListenConfig` 创建。独立引导解析器、原子策略快照和 UDP `net.PacketConn` 适配分别负责避免循环依赖、保证重载一致性和保留标准库所需的报文语义。

## 流量控制与路由编译

路由代码按编译、谓词求值和执行分工：

| 文件 | 职责 |
| --- | --- |
| `control/routing_profile_compiler.go`、`routing_flow_compiler.go`、`routing_matcher_builder.go` | 展开片段与策略，收集和共享谓词资源，校验完整程序 |
| `control/routing_state.go` | 编译后规则、动态 client/interface 更新及用户态/内核同步；发布后不保留 Builder |
| `control/routing_instruction.go` | 指令标志、动作生成和相对跳距编码 |
| `control/routing_predicate.go` | 用户态谓词求值，按需准备域名位图和 LPM 查询键 |
| `control/routing_matcher_userspace.go`、`routing_matcher_kernspace.go` | 构建与执行用户态匹配器，或向内核发布已编译程序 |
| `control/kern/routing_abi.h` | 内核指令布局、谓词资源和策略 maps |
| `control/kern/routing.h` | 内核策略选择、三态求值和控制动作执行 |
| `control/kern/tproxy.c` | 报文解析、连接归属、路由缓存与转发 |

policy 内的 `rules {}` 与出站规则共享过滤条件解析、别名和数据集展开。入口接口或默认绑定先选 policy，再执行该策略的三个阶段：

- 目的地址阶段（`DestinationProgram`）：内核按完整过滤条件捕获候选，命中后立即交接，避免用旧地址提交路由。用户态匹配原始连接并选定首个 DNAT/Host 目标；原始五元组保留用于身份和回包，新目的地址成为后续程序的输入。不在内核直接修改报文地址。
- 流量控制阶段：累积 `must`、`bump` 和 HTTP 捕获标志。动作使用独立字段，不占用出站编号；控制段末尾统一处理用户态路由要求。共享 IP 导致的 must 歧义不会提前终止控制段，后续确定性 must 和捕获仍然生效。
- 出站选择阶段：使用重写后的目的地址、地址族和原始来源/接口/进程/策略选择出站及 mark；`must` 同样由新上下文计算。DNAT 与 Surge Host 都在选路前确定目标，不因出站选择撤销映射；新目标上的 block 保持拒绝。

内核使用一张共享物理指令表 `routing_map`，每个 policy 的 spans 单独组织执行顺序：API 精确直通 → 策略 DNAT 与全局插件捕获 → 策略 must/bump 和纯 MITM 捕获（包含控制结束指令）→ 插件前置路由、策略正文、插件普通路由和 fallback。共享片段只编译一次；物理存储位置不决定阶段顺序。Go 的 span 保留阶段，目标选定后跳过入口阶段，不再依赖全局下标分界。每个 policy 的 DestinationProgram 引用该策略的 DNAT 和全局插件目标规则；精确谓词存放在用户态后缀，`BuildKernspace` 只上传内核池。TCP 连接和活动 UDP 会话复用已经选定的目标。内核段沿用 `MAX_MATCH_SET_LEN` 上限，用户态目的地址段独立检查容量，上限为它的两倍。

内核以 `control_plane_routing` 表示未决路由。交接和 UDP 缓存共用无对齐空洞的 40 字节 `routing_result`：`route_epoch` 位于偏移 0，`profile_id` 位于偏移 16，`physinif` 位于偏移 32，`generation` 位于偏移 36。`generation` 标识配置代，`route_epoch` 独立标识设备连接策略版本。用户态 `routingResult` 嵌入该结果，并保存交接带来的本机进程名或内部请求的 PID/进程名。TCP 长期转发使用独立的 16 字节 `tcp_flow_state`，只保留设备版本、mark 和 `owner`：`owner` 为 0 表示普通直通，全 1 表示重定向到用户态，其他值是内核降级直连所属 fallback 代次的令牌。用户态分配令牌时跳过 0 和全 1，因此令牌可以与这些标记共用字段；普通无 mark、无设备版本、无令牌的内核直通无需记录。流状态随连接结束：内核转发的流在发起方发送 RST 时，内核按状态转发该 RST 后删除状态，此后发起方应答对端在途报文的 RST 不再带 mark；重定向到用户态的流不因 RST 删除，发起方后续的 RST 仍交给 dae 而不发往目标。透明监听 socket 的 `TCP_LINGER2` 为负：dae 先于客户端关闭时，客户端确认 dae 的 FIN 后即被重置，relay 结束后不会留下仍能发送的客户端 socket。状态在该元组最后一个已接受连接的 relay 结束 60 秒（TIME_WAIT 时长）后删除，覆盖关闭握手的重传和丢失的 RST；元组被新的已接受连接或内核转发的新连接复用时保留。内核转发流正常关闭后由 LRU 回收。`routing_tuples_map` 是 16384 项的交接 LRU：64 字节值包含完整结果、单调秒数过期时间、TCP 初始序列号和发送方本机进程名（供用户态重新求值 `pname()`），字段无空洞。TCP accept 原子取出并删除交接；相同 SYN 的重传在 30 秒内复用它且不续期；UDP 读取快照。交接容量和过期都不影响已建立 TCP 的转发状态。

编译后的目的地址谓词保存指令范围和目标 IP。`RouteParam.destination` 使用有效地址表示已选定目标，UDP 源生命周期固定首次选定的节点、路由及目的地址规则；规则或节点更新不改变已有生命周期，故障结束后同一源端口可按当前规则重新建立。`udp_destination.go` 管理目标 socket 与应答地址还原，`udp_binding.go` 管理源绑定。

`routingInput` 是目的地址谓词和后续路由共用的输入，统一从原始来源、接口、进程、MAC、DSCP 和策略构造；调用方传入本次目标和实际请求协议，无需中间 context 或改写内核记录的协议字段。`RouteParam.Dest` 保留本次匹配的原目标，`destination` 只保存已选定的有效地址，`effectiveDestination()` 提供后续路由和拨号的目标。UDP 建立源生命周期时保存首次 profile 和目的地址匹配器；后续目的地址复用这套规则，已匹配的目的地址（包括未命中改写的原地址）保持不变。只有生命周期结束后，新报文才按当前接口策略和配置重新选路。

`routeDestination` 跳过所选 policy 的入口阶段，从流量控制阶段开始求值一次，生成纯 `routeDecision` 后再选择拨号器。出站、block 和连通性回退都不改变已选定目标；block 由转发入口阻止拨号。IP 重写保留逻辑域名与 Host/SNI，不递归执行 DNAT，也不重新触发 API 入口直通。Surge 字面 IP Host 与原生 DNAT 使用相同语义；域名 Host 不自动产生 DNAT 或扩大捕获。`use-local-host-item-for-proxy` 控制已捕获代理连接是否保留 Host 静态 DNS 地址。

插件用 `HTTPScope{Scope, PreserveRoute}` 声明捕获范围与路由属性；默认在 HTTP 处理后选路，纯检查显式声明 `PreserveRoute: true`。Surge 按模块将脚本、URL Rewrite 和 Map Local 归入请求路由，域名、端口与排除条件保持原样。内核在目标处理前缀捕获这些候选，以 `control_plane_routing` 表示需要用户态决定出站。普通 MITM 保留有效内核路由。客户端准入独立于最终上游路由，已准入的请求先执行 rewrite，再根据最终目标决定 block/direct/proxy；未准入或精确范围未命中时执行普通连接路由。

请求处理后选路与保留原路由的 HTTP 捕获段各有一个条件块入口，使用内部 HTTP 客户端准入谓词与通用 `ConditionalJump` 动作。首次进入任一捕获段时按设备覆盖设置和客户端规则查询准入，同次路由求值复用结果；拒绝时直接跳过整个段，不读取该段的域名、IP、端口等匹配条件。无 HTTP 捕获或已由前面的规则结束的连接不查询 HTTP 客户端表。内核与用户态解释器使用相同的段入口和相对跳转，诊断将拒绝的捕获规则标记为 `client_not_allowed`；独立的 DNAT、must/bump、DNS 和普通路由不受该准入控制。

控制面的职责按文件划分：`route.go` 决定复用或重算路由并提交纯策略结果，`routing_input.go` 统一输入构造，`route_dial.go` 选择节点与带 mark 的拨号器，`route_log.go` 记录路由。`destination_matcher.go` 选择 IP 目标；`udp_destination.go` 管理目标 socket 与回包地址还原，`udp_binding.go` 管理源生命周期的内核绑定。`mitm.go` 负责插件接入和连接准入；`http_target.go` 共用目标解析、DNS 候选与 DestinationRule 求值，`http_route_plan.go` 构建逐请求计划，`http_dial.go` 负责实际上游拨号与统计。`mitm_download.go` 管理后台客户端生命周期和 daemon 身份。HTTP Host 接受 planner，由计划确定目标、路由及传输资源。

节点的 `groupBinding` 保存成功延迟统计、恢复窗口配置和完成状态，由共享路径的锁保护。共享路径负责故障事实和恢复观察时间；恢复验证复用单次测试与现有连通性调度器，失败不写入延迟窗口。自动选择控制器负责存活节点接替、切换后验证请求、分层选举、升级检查与探测需求，在节点通知时同步决策。无业务或探测需求的物理会话可休眠并按需重建，逻辑候选身份保持稳定。用户态 Trie 构造时的未压缩 rank/select 数组为局部临时数据，对象只保留查询所需的紧凑索引。

HTTP 的最终请求和脚本子请求通过同一计划构建逻辑，在连接池查找前选择目标及路由。HTTP/3 转发匹配 UDP 规则，脚本子请求独立匹配 TCP 规则；二者都在改写后匹配 DestinationRule，保留原来源与接口策略。原 authority 使用被截获的 IP（代理连接按 `dial_target_override` 发送域名），其他 authority 没有客户端选定的地址，经系统解析器形成候选 IP，再执行 DestinationRule、flow 和 routing。请求型范围即使只改路径，也要在 HTTP 处理后首次确定路由；纯检查才复用已有决定。每个原始连接拥有独立的池，池键包含 URL/TLS authority、候选拨号地址、出站、节点、mark 和回退状态；最多缓存 32 个可复用池；`planned_transport.go` 保留被淘汰池的在途响应，响应结束后关闭池，避免中断 HTTP/3 并发流。连接关闭时统一释放所有池。HTTP 请求在查池前收集完整候选计划，后台下载从同一个候选迭代器按需取地址、连接成功即停止。每个候选地址独立路由，被 block 的地址不拨号，全部被 block 时拒绝请求；代理收到域名时，路由到同一节点的候选地址共用一次拨号。TCP 候选连接的失败重试发生在发送 HTTP 数据之前；HTTP/3 不因握手失败隐式回退 TCP；字节统计归属实际上游连接。未知主机名沿用有效 IP 的 DNS 映射，歧义无法消除时拒绝；显式 IP URL 不借用其他逻辑域名的映射。

共享规则池中的 `match_set` 为 24 字节，每套接口策略用 `uint16` 指令索引描述执行顺序。编译器直接生成动作，动作类型决定字段含义。非终结指令的 `mark` 字段保存一个正向跳距：OR 确定命中后跳到子句尾，执行该子句的取反和后续动作；AND 确定失败后直接跳到下一条规则，跳过整条失败规则的剩余谓词和动作。`ConditionalJump` 在条件失败时跳过整个规则块，其前置 AND 子句失败也直接跳到块尾。跳距以策略执行顺序为坐标，用户态游标可跨物理片段前进；共享或重复片段无需重写内部跳距，也不增加策略表大小。接口监听更新只修改匹配值，保留跳转元数据。

`条件 -> use()` 编译为入口谓词和共享主体，各层条件保留独立边界，不向每条规则复制。编译器验证块之间只能嵌套或分离，入口与主体属于同一阶段，跳转目标落在完整规则边界。DNAT 捕获和流量控制分别包裹条件块；用户态目的地址精确谓词保留完整条件，对原目标选取首个改写规则。

执行器将谓词求值与动作执行分开。子句使用未命中、歧义、确定命中三个状态，OR 取较强结果，取反不改变歧义；完成的 AND 子句只需累积一个歧义标志，失败立即结束整条规则，无需“已失败”状态。歧义入口只记录其块尾位置，终结动作在该边界内继承歧义；嵌套块取最远的有效歧义边界，越过边界自动失效，不需要运行时作用域栈。入口歧义本身不触发捕获，块内条件仍可排除候选。`must` 同样使用三态，确定的 must 覆盖此前不确定的 must，控制段结束时统一判断。程序计数器、歧义边界和动作结果组成不含指针的 `route_state`；`route_apply` 作为全局 BPF 子程序独立验证，隔离谓词分支与动作、循环状态的组合。谓词所需的域名快照和准入缓存保留在求值上下文中。路由入口接收不含指针的报文字段，作为全局 BPF 子程序独立验证，避免报文解析和连接分支的状态与路由迭代路径组合膨胀；输入和无指针动作状态复用入口的 per-CPU 暂存区，所选策略 ID 写回该输入，策略和域名快照指针仅保留在求值器内部。编译器保证完整规则结构及出站参数合法性，内核继续检查策略、指令、域名索引和跳距边界。

内核的 `route_step_result` 仅表示继续或停止解释执行，实际路由决定保存在 `route_state.result` 中。`route_step()` 内联完成取指、谓词求值、AND/OR、取反和条件跳转，只有匹配成功的终结动作才调用 `route_apply()`；未命中规则和条件短路不经过动作子程序。`route()` 与 `route_apply()` 保留独立验证边界，连通性查询和结果编码使用内联函数。LPM 与 HTTP 客户端准入查询分别使用独立栈帧，让查询键的临时存储与规则遍历解耦。循环只限制最大执行次数，实际取指位置由前向跳转维护。

用户态执行相同的三态逻辑和单跳距指令，供普通路由和目的地址谓词共用。游标维护物理指令位置与逻辑执行位置，普通短路和条件块跳转共用前进操作；零跳距和超出整个程序的跳距返回错误。用户态只在实际执行相关谓词时查询域名位图或构造对应 LPM 键，同一次求值复用结果，纯端口和短路路径无需准备这些资源。

域名位图按独立的域名条件 ID 编号。重复域名条件（包括取反条件使用的同一正向集合）共用一个 ID；静态 LPM 集合也可跨程序复用。内核在一个包首次执行域名条件时取得域名映射快照，其余条件复用同一对位图；未找到映射也会记住，下一包重新查询。动态 `client()` 集合使用独立槽位，避免成员更新修改静态匹配条件；接口变更同步两端，用户态目的地址指令不会写入内核表。

UDP 路由缓存按源 IP 和源端口标识生命周期，24 字节键不含目的地址和策略。缓存直接保存、恢复完整 `routing_result`，无需字段转换；其中保留首次入口的出站、mark、must、捕获标志、接口、profile、MAC、DSCP、协议、设备路由版本和 reload 规则版本。加上过期时间、定时器、锁和 fallback 令牌，缓存值为 72 字节，无对齐空洞；生命周期结束时令牌字段改写为全 1 作为关闭标记，此时已不再需要令牌。进程谓词读取发送 socket 自身的归属存储。UDP 空闲超时、设备路由版本失效、reload 规则版本失效、fallback 令牌撤销和用户态源绑定共同约束生命周期，结束后的报文按当前规则重新选路。

UDP 流方向状态按五元组记录首包方向。LAN 入口和本机发出的报文开始出站流，按规则选路；LAN 出口上没有状态的报文（例如端口转发）开始入站流，其回复直连。WAN 入口位于 NAT 和防火墙之前，只有发往本机 socket（dae 自身的除外）的报文才开始入站流，例如本机的 WireGuard 服务；转发流经 NAT 后在 LAN 出口建立状态。入站流得到应答后才建立状态：此前记录在 16384 项的待应答 LRU 中，值为最近报文所在的秒；空闲超时内另一方向的首个报文（本机服务在 WAN 出口、LAN 主机在 LAN 入口）将其建立为入站状态。无人应答的报文（例如伪造来源发往 WireGuard 端口）只轮换该 LRU，不占用状态表，不会使新流因状态表已满而被丢弃；洪泛下首包在应答前被淘汰的入站流，其应答按出站流选路。经端口重定向或 DNAT 到达本机服务的入站流在 WAN 入口查不到 socket，其回复经反向 NAT 到达 WAN 出口时仍无状态，由 conntrack 判定为回复方向，开始入站流并直连。dae 经 dae0 中继的回复属于用户态关联，没有状态时开始出站流，因此本机进程对 full-cone 中继来源的回复仍按规则选路，不会被 conntrack 方向误判为入站。状态在双向都空闲 300 秒后删除：报文只记录所在的秒，定时器到期时检查空闲时长，不足则按剩余时间重新定时。定时器持有设置回调的程序，由处理该流报文的当前配置代接管，长期流不会让已退役的配置代常驻。

用户态 UDP endpoint 和 Anyfrom 回包 socket 各自保存空闲截止时间。活动在所属锁内延长截止时间，计时器首次建立后由到期回调检查最新值：提前触发时按剩余时间重新定时，真正到期时才删除对应实例并关闭 socket。持续活动无需逐包重设计时器；实例身份检查防止旧回调删除替代连接。

UDP 包的期限从入队时起算。已建立关联的写入只设置 socket 写截止时间，写后清除，不为每包创建 context 或定时器；不支持写截止时间的传输改用定时器，到期关闭 socket。从不阻塞的传输（`netproxy.NonBlockingWriter`）以 `TryWriteTo` 写入，不设截止时间、不占写入槽也不建定时器；其队列或 socket 发送缓冲区已满时丢弃数据报，计入 UDP 容量丢包，不算路径错误、中继失败或上传字节，MITM 与 DNS 上游的调用方则只见到途中丢失的数据报。smux 的 UDP 流排入会话队列；上传字节在入队时计入，会话失败时仍在队列中的字节已计为上传。每个关联独占内核 UDP socket 的出站（direct、Shadowsocks、Shadowsocks 2022、流加密 Shadowsocks、SSR、SOCKS5、juicity underlay）以 `MSG_DONTWAIT` 经 `RawConn.Control` 发送，`EAGAIN` 即丢弃并计为 `socket_full`：这类 socket 在出口 qdisc（如 cake）中各成一条流，排队与公平交给 qdisc，worker 不替它等待。加密层自己实现 `TryWriteTo`，先加密再交给下层的非阻塞写入，不实现 `Unwrap`，因此查找 `NonBlockingWriter` 不会越过加密直达 socket；下层只能阻塞（如链式代理经尚未改造的流承载）时 `TryWriteTo` 返回 `errors.ErrUnsupported` 且不发送，写入改走阻塞路径及其截止时间。这些出站的 `WriteTo` 同样不等待发送缓冲区，丢弃视为写成功，只有解析域名目标时等待。MITM HTTP/3 桥接对端队列已满时同样丢弃。其他传输（包括 yamux）保持阻塞写入及其截止时间。为新目的地建立 socket、setup 和 MITM 等非 socket 工作才派生带包期限的 context。代际中断由任务池 worker 的写入槽承担：worker 先发布在写的 socket 再复查取消状态，中断方先取消任务池再扫描各槽，对在写的 socket 设为立即到期并在后台关闭，因此 Runtime 随后获取源锁时不等待阻塞写入。Anyfrom 回包先非阻塞发送，只有发送缓冲区已满时才串行化写入并设置写截止时间。能推送回包的传输（`netproxy.PacketPusher`，如 smux 的 UDP 流）由 session 的接收循环交付回包，不为每个 socket 启动读取 goroutine；处理器在 socket 首次写入前注册，回包不会无人接收。接收循环服务 session 的所有流，因此不能阻塞：只有目标已观测过、回包地址的 Anyfrom socket 已存在（首个回包地址缓存的 socket，或不等待锁即可在池中查到的 socket）且以 `MSG_DONTWAIT` 一次发出的回包才在接收循环上发送；其余回包（首次观测目标需同步刷新注册表、socket 池被占用或需新建 socket、raw 回退、发送缓冲区已满）连同该 socket 之后的回包交给按需启动的 goroutine 按序发送，队列最多 128 个，超出或超过 UDP 包内存预算的回包被丢弃并计入 UDP 容量丢包。交付结束的通知可能来自接收循环或持有源锁的关闭方，同样由该 goroutine 在已排队的回包之后结束 socket。

`Runtime` 持有监听循环、内核挂载、TCP 集合、UDP endpoint 与跨代连接 maps；TCP/UDP 原始监听 FD 通过 `SyscallConn.Control` 注册到内核并直接服务，无额外 FD 副本。`BPFState` 和控制平面只拥有单个配置代。候选在独立规则、域名位图、LPM、接口策略、出站状态和 API 观察表中准备，失败可独立关闭。静态规则只上传一次；发布前排空旧 API 写入，仅刷新 selector 和变化的 client LPM 槽位，不重建静态表或重订阅接口。profile ID 从 1 起在本代内分配，零表示用户态默认策略。域名证据复制后按新条件投影，DNS 后续观察分发给仍存活的各代。TCX 使用 `link.Update` 原位替换，每个接口引用完整配置，无全局暂停；多接口切换不是单一原子事务。

`ControlPlane` 组合流量接入、HTTP 插件、DNS、出站、API 设置、路由和接口状态。只使用单项状态的操作由对应组件承载，跨组件启动、发布和关闭仍由控制平面协调。构造先验证配置，再接管内核准备结果，依次建立用户态资源、出站和路由，最后启动连通性检查并准备插件。失败候选先取消准备工作，再走相同的关闭顺序，保留构造错误与清理错误；内核资源和用户态请求的退出阶段保持独立。

`Runtime` 的 `InterfaceManager` 持有唯一的 link netlink 订阅和接口缓存，控制平面与插件各借用作用域。接口新增、删除、重命名的生命周期回调保持有序；同名接口的 carrier、operstate 等属性变化通过可合并通知送给 `HostNetworkMonitor`，不重复触发绑定回调。监控器自行订阅地址、路由和策略规则事件，并通过完整 dump 重建快照；事件只是刷新提示，不作为连通性证明。订阅中断与恢复也触发刷新。关闭监控器或某个作用域只释放其观察者，完整进程退出时才关闭共享 link 事件源。

常驻接入循环按交接的 generation 分发，旧代保留 30 秒接入宽限期，随后停止 setup 并排空 MITM/DNS；下一次候选准备等待退役完成，使配置资源最多同时保留两代。普通 TCP relay 及 UDP 会话独立保留已选资源，组策略 lease 的迟到获取仍归当前组管理。暂停、停止和 abort 都通过 Runtime 收束连接及内核回包路径。

除自动接管的 DNS 53 外，任何未命中显式捕获或用户态路由要求的 direct 流量继续保持 eBPF 直通。正向域名条件缺少 DNS 映射时不补全流量捕获；内核只选候选连接，MITM 的实际主机名判断仍在用户态完成。DNS 仍尊重 `must` 和 API 直通前缀，不借用或替换无关 UDP 源会话的路由。

测试方法、基准命令和指标口径见[测试与性能测量](../development/testing-and-performance.md)。
