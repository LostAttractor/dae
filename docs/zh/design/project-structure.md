# 项目组织结构

| 目录 | 职责 |
| --- | --- |
| `cmd` | 命令、启动、重载和生成的插件表 |
| `config` | 用户配置解析与校验 |
| `control` | 控制面、TCP/UDP 转发、内核资源交接；eBPF 位于 `kern` |
| `component/routing`、`outbound` | 路由规则、目的地址计划、出站选择 |
| `component/network`、`sniffing` | 接口管理与协议嗅探 |
| `component/mitm`、`component/plugin` | HTTP/TLS、通用插件生命周期与公开 API；`mitm/surge` 实现 sgmodule，`mitm/ca` 管理证书 |
| `api`、`api/client` | 公开数据契约与独立 HTTP/Unix 客户端 |
| `client/cli`、`client/status` | 终端命令与 API 状态展示 |
| `web`、`internal/webui` | 独立前端源码与构建、产物嵌入及静态托管 |
| `internal/apiserver` | TCP/Unix 监听、HTTP 路由、鉴权、请求校验与重载等待；通过存储接口调用控制面 |
| `component/settings`、`component/clientset` | 设置持久化、客户端集合 |
| `pkg`、`common`、`trace`、`third_party` | 基础代码、追踪工具和固定版本依赖 |

## 插件

MITM 是可选组件，业务插件的实现、测试和文档在独立仓库维护。
[plugins.cfg](../../../plugins.cfg) 经 `make` 生成
`cmd/plugins_generated.go`，完整 Definition 表（静态校验、Setup 和命令）随启动和重载传递。
插件依赖[公开 API](../../../component/plugin/README.md)，宿主持有传输资源。

原生 [rules / DNAT](../configuration/destination-rules.md) 与 Surge `[Host]` 的字面 IP 条目共用拨号目标重写；域名条目通过 DNS 插件应答。

## DNS

核心的 `dns_relay.go` / `dns_stream.go` 透明转发 TCP/UDP 53，`dns_observer.go` 观察成功交付的应答（包括缓存回放）。报文通过 `netutils.UnpackDnsMessage` 严格解析后才能进入插件和证据观察。域名证据按职责组织：

| 文件 | 职责 |
| --- | --- |
| `control/domain_registry.go` | 共享 pair 的域名/IP 双向索引，DNS 批量登记、验证、期限延长与时间 GC |
| `control/domain_projection.go` | 按 IP 局部生成 AND/OR，容量选择和内核发布 |
| `control/domain_activity.go` | 活动规范化、合并队列及批次应用、精确 pair/IP 续期 |
| `control/domain_activity_conn.go` | TCP/UDP I/O 观察适配，保留半关闭能力 |
| `control/domain_registry_lifecycle.go` | 一个后台循环应用活动、执行 GC/脏保存，关闭与 reload 继承 |
| `control/domain_registry_disk.go` | 分组 gzip JSON 编解码、完整校验和原子发布 |

用户态暂不设容量上限，内核是按完整 IP 状态聚合、排序后的有容量子集。详见[DNS 设计与 TODO](../configuration/dns.md)。高级解析策略与传输位于独立的 `dae-plugin-dns-router`，完整应答缓存位于 `dae-plugin-dns-cache`，均可选编译与配置。推荐插件顺序为 cache → Surge → router → 核心中继。

### 传输生命周期

核心 `dnsStream` 持有客户端 TCP 连接，按 ID 和问题关联响应；AXFR/IXFR 首帧交付后才转发后续帧。router 的 `transport.Exchange` 拥有单次上游查询的上下文、应答副本和 socket，查询之间不共享连接。并发 UDP 查询使用独立 socket；普通 TCP 查询在连接中断后最多换一个连接重试，不在存活 stream 上重传。TLS 传输校验上游主机名，DoQ 处理 padding、FIN 和协议错误。

核心 UDP 中继从已有缓冲池借用最大报文尺寸的接收缓冲，读取后按实际长度复制应答。返回的 `DNSResponse.Wire` 独立拥有字节，临时缓冲在本次中继返回时归还；后续查询复用缓冲不会改变已经交给插件或交付端的应答。

家族偏好探测使用独立的时间预算和 TCP 连接，其取消不会关闭客户端的共享流。查询失败或取消时不发布应答副本；I/O worker 负责释放连接，取消返回不等待阻塞的 outbound `Close`。

缓存按应答的 `ReceivedAt` 老化 TTL。核心在交付 observer 前为缺失的时间戳填入交付时间；缓存命中保留原始时间戳，成功交付则独立刷新 Registry 的保留期限。

### 证据生命周期

每个域名拥有一份 bitmap，域名索引和 IP 索引引用同一份 pair 期限。活动观察仅延长已有记录，期限更新取最大值；单调评估时间水位防止延迟观察重新引入已回收的证据。IP 节点保存其全部关联域名及 AND/OR、优先级；全零 bitmap 也参与 AND，以表示共享地址上的域名歧义。

Registry 以最早可能到期时间作为 GC 扫描门槛。续期可以留下偏早的门槛，扫描时从剩余期限重新计算；新增记录、冷恢复和重载安装记录都将期限纳入门槛。pair 新增或删除时按 IP 重算聚合，续期只提高期限和相关优先级。一次 DNS 应答批量更新所有关联关系后，每个受影响 IP 只发布一次完整状态。变更计数用于脏快照保存；内核驻留选择独立读取 IP 聚合，已驻留 IP 的纯续期无需重写位图。应用观察时推进时间水位并检查到期回收。

首次活动和 DNS 登记同步完成，持续 TCP/UDP I/O、MITM 和 splice 活动使用共享合并队列，每个 `(IP, 域名或空串)` 只保存最大的观察时间。TCP 回调构造时规范化身份，流量观测适配器用于入口已接受的 TCP 连接，保留其原生 socket 和 `CloseWrite` 能力；UDP 按原始目标保存规范化键，首个目标保留嗅探名，其他目标使用 IP。

所有观察共用一个合并队列和一把队列锁。消费者先取得 Registry 锁，再短暂取得队列锁，交换两个可复用 map 后释放队列锁。续期、GC 和内核发布在队列锁之外执行，入队不等待这些 Registry 操作；所有目标共用一次批次边界。

所有者在发布 Registry 前调用一次 `Start`，一个后台循环每秒尝试应用活动，每分钟检查 GC，每 30 秒检查脏快照；激活成功后启用持久化。DNS 登记、GC 和快照复制也先应用此前排队的活动，避免回收抢先删除已有证据，或把较早的未知 pair 活动用于新登记。验证和状态读取不消费队列。

关闭在队列锁的临界区中标记退休并截取最后一批活动，按旧窗口应用后保存。普通关闭清空队列的所有者，交接则保留指向退休 Registry 的句柄并继续接收活动；队列所有者和交接状态均由队列锁管理，Registry 的关闭状态由 Registry 锁管理。新 Registry 复制 pair 及原期限，建立双向索引，按当前规则安装 bitmap，切换共享活动句柄，再以新窗口应用截取的交接队列并执行 GC，最后生成全部 IP 聚合。后续入队不等待聚合与内核发布。

冷恢复和重载的记录安装都只用于尚未发布的新 Registry，使用构造时分配的空索引。磁盘恢复在完整校验 gzip 和 JSON 流后发布记录，调用方持有控制面生命周期锁以排除并发关闭；重载交接由控制面的单一所有者执行，前驱必须已完全关闭。

### 内部解析

`common/netutils/resolver.go` 封装 dae 内部解析：稳定的标准库解析器指针、可原子替换的服务器/路由策略，以及独立的节点引导解析器。`global.dns_resolver` 可覆盖内部服务器；未配置则使用系统 DNS。`cmd/daemon.go` 在监听器就绪和重载提交时切换策略，`control/daemon_dial.go` 提供 dae 进程身份及路由 DNS 拨号，复用 `route_dial.go` 的地址选择和 `dns_upstream.go` 的传输生命周期。代理链底层使用独立 bootstrap direct dialer，避免解析节点依赖尚未建立的代理。

解析器安装统一由 `InstallDefaultResolver` 完成校验、构造和发布，底层创建带 mark 的 socket dialer，复用 outbound 的 `SoMarkControl`。direct 使用调用方注入的解析策略，省略时使用 `net.DefaultResolver`。每个 direct 实例持有一个 `net.Dialer`，TCP、连接型 UDP 和无连接 UDP 共用它的 resolver 与 socket Control；无连接 UDP 由 `net.ListenConfig` 创建。独立引导解析器、原子策略快照和 UDP `net.PacketConn` 适配分别负责避免循环依赖、保证重载一致性和保留标准库所需的报文语义。

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

内核以 `control_plane_routing` 表示未决路由。路由结果中的 `profile_id` 位于偏移 36，`no_sniff` 位于偏移 43，`route_epoch` 位于偏移 48，完整结果为 56 字节。编译后的目的地址谓词保存指令范围和目标 IP。`RouteParam.destination` 使用有效地址表示已选定目标，UDP 源生命周期固定首次选定的节点、路由及目的地址规则；规则或节点更新不改变已有生命周期，故障结束后同一源端口可按当前规则重新建立。`destination_udp.go` 处理应答地址还原，`udp_binding.go` 管理源绑定。

`routingInput` 是目的地址谓词和后续路由共用的输入，统一从原始来源、接口、进程、MAC、DSCP 和策略构造；调用方传入本次目标和实际请求协议，无需中间 context 或改写内核记录的协议字段。`RouteParam.Dest` 保留本次匹配的原目标，`destination` 只保存已选定的有效地址，`effectiveDestination()` 提供后续路由和拨号的目标。UDP 建立源生命周期时保存首次 profile 和目的地址匹配器；后续目的地址复用这套规则，已匹配的目的地址（包括未命中改写的原地址）保持不变。只有生命周期结束后，新报文才按当前接口策略和配置重新选路。

`routeDestination` 从 FlowProgram 开始求值一次，生成纯 `routeDecision` 后再选择拨号器。出站、block 和连通性回退都不改变已选定目标；block 由转发入口阻止拨号。IP 重写保留逻辑域名与 Host/SNI，不递归执行 DNAT，也不重新触发 API 入口直通。Surge 字面 IP Host 与原生 DNAT 使用相同语义；域名 Host 不自动产生 DNAT 或扩大捕获。`use-local-host-item-for-proxy` 控制已捕获代理连接是否保留 Host 静态 DNS 地址。

插件用 `HTTPScope{Scope, PreserveRoute}` 声明捕获范围与路由属性；默认在 HTTP 处理后选路，纯检查显式声明 `PreserveRoute: true`。Surge 按模块将脚本、URL Rewrite 和 Map Local 归入请求路由，域名、端口与排除条件保持原样。内核在目标处理前缀捕获这些候选，以 `control_plane_routing` 表示需要用户态决定出站。普通 MITM 保留有效内核路由。客户端准入独立于最终上游路由，已准入的请求先执行 rewrite，再根据最终目标决定 block/direct/proxy；未准入或精确范围未命中时执行普通连接路由。

控制面的职责按文件划分：`route.go` 决定复用或重算路由并提交纯策略结果，`routing_input.go` 统一输入构造，`route_dial.go` 选择节点与带 mark 的拨号器，`route_log.go` 记录路由。`destination_matcher.go` 选择 IP 目标；`destination_udp.go` 处理回包地址还原，`udp_binding.go` 管理源生命周期的内核绑定。`mitm.go` 负责插件接入和连接准入；`http_target.go` 共用目标解析、DNS 候选与 DestinationRule 求值，`http_route_plan.go` 构建逐请求计划，`http_dial.go` 负责实际上游拨号与统计。`mitm_download.go` 管理后台客户端生命周期和 daemon 身份。HTTP Host 接受 planner，由计划确定目标、路由及传输资源。

节点的 `groupBinding` 直接保存最近十次连通性检查的延迟与失败标记，由 `Dialer.mu` 统一保护。失败检查按配置罚时入窗，读取快照时从这十个样本计算平均值和窗口失败状态；移动平均在记录样本时更新。可用性查询只检查健康、当前 Session 和网络支持状态。用户态 Trie 构造时的未压缩 rank/select 数组为局部临时数据，对象只保留查询所需的紧凑索引。

HTTP 的最终请求和脚本子请求通过同一计划构建逻辑，在连接池查找前选择目标及路由。HTTP/3 转发匹配 UDP 规则，脚本子请求独立匹配 TCP 规则；二者都在改写后匹配 DestinationRule，保留原来源与接口策略。原 authority 使用被截获的 IP，其他 authority 经系统解析器形成候选 IP，再执行 DestinationRule、flow 和 routing。请求型范围即使只改路径，也要在 HTTP 处理后首次确定路由；纯检查才复用已有决定。每个原始连接拥有独立的池，池键包含 URL/TLS authority、候选拨号地址、出站、节点、mark 和回退状态；最多缓存 32 个可复用池；`planned_transport.go` 保留被淘汰池的在途响应，响应结束后关闭池，避免中断 HTTP/3 并发流。连接关闭时统一释放所有池。HTTP 请求在查池前收集完整候选计划，后台下载从同一个候选迭代器按需取地址、连接成功即停止。block 终止候选序列，不会因重试绕过。TCP 候选连接的失败重试发生在发送 HTTP 数据之前；HTTP/3 不因握手失败隐式回退 TCP；字节统计归属实际上游连接。未知主机名沿用有效 IP 的 DNS 映射，歧义无法消除时拒绝；显式 IP URL 不借用其他逻辑域名的映射。

共享规则池中的 `match_set` 为 24 字节，每套接口策略用 `uint16` 指令索引描述执行顺序。编译器直接生成动作，动作类型决定字段含义。非终结指令的 `mark` 字段保存一个正向跳距：OR 确定命中后跳到子句尾，执行该子句的取反和后续动作；AND 确定失败后直接跳到下一条规则，跳过整条失败规则的剩余谓词和动作。规则片段只在完整规则之间拼接，因此复用片段无需重写跳距，也不增加策略表大小。接口监听更新只修改匹配值，保留跳转元数据。

执行器将谓词求值与动作执行分开。子句使用未命中、歧义、确定命中三个状态，OR 取较强结果，取反不改变歧义；完成的 AND 子句只需累积一个歧义标志，失败立即结束整条规则，无需“已失败”状态。`must` 同样使用三态，确定的 must 覆盖此前不确定的 must，控制段结束时统一判断。程序计数器和少量 `volatile` 状态保留在包的执行上下文中，限制验证器对跨迭代状态的细化。编译器保证完整规则结构及出站参数合法性，内核继续检查策略、指令、域名索引和跳距边界。

用户态执行相同的三态逻辑和单跳距指令，供普通路由和目的地址谓词共用。跳距在完整规则内计算，AND 失败可恰好跳到当前 span 末尾，再由下一个 span 继续；零跳距和越界跳距返回错误。用户态只在实际执行相关谓词时查询域名位图或构造对应 LPM 键，同一次求值复用结果，纯端口和短路路径无需准备这些资源。

域名位图按独立的域名条件 ID 编号。重复域名条件（包括取反条件使用的同一正向集合）共用一个 ID；静态 LPM 集合也可跨程序复用。内核在一个包首次执行域名条件时取得域名映射快照，其余条件复用同一对位图；未找到映射也会记住，下一包重新查询。动态 `client()` 集合使用独立槽位，避免成员更新修改静态匹配条件；接口变更同步两端，用户态目的地址指令不会写入内核表。

UDP 路由缓存按源 IP 和源端口标识生命周期，24 字节键不含目的地址和策略。32 字节决策保留首次入口的出站、mark、must、捕获标志、接口、profile、MAC、DSCP、协议、no_sniff 和设备路由版本，命中时恢复这份身份。加上过期时间、定时器、锁和关闭标志，缓存值为 64 字节。PID 和进程名不由内核写入路由结果，进程谓词独立查询 socket cookie 映射。UDP 空闲超时、设备路由版本失效和用户态源绑定共同约束生命周期，结束后的报文按当前规则重新选路。

用户态 UDP endpoint 和 Anyfrom 回包 socket 各自保存空闲截止时间。活动在所属锁内延长截止时间，计时器首次建立后由到期回调检查最新值：提前触发时按剩余时间重新定时，真正到期时才删除对应实例并关闭 socket。持续活动无需逐包重设计时器；实例身份检查防止旧回调删除替代连接。

配置加载分为 `Prepare → Activate`：先在内存中完成编译和校验，重载时在旧控制面停止后继承域名记录、重算新条件位图，再发布内核表和绑定接口。规则表、域名位图与 LPM 资源必须属于同一份配置。

除自动接管的 DNS 53 外，任何未命中显式捕获或用户态路由要求的 direct 流量继续保持 eBPF 直通。正向域名条件缺少 DNS 映射时不补全流量捕获；内核只选候选连接，MITM 的实际主机名判断仍在用户态完成。DNS 仍尊重 `must` 和 API 直通前缀，不借用或替换无关 UDP 源会话的路由。

## 测试与性能测量

`control/kern/tests` 的 C 用例各自加载独立 maps，避免前一个用例的路由、域名或连通性状态掩盖错误。Go 的捕获与缓存回归直接检查内核返回值和交接状态，不能仅以最终出站名为 direct 证明内核直通。

内核 fixture 构造集中在 `routing_test_helpers_test.go`，功能回归在 `routing_flow_test.go`，计时循环在 `routing_flow_benchmark_test.go`。`make ebpf-lint` 同时检查本项目的内核 C 文件和路由头文件。

`BenchmarkRoutingFlow` 覆盖域名映射缺失、空位图、AND/OR 短路及普通顺序扫描。比较包处理性能时使用其 `bpf-ns/op` 指标；`ns/op` 包含批量调用开销。`BenchmarkUDPRoutingCache` 分开测冷路由与缓存命中。生成内核测试后可运行：

```sh
go test -c -tags dae_bpf_tests -o /tmp/dae-kernel.test ./control/kern/tests
sudo /tmp/dae-kernel.test -test.run '^$' -test.bench 'Benchmark(RoutingFlow|UDPRoutingCache)' -test.benchtime 30x -test.count 3
```

使用 `scripts/routing-program-metrics.go` 测量生产 ELF 的验证指令数、程序大小和加载时间，使用 `scripts/routing-map-memory.go` 测量内核实际 map 内存。两者均创建隔离 maps，不复用 daemon pins，也不挂载网络接口；使用当前 direnv 工具链编译后以 root 运行。加载成本、每包耗时和内存占用应分别测量。

用户态 `BenchmarkRoutingMatcher` 使用相同的有效指令比较执行器与输入准备开销，覆盖顺序端口、域名、混合 LPM 和 AND/OR 短路，同时报告分配次数：

```sh
go test ./control -run '^$' -bench '^BenchmarkRoutingMatcher$' -benchmem -benchtime=100ms -count=3
```

以下基准分别测量紧凑 Trie、节点可用性及延迟快照、DNS 接收存储和 UDP 空闲时间刷新。`BenchmarkTrieHasPrefix` 在构造完成后查询固定的 IPv4/IPv6 命中与未命中键；`BenchmarkDialerUsable` 和 `BenchmarkDialerSelectionSnapshot` 包含已填充的延迟历史，但不包含具体协议的 Session 查询。`BenchmarkDialerLatencyUpdateAndSnapshot` 在同一临界区记录一次检查并读取延迟，计入写入和快照的完整成本。两个 control 基准不执行网络 syscall，DNS 基准包含中继取消设置和独立应答构造：

```sh
go test ./pkg/trie -run '^$' -bench '^BenchmarkTrieHasPrefix$' -benchmem -cpu=1 -count=5
go test ./component/outbound/dialer -run '^$' -bench '^BenchmarkDialer(Usable|SelectionSnapshot)$' -benchmem -cpu=1,8,32 -count=5
go test ./component/outbound/dialer -run '^$' -bench '^BenchmarkDialerLatencyUpdateAndSnapshot$' -benchmem -cpu=1 -count=5
go test -tags=netgo,osusergo,trace,dae_splice ./control \
  -run '^$' -bench '^Benchmark(DNSUDPBuffer|UDPIdleRefresh)$' -benchmem -cpu=1 -count=5
```

HTTP scope 匹配的构建与查询成本可用 `BenchmarkHTTPScopes` 测量：

```sh
go test ./component/mitm -run '^$' -bench '^BenchmarkHTTPScopes$' -benchmem -benchtime=100ms -count=3
```

`BenchmarkDomainRegistry` 测量有名和无名活动续期、gzip 冷恢复的耗时及分配。内核写入回调为空操作，因此该基准只衡量用户态 Registry：

```sh
go test -tags=netgo,osusergo,trace,dae_splice ./control \
  -run '^$' -bench '^BenchmarkDomainRegistry$' -benchmem -benchtime=200ms -count=3
```

`BenchmarkDomainRegistryActivity` 使用包含共享 IP 和全零 bitmap 的 28,042 个 pair，分别测量同步入口的未知目标、期限未变、有效续期和到期前检查。`BenchmarkDomainRegistryContention` 的混合负载中四分之一同步观察延长期限，其余为期限未变或未知目标；用 `-cpu` 改变并发度，`p95-ns` 和 `p99-ns` 包含等待队列锁与 Registry 锁的时间。并发基准的分配量包含延迟采样开销，单次观察的分配量使用 Activity 基准：

```sh
go test -tags=netgo,osusergo,trace,dae_splice ./control \
  -run '^$' -bench '^BenchmarkDomainRegistryActivity$' -benchmem -benchtime=300ms -count=5
go test -tags=netgo,osusergo,trace,dae_splice ./control \
  -run '^$' -bench '^BenchmarkDomainRegistryContention$' -benchmem -benchtime=1024x -cpu=1,8,32 -count=3
```

`BenchmarkDomainRegistryCapacity` 使用一个内核槽位，分别测量已驻留 IP 续期和两个 IP 交替竞争槽位；固定操作数便于比较同一换入换出序列。`BenchmarkDomainRegistryFootprint` 测量上述历史数据在临时构造对象回收后的常驻 Go 堆，单独以 `-benchtime=1x` 运行，读取 `retained-bytes`、`retained-objects`：

```sh
go test -tags=netgo,osusergo,trace,dae_splice ./control \
  -run '^$' -bench '^BenchmarkDomainRegistryCapacity$' -benchmem -benchtime=1024x -count=3
go test -tags=netgo,osusergo,trace,dae_splice ./control \
  -run '^$' -bench '^BenchmarkDomainRegistryFootprint$' -benchtime=1x -count=5
```

`BenchmarkDomainActivityBatch` 使用同一历史数据，模拟 64 个连接对共享 IP 的重复 I/O；每 1,024 次观察应用一次批次，计时包含应用成本。`BenchmarkDomainActivityIOContention` 运行真实后台循环，并在计时结束前通过关闭应用最后一批；`p95-ns` / `p99-ns` 衡量前台观察回调耗时，状态实际可见时间还取决于批次应用。它是饱和负载，吞吐更高的实现也会产生更多排队竞争，不能直接把尾延迟当作固定流量下的网络延迟：

```sh
go test -tags=netgo,osusergo,trace,dae_splice ./control \
  -run '^$' -bench '^BenchmarkDomainActivityBatch$' -benchmem -benchtime=500ms -count=5
go test -tags=netgo,osusergo,trace,dae_splice ./control \
  -run '^$' -bench '^BenchmarkDomainActivityIOContention$' -benchmem -benchtime=1s -cpu=1,8,32 -count=3
```

`BenchmarkDomainActivityQueue` 为每个 worker 分配稳定的观察目标，分别测试多个独立目标和所有 worker 共用一个 IP。每 64 次回调采样一次耗时，以减少采样对短入队路径的干扰；后台工作和关闭时的最终批次应用均计入总耗时。评估队列竞争时，应同时测量同步入口和空批次成本：

```sh
go test -tags=netgo,osusergo,trace,dae_splice ./control \
  -run '^$' -bench '^BenchmarkDomainActivityQueue$' -benchmem -benchtime=1s -cpu=1,8,32 -count=3
```

`BenchmarkExchangeTCP` 通过 `net.Pipe` 完成一次 router 请求/响应，包括每查询 socket 和 worker 建立，衡量单次查询的管理成本。在包含 router 的工作区运行：

```sh
go test ../dae-plugin-dns-router -run '^$' -bench '^BenchmarkExchangeTCP$' \
  -benchmem -benchtime=300ms -count=5
```
