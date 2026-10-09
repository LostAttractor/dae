# Surge 脚本与 dae 的语义映射

本文定义 Surge 兼容层的架构边界和扩展设计。**标为“适配设计”的接口尚未实现**；可直接使用的能力以[支持范围](../configuration/surge-module-support.md)为准。

参考 Surge 官方的[脚本总览](https://manual.nssurge.com/scripting/overview.html)、[rule](https://manual.nssurge.com/scripting/rule.html)、[SCRIPT 规则](https://manual.nssurge.com/rules/script.html)、[event](https://manual.nssurge.com/scripting/event.html)、[JavaScript API](https://manual.nssurge.com/scripting/api.html)与[管理 API](https://manual.nssurge.com/tools/http-api.html)。

iOS 专属的 Shortcuts、系统唤醒、蜂窝信息及手机通知呈现统一作为平台边界，不分别列为 daemon 的待实现能力。Panel 等可以由 dae Web 页面承载的功能仍有独立适配价值。

## 兼容的单位是行为

每项能力需要同时明确输入来自哪里、何时执行、作用于哪个实例/请求、何时算完成，以及失败后的行为。只有函数同名或返回值形状相同，不足以说明兼容。

dae 的数据面与 Surge 有三个重要区别：

- 未命中显式捕获条件的 direct 流量在内核直通，JavaScript 看不到这些连接。脚本返回 DIRECT 后在用户态拨号，与内核直通不是同一种行为。
- dae 可以同时加载多个 Surge 实例；存储、模块、任务和通知按实例隔离，而系统网络、出站组和 daemon 生命周期属于宿主。
- dae 运行在 Linux 路由器或主机上。宿主的网卡、进程和桌面环境，不代表被代理手机的 Wi-Fi、应用进程或通知中心。

据此，能力分为三种实现方式：

| 方式 | 适用能力 | 约束 |
| --- | --- | --- |
| 直接复用运行时 | 存储、HTTP、定时器、编码、压缩、cron/generic 执行 | 保持返回值、截止时间、取消和资源限制 |
| 显式宿主适配 | event、`$network`、选择器、探测、指定出站、GeoIP/ASN | 补齐真实数据源与完成语义，并说明 Linux/实例作用域 |
| 保留不支持或限定范围 | 全局 rule、系统代理/增强模式、WebView/JIT | 不用相似功能伪造原语义 |

## 可实现范围与依赖

以下能力具有明确的 Linux 实现路径；先完成范围有限但语义完整的子集。表中描述的是实现设计，不改变当前支持状态。

### 可以独立补齐的运行时与内容处理

| 能力 | 可交付子集 | 实现依托与关键约束 |
| --- | --- | --- |
| 常用 crypto | `getRandomValues`、`randomUUID`、`subtle.digest` 的 SHA-1/256/384/512 | Go 标准库提供随机源和摘要算法，现有桥支持二进制值；需遵循 TypedArray 类型、随机长度上限、ArrayBuffer 返回值、Promise 和错误语义。HMAC/AES 等按算法继续扩展，不依赖 WebView |
| 本地脚本 debug 重读 | 每次调用读取已解析的本地 script-path | 复用资源读取和调用预算；每次执行持有独立源码快照，不能原地修改被并发调用共享的 Script.Source。HTTP notes 是独立的诊断展示能力 |
| 响应正文正则重写 | 在已捕获响应中执行 Surge 声明的替换 | 复用正文快照、解压、regexp2 和内存预算；明确替换次数、捕获组语法及超限回放。请求正文 jq/regex 还需处理 chunked、Expect 和消息分帧，不能简单套用响应路径 |
| `$surge.logbook` 日志适配 | 带实例、模块、脚本和 session 的结构化事件 | 复用日志入口；如果要求查询 Recent Events，再增加有界事件历史，不与通知历史混用 |

### 复用宿主能力即可实现，但需要扩展接口

| 能力 | 已有基础 | 必须补齐的部分 |
| --- | --- | --- |
| selector 查询与选择 | Selectors/Select、路径身份、原子持久化 | 实例到当前控制面的服务绑定、名称消歧和退役保护；`$surge` 与对应 `$httpAPI` 路径共享实现 |
| `$httpClient.insecure` / `policy` | 路由 HTTP 客户端、TLS transport、出站选择 | 请求级选项接口、按出站/TLS 配置隔离连接池；HTTP 拦截调用与后台调用都要支持，不能只处理标准 `http.Transport` 的一种调用来源 |
| event 与 `$network` | taskRunner、daemon ready 边界、HostNetworkMonitor、实例通知 | 先定义网络快照与生命周期投递，再接后台执行。启动/重载/通知可分别接入；network-changed 必须连同真实网络数据源实现 |
| fetch API 子集 | `$httpClient` 的异步桥、Promise 和正文预算 | 非流式 HTTP 请求、Headers/Request/Response、text/json/arrayBuffer、AbortSignal；先定义 bodyUsed、重复消费和 redirect 行为。取消一个 fetch 应取消对应请求，不能取消整个脚本 |
| 远程脚本定期刷新 | 分组资源缓存、依赖加载、原子文件发布 | 不可变源码版本、刷新调度及失败保留旧版；同一资源共享加载，明确不同声明更新间隔的调度。尊重 resource_cache 开关，保持模块依赖组的一致回退 |
| `retestGroup` | 有界连接检查器与健康快照 | 可等待的探测轮次、完成通知和协议族结果归并；这部分完成后才能提供 Surge 的结果回调 |

异步宿主调用还需要统一完成事件的来源与取消标识。当前运行时的异步事件通道用于 HTTP 完成并递减 pendingHTTP；接入探测、fetch 单请求取消等能力时，不能把所有新事件都计作一次 HTTP 完成，也不能让新入口绕过 20 个并发 HTTP 请求的共同上限。

### 需要独立数据源或呈现层的能力

- **GeoIP/ASN**：提供本地国家与 ASN 数据库后，可实现三个查询函数；关键依赖是数据库格式、更新和未知结果契约。
- **Panel**：可以放在 dae Web 页面中实现，复用 generic 执行，但需要单独的结果缓存与刷新入口；不是只增加一个脚本全局变量。
- **policy-descriptor**：可以实现明确的协议子集，但需要 Surge 描述符解析器和临时拨号资源管理，工作量高于选择已有 policy。
- **更完整的文本编码与 DOM**：可以逐项补齐脚本实际使用的 API；每项保留相同的内存、取消和解析限额。

实现顺序以依赖关系为准：运行时工具和 selector 适配可独立进行；宿主 HTTP 选项与异步取消接口是 fetch 的基础；网络快照是 network-changed 的基础；探测完成协议是 retestGroup 的基础。全局 rule 的捕获语义问题不阻塞这些能力。

## rule：请求选路中的同步谓词

### 原语义与当前边界

Surge 在规则链到达 `SCRIPT,name,policy` 时执行脚本，以 `$done({matched: boolean})` 决定是否采用该行的策略；同一请求的后续引用复用结果。默认不主动解析 DNS，`requires-resolve` 才要求解析。`SCRIPT` 不支持 `pre-matching`。

当前 dae 的 `[Rule]` 子集通过 [`ModuleRule`](../../../component/mitm/surge/module_rule.go) 转换成原生 routing，再通过插件 `Plan` 交给宿主。它不是逐个 HTTP 请求调用 JavaScript 的规则解释器。任意 JS 可以依赖存储、网络状态或异步请求，不能按一般情况编译为 eBPF，也不能靠一次预执行得到永久规则。

**当前保持 `type=rule` / `SCRIPT` 不支持。** 解析时给出警告并忽略，不把它转换成 cron/generic，也不额外捕获流量。已有原生规则能表达的域名、地址、端口等条件，直接使用 dae routing；环境变化后切换节点的需求，更适合 event 与选择器适配。

### 限定范围的适配设计

可实现的子集是“已经明确准入 HTTP/MITM 的请求内求值”，必须作为显式选择的作用域模式，而不是默认宣称全局 rule 兼容。该模式需要满足：

1. **捕获先于 JS，且独立决定。** 只使用模块已经声明的域名/IP 与对应端口；不得从 JS 推导兜底捕获，不得为读取 SNI/Host 扩大为全 TCP/UDP 或仅按端口捕获。缺少 DNS 域名映射时仍遵循普通 routing，脚本可能根本不运行。
2. **保持一条有序规则链。** 同一限定范围内混排的静态规则与 SCRIPT 应一起保留声明顺序。不能先把全部静态规则导出为全局 eBPF 规则，再在最后附加 SCRIPT；这样会改变首个匹配语义。该模式下这些规则只属于声明的请求作用域，与当前全局原生 `[Rule]` 子集有明确区别。
3. **保留 dae 路由优先级。** 模块规则在现有显式 routing 的相应位置求值；不能通过脚本绕过 must、改写已有 mark、取消 API 直通或扩大 DNAT 条件。匹配只选择支持的动作/出站，实际拨号仍由宿主负责。对已经捕获的请求选择 DIRECT，仍是该请求的用户态直连。
4. **结果属于当前求值。** 返回值只接受布尔 `matched`。同一模块内同一脚本在一次规则求值中执行一次；后续引用复用首次求值结果，不跨请求/连接缓存。首次求值需要 `requires-resolve` 时，用宿主解析器完成 DNS 后再运行；解析也计入总预算。重写目标后的重新选路是新的求值，不能沿用旧目标的结果。
5. **输入反映真实可见性。** hostname、目标端口与 URL 来自这次选路目标；sourceIP/sourcePort 保留原客户端元组。仅在确实处理 HTTP 时提供 URL/User-Agent；processPath 对远端客户端为 `null`，不能用 dae 进程路径冒充；listenPort 是实际接收端口，不能填目标端口。无法获得的字段按 Surge 契约给 `null`，协议不能只凭 443 端口猜测。
6. **前台等待结果。** 与其他脚本共享运行时和执行名额，但不进入后台任务队列，不由 `surge run` 手动替代。名额等待、解析、JS、HTTP 调用共享请求截止时间；异常、超时或非法结果记录失败并按未匹配继续规则链。已经发生的存储写入、HTTP 请求或宿主状态修改不会因判定失败而回滚。

仅增加 `matched` 字段还不足以实现这一子集：宿主必须先提供请求内有序选路接口和完整输入。实现范围也不包含任意 TCP/UDP 连接的 Surge rule。

捕获/选路的验收必须检查实际 eBPF 决定：目标捕获成立，SSH（如 `10.0.0.1:22`）、无关 HTTPS、缺少 DNS 映射的连接仍内核直通，原出站、mark、must 和 API 直通保持。只检查最终出站名称为 direct 不足以验收。

## event：宿主事件与后台执行分离

### 事件来源的适配设计

Surge 定义四种事件；“节点切换”“配置文件写入”“外网探测恢复”均不能自动当作其中任意一种事件。

| Surge 事件 | dae 的对应触发点 | 数据与边界 |
| --- | --- | --- |
| `engine-started` | daemon 初次启动成功：内核路由恢复、监听器 ready、DNS 路由和管理 handler 发布、初始网络快照就绪后 | 每次 daemon 启动一次；不把每个新建插件实例当作一次 engine 启动。无 `$event.data` |
| `profile-reloaded` | 配置重载的新控制面完成替换并进入 ready 后，由新实例接收 | 初始加载、候选准备、失败重载不触发；新增加的实例也接收本次 reload。运行时 selector/store 文件变化及单纯挂起/恢复不算 profile reload。无 `$event.data` |
| `network-changed` | daemon 所在宿主网络快照发生真实变化 | 接口、地址、默认路由和策略路由变化，包括断网；DNS 配置变化需要独立数据源。初始快照是基线。无 `$event.data`，脚本读取同次事件的 `$network` 快照 |
| `notification` | 当前 Surge 实例接受一条 `$notification.post` 通知后 | `$event.data` 包含 title/subtitle/body；有 identifier、script-options 时才带入。范围是实例通知，不是所有 logrus 日志、其他实例或 Linux 桌面通知 |

[`Runtime.Publish`](../../../control/runtime.go) 与 [`Host.Start`](../../../component/mitm/host.go) 负责资源激活，未变化的实例复用已有 Worker；它们都不是 `engine-started` 的正确发射点。初次与重载的成功边界由 [`internal/daemon`](../../../internal/daemon) 持有，重载可能不创建新控制面。事件应从这些提交点传递，并在 Worker 尚未就绪时暂存投递。脚本执行不能反过来阻塞提交点。

提交事件需要携带初次启动、配置重载、挂起/恢复等来源，不能仅凭新建了 ControlPlane 判断事件类型。网络快照就绪表示完成一次有界采集，采集失败可报告未知字段；不要求外网连通，也不因脚本等待网络而延迟 daemon 启动。

[`HostNetworkMonitor`](../../../component/network/network_monitor.go) 已有去抖、快照和 revision，可以复用；但 `ConnectivityChanged` 会过滤失去连通性的状态，不能直接作为 network-changed 的判断。应比较完整快照，DNS/Wi-Fi 元数据变化也进入同一快照版本。监控回调只投递快照，不执行 JS 或等待共享名额。

### 执行器的适配设计

event 可以复用 [`taskRunner`](../../../component/mitm/surge/tasks.go) 的 VM、HTTP 客户端、存储、截止时间、执行名额、通知、指标和停止清理。需要增加的是触发输入和事件待处理策略：

- 正常触发注入 `$event.name`，按事件提供 data，不注入 `$trigger`；`$done()` 的结果忽略。
- CLI/API 手动调用使用同一 `list/run` 入口，注入 `$event.name = "manually"`、`$trigger = "http-api"`，不伪造一次网络变化或 reload。当前入口仍只支持 cron/generic。
- 同一脚本串行执行。手动重叠仍返回冲突；network-changed 在忙碌期间保留一个最新快照，完成后再处理，不能像 cron 一样直接丢掉最后一次网络状态。
- notification 按接收脚本使用有界 FIFO，设计容量为 50 条；满时丢弃新入队事件并累计 dropped，不删除原通知历史。启动/重载事件按代际只投递一次。状态应区分 queued、coalesced、dropped 与执行失败，不把这些全部混成 cron 的 skipped。
- 事件预算从入队起计算，包含队列等待和共享名额等待；合并的网络事件使用最新事件的快照及入队时间。执行异常不阻塞其他脚本，不自动重放事件。
- 挂接 `notification` 的脚本禁止调用 `$notification.post`，包含其手动执行；运行时抛出异常，避免通知递归。这与 Surge 的限制一致。
- 重载/停止先关闭旧代际的事件入口、取消订阅，再取消并等待执行清理。旧队列不转交新实例；新实例只接受成功发布后的事件。

宿主拥有事件的产生和代际，实例拥有事件的消费。当前网络监控 `Register` 没有取消订阅接口，接入实例生命周期前需要可注销的订阅或宿主统一分发，不能每次重载都永久追加一个旧实例回调。

## `$network`：宿主网络，不是被代理设备网络

当前未注入 `$network`。适配设计使用由宿主提供的只读快照，每次调用固定一个版本；network-changed 直接携带触发时的版本，避免读到另一次变化。

| 字段 | 数据源与缺失语义 |
| --- | --- |
| `v4.primaryAddress` / `primaryInterface` / `primaryRouter` | 宿主默认路由及其实际首选源地址/网关；不是 dae 内部 netns 的虚拟地址，也不是某个出站节点的地址 |
| `v6.primaryAddress` / `primaryInterface` | 同上，独立选择 IPv6；不能从 IPv4 主接口推断 |
| `dns` | 宿主实际配置的系统 DNS 服务器列表；不是 dae DNS 路由图的全部上游。系统只提供 stub 地址时如实报告，不猜测背后的服务器 |
| `wifi.ssid` / `bssid` | 只有宿主自身使用 Wi-Fi 且 Linux 数据源可获取时填写；LAN 客户端的 MAC 不能用于猜测其 SSID |

标量不可知时为 `null`，列表无可用内容时为 `[]`，保留 wifi/v4/v6 对象以便属性访问。多 WAN、ECMP 或策略路由没有唯一 primary 时相关标量为 `null`，不任取第一张网卡。未知、未连接和采集失败的区别在宿主诊断中保留。

现有网络快照记录候选默认路由接口和指纹，但没有结构化 primaryRouter、系统 DNS、SSID/BSSID；其中的源地址是候选可用地址，不等于某次 Linux 路由选择的首选源地址。因此不能把现有结构直接序列化成 `$network` 并宣称完整兼容。

## `$surge` 与 `$httpAPI`：以宿主服务适配

### 方法映射

当前两个全局均未提供。可以适配的方法和不能直接对应的方法如下：

| 方法 | 适配设计 |
| --- | --- |
| `setSelectGroupPolicy(group, policy)` | 仅映射到真正的 dae selector；通过宿主现有 Select 事务更新并持久化。Surge 使用名称，dae 使用路径 node_id；只有名称唯一对应组内一条路径时才接受，歧义、非成员、组不存在或提交失败返回 false |
| `selectGroupDetails()` | 只返回可无歧义表示为 Surge 名称的 selector，生成 groups/decisions。重名路径或未选择的组不能编造一个决定；这些组应明确报告适配受限，而不是随意选第一个节点 |
| `retestGroup(group, callback)` | 复用现有检查器，但必须增加“本轮检查完成”的可取消等待与版本标识，再返回 availablePolicyNames。可合并同一轮未完成探测，不能把上一轮健康状态当作本轮结果 |
| `logbook(content)` | 可映射到携带实例/模块/脚本/session 的有界结构化事件；dae 日志与 Surge Recent Events UI 仍有展示差异，不能转成 `$notification.post` |
| `setOutboundMode(direct/global-proxy/rule)` | dae 没有该全局开关；修改 fallback 不会覆盖前面的显式规则，也不能模拟 Surge 全局模式。保持不支持 |
| `setHTTPCaptureEnabled` | Surge 的 HTTP 流量记录开关不等于 dae MITM 捕获范围或设备开关；保持不支持 |
| `setRewriteEnabled` | 需要独立定义实例级重写开关以及生效中的请求快照；停止插件、停用 MITM 或清空模块都不是等价操作。当前不支持 |
| `setEnhancedModeEnabled` | 没有一一对应的宿主能力；不映射到卸载 eBPF、修改网卡或切换 Linux 路由 |

[`ControlPlane.Select`](../../../control/api_state.go) 已有运行中选择与持久化的一致更新。适配器应直接复用此事务，不维护第二套 selector 状态。名字映射必须覆盖全部可选路径；无法映射的组在兼容查询中省略并记录原因，dae 原生 API 仍按 node_id 完整呈现。

当前 [`ProbeResponse`](../../../api/probe.go) 仅确认检查已受理或合并，`Probe` 不等待结果；健康信息也可能按 TCP/UDP、IPv4/IPv6 分别变化。retestGroup 的单一 available 列表需要明确采用组配置的测试语义，不能简单把任一网络族曾经成功视为本轮成功。

### `$httpAPI` 的入口契约

适配设计是一个进程内的 Surge 路径翻译层，调用与 dae 管理 API 相同的宿主服务。它不向本机管理监听器发起 HTTP，也不依赖 api_port、Bearer key、来源 IP 或路由旁路。

- 每条支持路径分别转换输入、输出和完成语义；GET 的 body 转查询参数等行为仍按 Surge 契约处理。
- selector 查询/选择可以复用上述适配。组测试路径必须等真实结果；dae 的异步受理 JSON 不能直接作为 Surge 的测试结果返回。
- `/v1/outbound`、system_proxy、enhanced_mode、全局 capture、全局模块启停等没有等价服务的路径，返回明确的“不支持”错误，不能响应成功空对象。
- `/v1/profiles/reload` 不能在旧实例内同步等整个重载完成：重载会等待该实例退出，容易形成自等待。需要 daemon 级异步控制命令契约；在完成此设计前保持不支持。
- 请求历史、DNS 缓存、设备和配置查询也需逐项解释作用域；不能将 dae 的状态快照直接包装成 Surge 的完整请求历史或可切换 profile 列表。
- 宿主服务引用绑定实例的控制面代际。退役后禁止旧脚本继续修改新控制面；异步结果通过原 VM 的回调队列交付，取消后不再回调。

仅实现 `$surge` 的少数方法不意味着整个 `$httpAPI` 路径集合兼容。全局尚未提供时保持缺失；提供部分模块后，已声明但不可用的方法需要明确失败，不能假装执行成功。

## `$httpClient` 剩余选项

当前 `policy`、`policy-descriptor`、`insecure` 没有传入宿主；请求仍使用原有路由与 TLS 校验。它们需要以下适配，不能只在 JS 端增加字段：

| 选项 | 适配设计 |
| --- | --- |
| `policy` | 由宿主解析已有出站/策略名称，产生仅作用于该脚本 HTTP 请求的选路要求；DIRECT/REJECT 对应直连/拒绝该主动请求，其他名称必须可无歧义解析。未知名称返回 HTTP 回调错误，不能退回默认路由 |
| `policy-descriptor` | 需要 Surge 临时策略描述符的解析器、协议能力映射及调用级资源所有权。dae 的节点 URI 不是 Surge descriptor；不能直接字符串转发。支持时按 Surge 优先于 policy，描述符无效也不能悄悄使用 policy |
| `insecure` | 可以实现为请求级 TLS 配置，只影响脚本主动访问的 HTTPS，不影响透明 MITM 入站/出站校验。transport 的复用键须包含 TLS 与出站选择，不能修改共享 transport 或套用整个实例的跳过验证 |

宿主必须保留内部 socket mark、防循环标记、客户端身份、策略资源生命周期以及连接统计；重定向后的每次拨号也经过同一策略处理。未指定 policy 时保持当前路由行为；显式 policy 与 dae 强制规则存在冲突时应明确失败，而不是静默忽略一方。

这些是脚本主动生成的请求，DIRECT 在这里使用用户态拨号是合理语义；不能据此将普通被代理客户端的内核 direct 流量也引入用户态。

## 其他 API 与能力

| 能力 | 当前状态、适配方式与边界 |
| --- | --- |
| `$utils.geoip/ipasn/ipaso` | 未实现。需要可查询的本地国家/ASN/组织数据源和只读索引；dae 现有 geodata 是代码到地址集合的规则库，可能含 private、反向或重叠集合，不是 IP 到 ISO 国家/ASN 的完整数据库。不能取任意匹配标签当国家。查询不隐式联网；ASN 未知按官方返回 null，其他函数的未知值需明确契约 |
| fetch / Headers / Request / Response / AbortController | 未实现。可通过已有受限 HTTP 桥实现，但必须定义 Promise、取消、头部、重定向、正文消费和 streaming 行为；与 `$httpClient` 共用单次调用的 HTTP 并发、CookieJar、截止时间与内存预算，不能另开不受限客户端 |
| crypto | 未实现。需逐项实现 getRandomValues、digest 等 API；随机数使用系统密码学随机源，不能用 Math.random。SubtleCrypto 的算法、密钥格式、Promise 和错误类型分别声明，不能因有几个哈希函数而声称完整 WebCrypto |
| WebView/JSC/JIT | 当前均使用 QuickJS。Web API 补齐与执行引擎是两个问题；不模拟浏览器进程、页面网络加载、JIT 或 Surge 的两类引擎并行名额 |
| `$environment` | 当前报告宿主 Linux、locale、硬件和 dae 构建信息；surge-version/build 为空。宿主 locale 不等于 Surge UI 语言，不能伪造 iOS/macOS 来让平台判断通过 |
| `$notification` options | 当前只保留标题/副标题/正文，选项忽略。可扩展有界元数据供 Web 消费端展示/回传；通知动作由呈现端实现，daemon 不执行用户交互动作 |
| [Panel](https://manual.nssurge.com/tools/panel.html) | 当前无 `[Panel]` 和结果通道，generic 手动运行忽略返回值。面板适配需要独立 PanelResult、缓存、失败保留旧值、点击/浏览时刷新，并注入 `$input` 与 `$trigger=button/auto-interval`。官方 update-interval 是打开界面时检查是否到期，不等于全天候 cron；SF Symbols 也需呈现端替代 |
| editor / 任意文本 evaluate | 当前无这些启动通道。已有命名脚本的 daemon run 是实际可用能力；临时文本、mock 输入、结果返回、存储命名空间需独立契约 |
| script-update-interval | 当前忽略，脚本随模块准备/重载加载。适配时复用资源缓存的校验与原子发布，以不可变源码版本切换；已有调用使用旧快照。script 刷新不应触发 profile-reloaded、重建 cron 定时器或清空 store/通知 |
| debug | 当前忽略。官方包括每次运行重读本地脚本及 HTTP 请求 notes；本地重读可以独立实现，notes 依赖请求诊断载体。预算从接受调用开始，不因重读文件延长，读取失败须明确报告 |
| img-url | 当前忽略；可作为有界呈现元数据交给 Web 页面，图片加载不属于脚本执行语义 |
| system/requirement/条件声明 | 当前缺失。平台条件只能基于真实 dae 能力和宿主信息求值；不能用虚构 Surge 版本让条件通过。不认识的条件不能当作 true 来宣称支持条件执行 |
| Header/Body Rewrite、规则集和其他规则类型 | 纯内容变换可在现有处理链扩展；规则集需保留组合规则的完整过滤条件并进行组加载校验。涉及 URL/进程/来源的规则仍受内核信息可见性约束，不能通过扩大捕获实现 |
| DNS | 已有地址/TTL 结果和普通/加密上游接口，但 Linux system/syslib 仍是宿主解析模型。脚本重定向 DNS 与恢复内核 domain 映射是两个环节，不能以脚本看到了域名为由扩大后续连接捕获 |
| full-header-mode / TextDecoder / DOM / 资源限额 | 当前支持范围见配置文档。原始跨字段头顺序、大小写已被 Go HTTP 栈丢失，不能在 JS 层恢复；UTF-8 工具与有限 DOM 也不意味着完整浏览器。dae 的内存/正文/存储上限是宿主契约，不伪装成 Surge Mac 限额 |

## 宿主与运行时的接口边界

适配按真实能力接入，避免向脚本层暴露整个 ControlPlane：

- **运行时**负责 JS 值转换、完成协议、回调、资源预算和每次调用的隔离。
- **后台执行器**负责 cron/generic 及 event 适配后的准入、排队、执行记录与停止清理；rule 属于请求选路链。
- **宿主网络服务**提供带版本的快照与可取消事件订阅；不以一次 HTTP 请求推断整个网络状态。
- **宿主管理服务**负责 selector、探测、出站和持久化事务；`$surge` 与 `$httpAPI` 共享同一实现，不形成两套管理状态。
- **宿主 HTTP 服务**负责请求级出站/TLS 选项、重定向拨号和资源生命周期；运行时不能修改全局 transport。
- **daemon 提交点**负责启动、重载和停止的代际边界；模块加载、缓存回退和构造函数都不产生系统事件。

完成协议按调用用途区分：HTTP 修改、DNSResult、RuleResult、无返回值的后台任务，以及面板的 PanelResult。rule 的 `$request` 使用独立输入结构，不能复用只有 URL/headers/body 的 HTTP Message；generic 面板调用也不能继续按普通手动调用丢弃 `$done` 结果。

接口是否可用取决于上述服务是否具备完整行为。扩展状态必须能区分缺少宿主能力、输入无法映射、任务被合并/丢弃和执行失败，而不是统一返回成功空值。
