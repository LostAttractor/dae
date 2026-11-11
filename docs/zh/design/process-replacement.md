# 进程热替换

进程替换是**带故障防护的进程重启**，不是全局原子或无损交接。Block 前失败保留旧服务；Block 后旧连接关闭不可回滚，失败后保持 fail-closed，直到成功恢复。多 hook 的逐步安装与撤旧是有防护的中间态，不是一个全局原子事务。

`reload` 是统一入口。通过本地 Unix socket 发起的 CLI 请求带上自己的 PID；daemon 校验 `SO_PEERCRED`，打开 `/proc/<peer>/exe` 并按完整文件内容比较。内容相同执行配置热重载，内容不同执行进程替换，`reload --replace` 强制替换。版本标签不参与判断。未指定 executable PID 的 API 请求只重载配置，TCP API 不接受进程替换。使用方式见[重载与暂停（英文）](../../en/user-guide/reload-and-suspend.md#process-replacement)。

## 进程与资源所有权

`dae run` 直接运行业务，正常运行只有一个 dae 业务进程，没有常驻 supervisor 或主进程/worker 拆分。替换通过关闭旧业务后同 PID exec 已打开的目标 ELF 完成；PID 和 `/proc/<pid>/stat` 的 starttime 不变，但旧 Go heap、goroutine 和用户态连接全部消失。exec 不运行旧映像的 defer，因此 Runtime 关闭、持久化 flush、API 排空和插件子进程回收必须在 exec 前显式完成。

短生命周期预检进程运行目标 ELF 的配置解析器、`plugin.Preflight` 和内核能力检查，不构造完整 Runtime。daemon 自身持有实例锁并设置 Linux subreaper，以便在插件正常关闭和已有 `exec.Cmd.Wait` 完成后检查残余后代。预检进程只借用同一打开文件描述，不能主动解锁。预检使用独立的 `replacement_pid_map` 临时豁免，正常路径先撤销再 `Wait`；撤销失败时不能回收并释放仍被豁免的 PID。daemon 或候选异常退出时，内核退出 hook 也会清除临时豁免，防止 PID 复用。残余存活后代须有界终止、回收并使替换失败，不能带入新映像。

固定的 `dae0`、`dae0peer`、`daens`、实例锁及未变更的 API/observability 监听器通过 FD 跨 exec 保留身份，新运行时在数据面提交和最终就绪检查均成功前只借用固定对象，不拥有删除权。监听 FD 不等于 HTTP 服务连续可用：旧 Go server 关闭后、新 server 恢复前，请求可能超时或断连。

普通 restart 复用兼容的 canonical pins，保留固定 ABI、设备 epoch、fallback 发行序号及失败接管保护；同进程配置 reload 共享 Runtime maps。只有进程替换或遗留 guard 恢复创建私有业务 maps，不复用前任业务 pins，因而不要求两代私有业务 map 布局兼容。成功提交显式发布自身 canonical pins，正常运行继续持久化；私有初始化不等于业务 maps 永不 pin。

阻断防护以 `/sys/fs/bpf/dae/guards/<link-id>/` 下的 bundle 持有入口 link、两张 UDP timer maps（`udp_conn_state_map`、`udp_routing_cache_map`）、该代 socket 身份 writer links、exit hook 和 `daemon_identity_map`。TCP 没有 timer。内核 UDP timer 需要 map FD 或 map pin，仅有 link→program→map 引用不足以继续回收过期记录。撤除旧 guard 时必须实际释放 canonical 与 guard 两处引用；旧身份 writer 不能通过同名 pin 的 `Update` 被新程序替换。guard maps 不是后继运行时的业务状态源。

共享网络对象的 BPF link 通过 FD 保留。导出快照先将 Runtime 的原始 links 标记为冻结状态再借用（避免在跨 exec 复制与校验期间长期持有互斥锁），为每个附件复制一份 FD 并将其所有权交给替换流程；阻塞提交或释放快照时解除冻结，未移交的 FD 在释放快照时关闭。

内部 handoff 协议版本为 4。描述包含原 PID、事务期限、交割起点、operation、FD 角色、link 身份及固定拓扑，在 API 排空和 Block 前写入最多 64 KiB 的 sealed memfd；编码、超限或封印失败不影响旧服务。恢复时校验大小、封印、版本、同 PID、原期限、FD 唯一性/类型、实例锁、namespace 和 link 身份；非法内部入口直接拒绝，不降级为普通启动。环境变量只定位继承 FD，不能单独授权。exec 前以 `CLOSE_RANGE_CLOEXEC` 保护全部非标准 FD，只对白名单清除 CLOEXEC；新映像接收后立即恢复 CLOEXEC，避免泄漏给插件。没有前任 pidfd 等待、候选收养或跨进程提交授权消息。

LAN/WAN 捕获接口列表及其解析出的实际 ifindex/角色集合必须相同，包括 `auto` 和通配符的变化；阻断前、安装和提交时检查完整覆盖。固定网络拓扑或服务启动条件变化需要显式重启。

## 入口状态

`exited_map` 使用四个状态，数值统一定义在 `routing_abi.h` 并生成 Go 常量：

| 状态 | 行为 |
| --- | --- |
| `ONLINE = 0` | 正常分类与捕获 |
| `OFFLINE = 1` | 异常退出，按 `unexpected_exit_behavior` 的 bypass/block 策略处理 |
| `STARTING = 2` | 普通启动接管期间，保留未就绪时的保护 |
| `STOPPING = 3` | 主动阻断，只允许可证明的明确直连、必要控制协议及受限进程身份豁免 |

退出 tracepoint 注销真实退出的 daemon 身份，但不覆盖 `STOPPING`。普通停止先设置 `OFFLINE`，在关闭业务后卸载入口；进程替换则先设置 `STOPPING`，保留防护直到新运行时就绪。Block 拒绝 proxy、DNS/MITM capture、fallback、无法确认的报文和非首分片，只放行可证明的 explicit direct、必要控制协议，以及正式 daemon 和临时预检 PID 的受限豁免。合法 ARP、ICMP 等非捕获控制协议不等于报文解析失败。普通异常退出仍按 `unexpected_exit_behavior` 的 bypass/block 策略处理；panic 跳过正常清理，不全局改成 fail-closed。

明确直连证据存入 `routing_result` 偏移 31 的 byte 和 `tcp_flow_state` 偏移 20 的 u32 `explicit_direct`，结构大小仍为 40/24 字节。零表示 unknown，旧 padding 为零的记录不能在 `STOPPING` 中证明 direct。fallback 0 只表示不受代次撤销，不等于 explicit direct；1 始终无效，其余为唯一发行令牌，没有 `PERMANENT` 特殊 token，持久发行序号不复用。

## 交接状态

1. **轻量预检**：旧 daemon 启动目标 ELF，沿用自身环境、工作目录和有效启动参数。私有 socket、父进程身份、继承锁和原期限通过校验后，目标执行非交互配置解析、插件 Preflight 和 kernel checks；父进程死亡或通道断开会取消预检。此阶段不读取 settings/Registry，不下载订阅或模块、不执行脚本 `Warm`，不构建完整 Runtime、不发布客户端集合。旧数据面和 API 继续服务，新的配置操作返回 409。预检成功后先撤销 PID 豁免、回收临时进程，再导出并冻结 kernel links。
2. **交割准备与 API 排空**：保存所需监听器和网络对象 FD，记录交割阶段起点并编码、封印完整继承描述，成功后才暂停本地与管理 API 的业务请求，按原期限等待在途请求结束；仍由旧 server 接收的管理读写返回 503。本地 operation 路由在 server 存活时仍可查询，但不能保证整个切换期可用。排空时取消会直接重新开放原 handler。写入 `STOPPING` 前再次检查取消；若失败，只清理本次新增的 guard，解冻后按当前接口补挂或撤除 hook。
3. **阻断与关闭**：将捕获入口 link、UDP timer maps 及身份 hooks/maps 成组 pin 到 `/sys/fs/bpf/dae/guards/<link-id>/`，设置 `STOPPING` 并放弃固定对象删除权。此处是不可逆边界。旧 daemon 启动由 Startup 持有的 15 秒停机宽限，调用正常的 `Runtime.Close()`：关闭 UDP 工作、监听器及 backlog，为旧 TCP 设置 abortive close，等待连接、任务和插件关闭并完成 flush。保留旧回程供 RST 使用，直到旧业务关闭；关闭错误不能忽略。
4. **同 PID exec 与重建**：完成子进程回收；停止信号接收器并汇合、检查已排队的真实停止信号，复核原期限，再 exec 已打开的目标 ELF。新映像重建 Go 运行时，校验并借用继承资源，首次读取最终 settings，再加载订阅、模块和完整私有业务 BPF，构造正式插件实例、执行 `Warm`，在 `PrepareKernel` 中首次恢复 DomainRegistry 并完成私有投影，然后建立透明监听器。原三分钟事务期限不因 exec 重置。重绑前先释放不再使用的 wildcard 管理监听器；管理端口与 loopback 观测端口可在替换时互换，但不会跨监听地址复用旧 FD。
5. **本地提交的安装阶段**：`CommitReplacement` 先准备当前 settings 对应的 client ipset/nft 导出，再以 checked update 更新 socket lookup、peer 侧 DNS 回复出口和两侧入口的 links，再将新 host TCX links 通过 `AfterLink` 挂在旧 guard 后面并 pin。旧 host link 的额外 FD 必须在撤旧 guard 前关闭，否则 unpin 后仍会保活旧入口。新入口也保持 `STOPPING`；`SK_LOOKUP` 在本运行时进入 `ONLINE` 前拒绝交付，包括已越过旧入口的迟到包。
6. **数据面生效与就绪通知**：同一次 `CommitReplacement` 在安装完成后发布已准备的 client ipset/nft 导出，通过 `Host.Start` 启动插件后台 worker、启用 Registry 持久化；再次检查取消/期限及完整入口覆盖后先创建 `/sys/fs/bpf/dae/replacement_pending`，再发布自身 canonical pins；无捕获接口也有恢复标记。随后逐步撤旧 guard 和旧身份 hooks，使新运行时进入 `ONLINE`。`ONLINE` 是本运行时的数据面生效点，不代表所有 hook 和共享导出的原子提交。新代自身 guard bundles、`privatePins` 和 `preparing` 接口冻结仍保留，Commit 不提前放弃恢复保护或取得 canonical pins 的删除权。Commit 成功后开放 API/observability；`ConfirmReady` 在接口仍冻结时校验全部 hook 及 guard 身份，在原期限内发送 READY；成功后才取得所有权并移除恢复标记，清理冗余临时 bundles、解除接口冻结并取得 canonical pins 的正常删除权，同时取得固定 netns 对象和 Unix API 的删除权，完成原 operation。READY 是就绪通知，不是全局原子提交回执；晚期 READY 失败或取消仍可使新运行时重新进入 `STOPPING` 并终止，保留恢复标记和防护，不清除借用状态。这是已生效数据面的失败处置，不是恢复旧进程，也不能忽略 READY 失败。API handler 在每次启动中只发布一次，并在继承监听器激活前准备完成。

通过 sealed exec state 校验恢复时，`Run` 不重复执行目标 ELF 已通过的 `CheckKernelFeatures`，但仍对重新加载的配置执行插件 Configure/Preflight 并实际加载、验证业务 BPF；普通冷启动和失败后重启仍完整检查，settings/Registry 仍仅在旧写者结束后的正式启动中读取，不引入内核能力缓存结构或配置。

旧 WAN socket-owner hooks 需要临时跨 exec 保活：旧 guard 读取旧 `socket_owner_map`，同 PID 并不使新 socket 自动拥有旧 map 中的身份。临时旧 hooks 与新运行时的 `pidLinks` 分开持有，各自填充本代 socket-local storage；正式身份通过 `daemon_identity_map` 显式注册、注销。新的正式启动也向旧 guard 重新注册自己的真实身份，使恢复时的 daemon socket 可通过旧入口，而不豁免其他进程。撤旧 guard 后才关闭旧 writer/exit hooks 的引用，不共享新旧业务 maps，也不扩大 mark 豁免。`KernelProcessID` 通过短生命周期、无 maps 的 BPF probe 取得与 socket-owner/退出 hook 相同口径的 kernel TGID，用于业务 `PARAM` 和预检 hello，避免 PID namespace 中 `os.Getpid()` 与内核身份错配；socket 热路径不增加额外 lookup。

Block 前失败会清理预检进程并保留旧服务；若已暂停 API，则重新开放原 handler，共享导出保持原样。Block 后失败不恢复已经关闭的旧业务或旧 API，保留 pinned guard 和已发布集合。配置内端口重叠在预检阶段拒绝。坏 settings、外部进程占用端口、订阅/模块下载、脚本 `Warm` 及真实业务 BPF 加载错误都可能在 Block 后才出现；轻量预检成功不等于完整启动必成功。完整初始化位于 Block 窗口，不承诺无损切换或低于某个时长阈值。

客户端集合发布部分成功或后续激活失败时，保留已应用部分并清理临时备份，不回滚共享导出。成功接管后的备份清理、已提交运行时的冗余 guard-bundle 清理和无引用旧 UDP timer pins 清理失败只记录警告，不因这类清理错误撤销已生效服务。状态或拓扑校验错误、提交完成前的旧 guard 撤除错误仍是 fatal，不能作为清理警告忽略。普通配置 reload 的导出事务回滚语义不变。防护只 pin 真正捕获流量的 LAN ingress 与 WAN egress；同一 hook 上的回程程序不能算作替代入口。进程退出、FD 关闭不会自动移除这些链接；下一次正常启动准备好完整数据路径后才移除遗留防护。恢复先验证所有旧 hook 的覆盖，再持久化新入口；撤旧之前失败会撤销本轮新增 pin，不能扩大下一次恢复必须覆盖的接口集合。开始撤旧后，新防护必须保留。如果新的接口集合不能覆盖旧的受管 hook，拒绝解除防护并要求恢复原接口配置。失败不会静默降级成 restart 或直连。冷启动恢复期间旧 guard 仍阻断普通捕获流量；已重新注册的正式 daemon 可通过受限身份豁免取得启动资源，这不保证上游可达，也不向其他进程开放通路。

阻断期间捕获流量直接丢弃，不承诺排队或零丢包。已有明确直连在仅有旧 guard、且该 guard 仍持有有效证据时可能继续由内核处理；新旧 guard 使用私有 maps，直连证据不跨代共享。重叠期间新 guard 可以因缺少本代证据而阻断旧 guard 放行的流量，后置失败可能使暂停持续到成功恢复。因此不承诺直连不中断或暂停时长。成功替换后采用与普通 restart 相同的 TCP 语义，不保留永久的 unknown-ACK 拒绝模式：在 `ONLINE` 下，无 handoff、真实 proxy socket 或已保存属性的非 SYN 包归入 native。旧客户端可能未收到 RST，因此不能承诺成功后所有旧未知 ACK 永不放行。非首分片仅在 `STOPPING` 期间统一阻断；恢复 `ONLINE` 后继续由首分片执行路由检查，允许直连报文重组，仍拒绝无法代理的首分片。RST 在本机关闭时发出，不保证端到端送达。

TCP 从短期路由 handoff 转交给真实 accepted socket；SOCKHASH 只是可选索引加速，容量满或登记失败时回退到 proxy netns socket lookup，不把索引失败当作拒绝连接。`tcp_flow_map` 是 24 字节值的 LRU，仅保存 native 的路由 epoch、mark、fallback、SYN 序号及 explicit-direct 属性，不是代理连接准入 HASH 或 FIN/ACK 状态机，也没有 TCP timer takeover。淘汰会丢失保存的属性，不等于关闭真实连接；代理连接生命周期由 socket 和现有用户态关闭流程负责。

旧映像的用户态连接和内存缓存不迁移。私有 map 也不迁移连接状态。持久化配置、选择器和客户端成员在新映像中恢复；指标随新映像重新计数。进程替换不等同于保持连接的配置 reload。

## 持久化恢复

预检不读取 settings，也不对 DomainRegistry 执行 `Restore` 或启用持久化；不会读取或修复旧运行时正在写入的 baseline/journal，不会 rename 完整 `.tmp` 或删除旧格式文件。预检没有客户 DNS 或插件后台 worker，不需要合并预热快照。

首次 Registry 恢复发生在旧 Runtime 已正常关闭、同 PID exec 后的 `PrepareKernel` 中，新 host 捕获入口此时尚未安装。旧 Runtime 正常关闭仍会应用待处理活动并写入最后的续期；旧写者必须先关闭并完成 flush，新写者才读取最终状态并启用持久化，始终保持单写者约束。新运行时在 control-plane lifecycle 锁保护下校验最终 baseline、重放 journal、回收过期记录，并按新规则建立私有内核投影；提交时再准备客户端集合导出、安装新附件并发布集合，随后启动插件后台 worker、启用持久化并解除 guard。健康文件沿用最终有效 epoch 和追加位置，不因进程替换强制重建 baseline；缺失或损坏文件及写入失败仍遵循正常恢复、重建语义，不承诺磁盘损坏时无损恢复。

投影不完整时不能开放流量。未 Restore 的新运行时关闭不会写共享文件；Restore 后、启用持久化之前失败也不执行关闭写回。持久化已经启用但解除 guard 失败时，旧写者已关闭，新运行时按正常单写者关闭语义落盘。普通同进程 reload 继续接管内存证据和持久化文件。

运行时设置不与 Registry 共用延迟读取点：旧 API 最终排空并关闭、完成 exec 后，新启动流程首次调用一次 `settings.Open`，以该快照准备出站、私有路由和后续导出，不执行二次读取。API 屏障只冻结 daemon 的写者，不锁住外部文件编辑器；恢复服务后，设置 watcher 继续按正常事件循环处理外部变更。

Surge persistent store 在首次实际 read/write 时读取内容，构造、`Warm`、不访问 store 的脚本和 `Close` 不读取内容，也不创建存储目录、JSON 或 `.lock`。绝对路径和 symlink 规范化仍可能访问文件系统元数据；普通访问的刷新、写前跨进程锁与原子保存不变，首次 write 也先加载最新快照再修改单键。坏 JSON、FIFO 等错误延至实际 read 报错或 write 返回 false，失败不覆盖坏文件，修复后可重试。这不是所有缓存、证书或插件存储的统一延迟恢复协议；其他插件保持各自的准备与激活契约。

## UDP 方向与接收权

UDP 保留 `udp_conn_state_map`、`udp_inbound_pending_map`、binding、routing cache 及 timer 生命周期；系统 conntrack（CT）提供新私有代恢复入站回复所需的宿主方向证据，而不是替代这些状态。仅 `CT_ORIGINAL` 可创建入站 pending，仅 `CT_REPLY` 可恢复入站回复。LAN ingress 位于 netfilter 前，按当前报文的正向 tuple 查询默认 CT zone 中的既有记录并读取 ORIGINAL/REPLY；本机 WAN egress 优先读取报文附着的 CT，避免把 NAT 后的线上 tuple 当作原 tuple。查询缺失、过期或 NOTRACK 不是 direct 证据，不能凭“没有私有记录”“存在本地 socket”或先收到回复推断为真正入站。已有出站流的回复先到，也不能让下一客户端请求跳过新规则；请求在旧进程到达、第一份本地应答在新进程发出时，可依据仍有效的系统 CT 确认真正入站应答方向。一个 socket 应答过入站请求不豁免它访问其他远端的流。

`udp_conn_state_map` 保留已确认的连接方向与空闲生命周期，pending 等待本地接收权确认；`udp_routing_cache_map` 和 `udp_bindings_map` 保留路由缓存、代理关联职责。新私有代不能仅凭前任状态缺失认定入站。`DAE_REPLY_MARK` 仅标识 dae 合成的 relay 回包，不证明客户业务的发起方向。WAN 合成 UDP 回包重注入前必须匹配既有 host CT 的 REPLY 方向；记录消失或方向不符时丢弃迟到回复，防止它反向建立 CT，使未来客户端请求被误认成入站应答。LAN 合成回包直接送往 LAN egress，不经过 host PREROUTING，不要求为普通 LAN relay 创建 host CT。

必要 CT 能力缺失时，冷启动或替换预检明确失败，不回退到无 CT 猜测。预检在实际服务的 host namespace 中完成有界 IPv4/IPv6 回环 UDP 往返，再通过未挂载的 BPF probe 查询正反 tuple，要求观察到 ORIGINAL/REPLY；它同时检查 lookup/release、options ABI 和 verifier 支持，不只检查模块是否加载。预检不挂接宿主 loopback TC，不修改宿主防火墙、CT 参数或已有记录。错误区分 probe 加载、UDP 往返和方向查询失败，并标明地址族与阶段。

回环预检只证明当时该 host namespace 对受控新流的跟踪与查询能力，不保证接口专用 NOTRACK、自定义 zone 或管理员随后改变规则的场景。当前查询域是默认 zone；不为自定义 zone 承诺跨实例方向恢复。正常业务 lookup miss 仍按路由准入，不因此退出服务；没有可靠 CT、CT 已过期或被删除时，不承诺原入站会话的连续性，也不增加配置、CT mark 或 zone 迁移层。

`SK_LOOKUP` 只检查运行状态并从本运行时的 `listen_socket_map` 选择监听器，不根据路由缓存判断报文是否属于有效关联。`routing_tuples_map` 交接 TCP 和非 DNS UDP 的首包路由信息；DNS 按包使用 cookie 从 `dns_handoff_map` 取得路由和回包路径；UDP 源绑定及用户态 endpoint 负责关联生命周期，支持同一源访问多个目标，不依赖逐目标交接记录持续存在。

用户态入口复用已有源关联；新关联必须有本运行时有效的首包路由信息，DNS 继续逐目标读取。信息不足时丢弃，不回退直连。替换关闭旧关联，新运行时恢复接收后重新建立关联；普通配置 reload 仍保留同一运行时的关联。提交后迟到的数据报也遵循这些准入规则：可以进入已有的合法新关联，但不会读取旧进程的 maps，也不承诺区分所有切换前发出的 UDP 报文。

## 管理器与命令结果

预检和 exec 沿用 daemon 自身的 cgroup、工作目录、有效启动参数和环境，不采纳发起 `reload` 的 CLI 环境；交互修复过的配置文件使用修复后的路径。替换不依赖 systemd，也不转交 MainPID，支持直接前台运行和 `Type=simple`。正式 systemd 单元使用 `Type=notify` 和默认的 `NotifyAccess=main`；单一业务进程发送 READY、RELOADING、STOPPING，内部替换不发送 STOPPING，READY 等待真实业务就绪。NixOS 使用 `reloadIfChanged = true`，`ExecReload` 指向当前包中的 `dae reload`。Block 前 RELOADING 或可恢复操作结束时的 READY 发送失败会使该操作报错，已有 daemon 继续服务。服务启动参数、环境、credential 快照或其他启动条件变化仍要求显式重启。

SIGINT/SIGTERM 由 daemon 直接处理。Startup 从配置 I/O 前开始统一持有取消上下文、恢复期限和停机 watchdog，`Run` 复用同一个生命周期；不接受取消的阻塞 I/O 也受 15 秒停止期限约束。停止信号、恢复超时或主动关闭只启动一次停机宽限，进入 `Run` 和重复停机请求都不会延长它。恢复期限到达时先启动宽限，再取消准备工作；准备完成只停止恢复计时器，并等待已开始的取消回调结束。exec 前的信号屏障区分停止接收和真实停止请求，并检查已排队信号；新映像恢复原事务期限，不重新给予三分钟。旧 Go watchdog 不会跨 exec 存活。若新 ELF 的加载或包初始化永久挂死，仍需外部服务管理器介入；没有常驻 watchdog 进程，也不承诺 replace 能修复任意挂死。

操作始终保持 `kind=reload` 和同一个随机 ID。CLI 只重试交接期间的读取失败，不重试提交请求。新映像继承当前操作记录，以不变的 PID 和新版本完成记录；旧运行时不会提前报告成功。监听器 FD 保留不保证 operation 查询无间断：exec 后 Go server 恢复前可能超时或断连，交接失败后的冷启动也不会恢复原 operation。替换期间拒绝新的配置操作，避免将旧队列中的请求遗失。
