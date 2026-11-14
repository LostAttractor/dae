# 测试与性能测量

进入 `nix-shell` 或 direnv 开发环境。若没有本地 `plugins.cfg`，先复制 `plugins.cfg.example`；取消本地配置中 DNS cache 和 router 条目的注释，以验证全部自有插件的编译选择。从仓库根目录运行：

```sh
make test
make test SURGE_RUNTIME=nodejs
make client-test
make config-parser-check
make -C web test
```

Surge 的 worker 测试需要 delegated cgroup v2 memory；普通终端未获委派时，将上述 `make test` 放到临时 systemd 单元中运行，测试本身仍使用当前用户：

```sh
sudo systemd-run --wait --pipe --collect --uid="$(id -u)" \
  --property=Delegate=memory --property=DelegateSubgroup=daemon \
  --working-directory="$PWD" env "PATH=$PATH" "HOME=$HOME" \
  make test TEST_ARGS=-count=1
```

Node 后端在末尾追加 `SURGE_RUNTIME=nodejs`。临时单元退出后自动回收，不修改现有服务配置。

根测试覆盖核心、`pkg/outbound`、配置解析器和全部自有插件，包括 DNS cache、Surge 与 router 的组合用例。`make test` 同时检查协议库和宿主的依赖方向；`make client-test` 检查无 CGO 的 API/CLI 边界。第三方 fork 保持独立模块，使用单独的测试命令：

```sh
go test -race github.com/buke/quickjs-go/...
(cd third_party/quic-go && GOWORK=off go test -race . ./http3)
```

Web 测试使用本地最小夹具和已安装的 Chromium；可用 `CHROMIUM` 指定浏览器路径，`openssl` 和 NSS `certutil` 须位于 PATH。证书测试使用临时 HOME、浏览器配置和 NSS 信任库，不修改现有信任设置；不使用忽略 TLS 错误的启动参数。额外的 `pnpm --dir web run test:certificate` 需要 Go 工具链，单独运行生产 Go API、CSP 与浏览器请求函数的集成检查，覆盖安装 CA、未安装 CA、手动接受 HTTPS 警告，以及 HTTP/HTTPS 页面。除 IPv4/IPv6 回环地址外，存在私有 IPv4 网卡时也从该地址测试普通 LAN HTTP；没有该网卡时明确报告跳过。普通 Go 测试不替代需要 root 的 `make ebpf-test`。

## 持久内核状态与阻断防护

跨进程保留的 TCP 连接属性表为 `tcp_flow_map`（LRU hash，40 字节键、24 字节值），以及对应的原子门数组（4 字节键、8 字节值）。`socket_owner_map` 使用 socket-local storage（4 字节键、20 字节值），`daemon_identity_map` 保存显式登记的进程身份，`fallback_sequence_map` 保存单调发行序号（均为 4 字节键、8 字节值）。设备策略 outer/inner maps 同样保留设备版本。普通 restart 按表比较元数据，复用兼容的 canonical pins；替换不兼容的连接属性表会丢掉连接的 mark 和代次约束，但不中断连接。同进程 reload 使用 Runtime 的共享表。

固定表的字节布局及含义是显式契约。TCP 连接属性的 `route_epoch`、`mark`、`fallback`、`syn_seq` 分别位于偏移 0、8、12、16，偏移 20 的 u32 为 `explicit_direct`，`routing_result` 偏移 31 的 byte 同样记录该证据，大小仍为 24/40 字节。零表示 unknown，旧 padding 为零不能在 `STOPPING` 中证明 direct。fallback 为 0 只表示不受代次撤销约束，不等于 explicit direct；1 始终无效，其余值为唯一的组代次令牌，没有 `PERMANENT` 特殊 token；持久发行序号不回卷、不重用。Socket 归属值的 `pid` 位于偏移 0，16 字节 `pname` 位于 4。运行时元数据比较不能识别相同大小的语义变化；`TestPinnedMapABI` 与固定字节夹具独立于生成类型检查布局。容量不匹配只替换对应表。

`TestRemoveIncompatiblePinnedMaps` 验证选择性替换及保留表的 ID、内容；`TestPinnedTCPFlowEncoding` 验证直通 mark 和令牌边界。`TestPersistentKernelLifecycle` 在私有网络、mount、bpffs 和 `/run` 中启动自己的 helper 进程，验证同一真实 TCP 连接跨 SIGKILL、未上线即退出的重启与接管的转发，以及正常退出完整清理（含旧版本的 map pin）、身份撤销、版本恢复、异常退出后的新 UDP 转发、私有 timer map 替换和清理失败边界。NAT 测试使用自建命名空间和最小 nftables 规则，覆盖双栈本机、DNAT 到本机及 LAN 转发；握手并发测试验证新 SYN 与迟到 SYN-ACK 不会混用策略。测试不得接触宿主正在运行的 dae pins 或杀死非夹具进程。保留内核状态不保留用户态 relay socket；进程级 fallback 代次仍可能随冷重启结束。

## 表项容量快照

状态通过内核已有元素计数采样 hash/LRU 占用。独立按需加载的 BPF iterator 只对当前控制面选中的 map ID 读取计数，不扫描 flow entries、不刷新 LRU，也不在转发路径增加计数。并发增删时的 per-CPU 合计是采样值，不是事务快照。数组展示实际编译的指令或 LPM 表槽位数，不把预分配的数组单元误报为已占满。

用户态 UDP 表直接读取 source、packet resource 和回包 socket 的已有准入预算，共享资源只计一次；建立中、关闭中的预留按实际准入所有者释放时机计数。已占用表项不等于活动连接数，读取失败显示不可用而不是空表。测试使用私有小表与自写资源池夹具，不读取生产表内容。

## 替换私有状态与 guard 生命周期

进程替换是带故障防护的进程重启，不是全局原子或无损交接。Block 前失败保留旧服务；Block 后旧连接关闭不可回滚，失败后保持 fail-closed，直到成功恢复。多 hook 逐步安装与撤旧是有防护的中间态，不是一个全局原子事务。

只有进程替换和 guard 恢复创建私有业务 maps，不复用前任业务 pins；成功提交显式发布自身 canonical pins，正常运行继续持久化，普通 restart 复用兼容 pins，同进程配置 reload 共享 Runtime maps。TCP/UDP 用户态 relay socket、fallback lease 和私有连接状态不跨 exec 迁移。共享网络对象的 link 通过 FD 交接；协议中的 link 角色、固定网络拓扑及受管接口集合仍是交接契约，见[进程热替换](../design/process-replacement.md)。

`/sys/fs/bpf/dae/guards/<link-id>/` bundle 持有入口 link、`udp_conn_state_map`、`udp_routing_cache_map`、该代 socket-owner writer links、exit hook 和 `daemon_identity_map`。只有 UDP 使用 timer maps；内核 timer 需要 map FD 或 map pin，仅有 link→program→map 引用不足以维持过期回收。旧 canonical 与 guard 两处引用必须实际释放，同名 pin 不能将旧身份 writer `Update` 为新程序。guard maps 不是新运行时的业务状态源；恢复先验证全部旧捕获 hook 的覆盖，再解除旧防护。

已有明确直连在仅有旧 guard、且该 guard 仍持有有效证据时可能继续；新旧私有 maps 不共享跨代 direct 证据，重叠 guard 允许暂停直连，后置失败可能使暂停持续到成功恢复。测试必须允许该暂停，同时继续拒绝捕获及不确定流量，不能要求直连不中断。

TCP 使用短期 handoff，随后由真实 accepted socket 接收；SOCKHASH 只是可选索引，容量满或登记失败回退到 proxy netns socket lookup。24 字节值的 LRU `tcp_flow_map` 只记录 native 属性，不是代理准入账本或 FIN/ACK 状态机，没有 TCP timer takeover。成功替换与普通 restart 语义一致：`ONLINE` 下未知非 SYN 归为 native，不提供永久拒绝旧未知 ACK 的保证。

`TestReplacementGuardBundleKernel` 检查成组引用、重复 pin 身份校验、部分失败回滚和清理顺序；`TestGuardTimerMapReferences` 比较关闭 map FD 后仅保留程序引用与额外 pin 时的 UDP GC 行为。`TestReplacementGuardsKernel` 和 `TestFailedRecoveryDoesNotExpandGuardsKernel` 验证失去进程 FD 后仍阻断，以及失败恢复不会扩大后续必须覆盖的 hook 集合。`TestUDPRepliesReleaseRetiredTimerPrograms` 检查 UDP timer 回调退役，不引入 TCP timer 状态。测试使用隔离 maps、PID/网络/挂载 namespace 及私有 bpffs，不接触正在运行的 daemon 的 pins。

UDP 保留 `udp_conn_state_map`、`udp_inbound_pending_map`、binding、routing cache 及 timer 生命周期；host CT 提供新私有代恢复入站回复的方向证据。仅 `CT_ORIGINAL` 创建入站 pending，仅 `CT_REPLY` 恢复入站回复；CT miss、过期或 NOTRACK 不是 direct 证据，缺少有效 CT 时不承诺跨实例入站连续性。

## 性能测量

`scripts/runtime-ablation.py` 在临时副本和独立网络命名空间中执行 reload 消融：可通过 `--baseline` 传入源代码快照，对比接入循环额外复制的监听 FD 数量及配置发布开销；`extra-fds` 不含各版本都需要的原始 TCP/UDP 监听 socket 和 map 描述符。逐项移除代际、SYN、长期 TCP 状态、过期、消费、策略归属与关闭屏障，要求相应行为断言失败。日志、固定 CPU 的交错重复样本和统计保存在输出目录。运行前生成生产及内核测试 BPF 对象，需要 Go、Clang 和免密 sudo。

`control/kern/tests` 的 C 用例各自加载独立 maps，避免前一个用例的路由、域名或连通性状态掩盖错误。Go 的捕获与缓存回归直接检查内核返回值和交接状态，不能仅以最终出站名为 direct 证明内核直通。

内核 fixture 构造集中在 `routing_test_helpers_test.go`，功能回归在 `routing_flow_test.go`，计时循环在 `routing_flow_benchmark_test.go`。`make ebpf-lint` 同时检查本项目的内核 C 文件和路由头文件。

`BenchmarkRoutingFlow` 覆盖域名映射缺失、空位图、AND/OR 短路及普通顺序扫描。`BenchmarkRoutingLPM` 覆盖目的 IP、源 IP、MAC 的单次和连续查询，用未命中的路由规则和连续命中的 AND 链分别测量两条路径，单条命中规则直接结束路由；计时前验证实际命中结果，避免意外短路掩盖查询成本。路由基准以 block 结束 SYN 决策，不建立直通准入或用户态交接；重复报文必须遍历规则，而不是命中先前的连接准入。`BenchmarkRoutingConditionalBlock` 比较逐条条件与共享条件块，`BenchmarkHTTPClientAdmission` 比较 HTTP 准入允许和拒绝路径。比较包处理性能时使用 `bpf-ns/op` 指标；`ns/op` 包含批量调用开销。`BenchmarkUDPRoutingCache` 分开测冷路由与缓存命中。生成内核测试后可运行：

```sh
go test -c -tags dae_bpf_tests -o /tmp/dae-kernel.test ./control/kern/tests
sudo /tmp/dae-kernel.test -test.run '^$' -test.bench 'Benchmark(RoutingFlow|RoutingLPM|RoutingConditionalBlock|HTTPClientAdmission|UDPRoutingCache)' -test.benchtime 30x -test.count 3
```

使用 `scripts/routing-program-metrics.go` 测量生产 ELF 的验证指令数、程序大小和加载时间，使用 `scripts/routing-map-memory.go` 测量内核报告的 map 内存。两者均创建隔离 maps，不复用 daemon pins，也不挂载网络接口；使用当前 direnv 工具链编译后以 root 运行。

内存脚本从 ELF 读取实际类型、容量和分配标志，逐表读取 `fdinfo.memlock`：

- 对按需分配的 HASH，测量空表、1、16、1,024、65,536 项和满表，跳过超容量或重复的检查点。覆盖 UDP 绑定、域名路由、路由接口与 profile，以及 `device_routes_map.inner` 设备路由子表。
- 对预分配 HASH、LRU_HASH、ARRAY、PERCPU_ARRAY 和 ARRAY_OF_MAPS，只测创建成本，不重复填满。覆盖 TCP native 属性 LRU、UDP 路由缓存和主要 LRU 表；输出内核 possible CPU 数量，便于比较 per-CPU 分配。
- 外层 map 与单个 inner 模板分别报告；外层槽位不填入子表。设备路由表未使用时没有实际子表，更新时可能同时持有旧表、过渡表和新表，因此不能把单表结果直接当成运行时总量或更新峰值。
- 必测 map 或设备路由 inner 模板缺失、类型不支持时失败退出；其余未支持类型显式输出 `status=not_measured`。LPM、socket storage、SOCKMAP 和 SOCKHASH 不测，不生成前缀或 socket 夹具。

该口径不是进程 RSS，也不包含真实流量激活 timer、创建 socket storage 等生命周期分配；不汇总为 daemon 总内存或替换峰值。加载成本、每包耗时和内存占用应分别测量。

```sh
make ebpf
go test scripts/routing-map-memory.go scripts/routing-map-memory_test.go
go build -o /tmp/dae-map-memory scripts/routing-map-memory.go
sudo /tmp/dae-map-memory control/bpf_bpfel.o
```

`make test` 包含上述脚本的非特权回归，校验生产 ELF 覆盖范围及缺失对象的失败行为。内核测量回归需独立 PID、网络和挂载 namespace；先编译测试二进制，再以 root 和 `DAE_TEST_ISOLATED=1` 运行 `TestMeasureMapKernel`，验证不同容量检查点、固定分配、嵌套模板和不复用 pin。

用户态 `BenchmarkRoutingMatcher` 使用相同的有效指令比较执行器与输入准备开销，覆盖顺序端口、域名、混合 LPM 和 AND/OR 短路，同时报告分配次数：

```sh
go test ./control -run '^$' -bench '^BenchmarkRoutingMatcher$' -benchmem -benchtime=100ms -count=3
```

以下基准分别测量紧凑 Trie、节点可用性及延迟快照、DNS 接收存储和 UDP 空闲时间刷新。`BenchmarkTrieHasPrefix` 在构造完成后查询固定的 IPv4/IPv6 命中与未命中键；`BenchmarkDialerUsable` 和 `BenchmarkDialerSelectionSnapshot` 包含已填充的延迟历史，但不包含具体协议的 Session 查询。`BenchmarkDialerLatencyUpdateAndSnapshot` 在同一临界区记录一次检查并读取延迟，计入写入和快照的完整成本。两个 control 基准不执行网络 syscall，DNS 基准包含中继取消设置和独立应答构造：

```sh
go test ./pkg/trie -run '^$' -bench '^BenchmarkTrieHasPrefix$' -benchmem -cpu=1 -count=5
go test ./component/outbound/dialer -run '^$' -bench '^BenchmarkDialer(Usable|SelectionSnapshot)$' -benchmem -cpu=1,8,32 -count=5
go test ./component/outbound/dialer -run '^$' -bench '^BenchmarkDialerLatencyUpdateAndSnapshot$' -benchmem -cpu=1 -count=5
go test -tags=netgo,osusergo,trace ./control \
  -run '^$' -bench '^Benchmark(DNSUDPBuffer|UDPIdleRefresh)$' -benchmem -cpu=1 -count=5
```

HTTP scope 匹配的构建与查询成本可用 `BenchmarkHTTPScopes` 测量：

```sh
go test ./component/mitm -run '^$' -bench '^BenchmarkHTTPScopes$' -benchmem -benchtime=100ms -count=3
```

`component/plugin/codec` 的 `BenchmarkCodecHTTP` 在计时循环外准入既有输入 View，每轮计入输入消费、解码和输出释放；压缩窗口与正文共享预算。解码成功、大小/格式失败与预算拒绝使用各自的预算条件，避免因工作区尚未准入而跳过待测分支。

流式首消息测试使用通道闸门控制尾帧和 EOF，只在客户端实际读取首帧后放行，不依赖等待时长推断交付。`TestCodecCloseUnblocksSource` 先确认源 Read 已进入，再并发 Close；Mutex 等待不是 `synctest` 的 durable block，因此该用例用显式超时触发失败断言，随后放行闸门并回收 goroutine。

`BenchmarkDomainRegistry` 测量有名和无名活动续期、从二进制基线冷恢复的耗时及分配。内核写入回调为空操作，因此该基准只衡量用户态 Registry：

```sh
go test -tags=netgo,osusergo,trace ./control \
  -run '^$' -bench '^BenchmarkDomainRegistry$' -benchmem -benchtime=200ms -count=3
```

`BenchmarkDomainRegistryCompaction` 测量一次压实：锁内扁平复制全部 pair，锁外编码基线并按顺序发布两个文件，`baseline-bytes` 是基线大小。`BenchmarkDomainRegistryRenewals` 测量写入者结束一个续期窗口的成本，每个窗口续期 1,446 个不同的 pair，计时包括编码、追加和 fdatasync，结果取决于测试目录所在的文件系统：

```sh
go test -tags=netgo,osusergo,trace ./control \
  -run '^$' -bench '^BenchmarkDomainRegistry(Compaction|Renewals)$' -benchmem -count=3
```

`BenchmarkDomainRegistryRenewalLayout` 固定每窗口 1,446 个续期 pair，用自编写的确定性序号比较分散、热记录在前和热记录在后三种理想布局。`frame-bytes` 包含日志帧头和 CRC，不包含文件系统页粒度、元数据或闪存写放大，也没有计算为保持同域名分组而受到的重排限制。这个基准用于比较编码长度，不证明真实 I/O 或 CPU 收益：

```sh
go test -tags=netgo,osusergo,trace ./control \
  -run '^$' -bench '^BenchmarkDomainRegistryRenewalLayout$' -benchtime=1x
```

`TestInspectDomainRegistry` 与 `TestRegistryDump` 前缀的用例检查只读导出、基线和日志合成、损坏尾部、过期记录、稳定排序及 CLI 输出错误；夹具只包含保留的示例域名和地址，不读取真实 registry。

`TestDomainRegistryHotCompaction` 检查当前及前一窗口的热点分组、同域名内的热点前置，以及重编号后新增和续期日志的正确重放。`TestDomainRegistryHotCompactionSparsePairs` 生成 50,000 个 pair，其中 100 个近期续期、20,000 个从未续期；它验证所有记录和序号的完整恢复，并比较真实压实前后的续期帧长度，而不假定热点 pair 能跨域名组任意排列。

`BenchmarkDomainRegistryActivity` 使用包含共享 IP 和全零 bitmap 的 28,042 个 pair，分别测量同步入口的未知目标、期限未变、有效续期和到期前检查。`BenchmarkDomainRegistryContention` 的混合负载中四分之一同步观察延长期限，其余为期限未变或未知目标；用 `-cpu` 改变并发度，`p95-ns` 和 `p99-ns` 包含等待队列锁与 Registry 锁的时间。并发基准的分配量包含延迟采样开销，单次观察的分配量使用 Activity 基准：

```sh
go test -tags=netgo,osusergo,trace ./control \
  -run '^$' -bench '^BenchmarkDomainRegistryActivity$' -benchmem -benchtime=300ms -count=5
go test -tags=netgo,osusergo,trace ./control \
  -run '^$' -bench '^BenchmarkDomainRegistryContention$' -benchmem -benchtime=1024x -cpu=1,8,32 -count=3
```

`BenchmarkDomainRegistryGC` 按 worker 的节奏重放一小时：每秒执行一次回收，并随机续期十个 pair。夹具约有 10.2 万个 pair，分布在 1.6 万个共享 IP 上，其中一个域名有 4,096 个地址，截止时间分散在整个窗口内。`max-call-ns` 是最慢一次回收的耗时，回收期间持有连接建立和 DNS 交付都要等待的 Registry 锁：

```sh
go test -tags=netgo,osusergo,trace ./control \
  -run '^$' -bench '^BenchmarkDomainRegistryGC$' -benchmem -count=3
```

`BenchmarkDomainRegistryCapacity` 使用一个内核槽位，分别测量已驻留 IP 续期和两个 IP 交替竞争槽位；固定操作数便于比较同一换入换出序列。`BenchmarkDomainRegistryFootprint` 测量上述夹具数据在临时构造对象回收后的常驻 Go 堆，单独以 `-benchtime=1x` 运行，读取 `retained-bytes`、`retained-objects`：

```sh
go test -tags=netgo,osusergo,trace ./control \
  -run '^$' -bench '^BenchmarkDomainRegistryCapacity$' -benchmem -benchtime=1024x -count=3
go test -tags=netgo,osusergo,trace ./control \
  -run '^$' -bench '^BenchmarkDomainRegistryFootprint$' -benchtime=1x -count=5
```

`BenchmarkDomainActivityBatch` 使用同一夹具数据，模拟 64 个连接对共享 IP 的重复 I/O；每 1,024 次观察应用一次批次，计时包含应用成本。每个连接的回调每秒最多入队一次，因此以下活动基准中的大多数调用只经过无锁的节流判断。`BenchmarkDomainActivityIOContention` 运行真实后台循环，并在计时结束前通过关闭应用最后一批；`p95-ns` / `p99-ns` 衡量前台观察回调耗时，状态实际可见时间还取决于批次应用。它是饱和负载，吞吐更高的实现也会产生更多排队竞争，不能直接把尾延迟当作固定流量下的网络延迟：

```sh
go test -tags=netgo,osusergo,trace ./control \
  -run '^$' -bench '^BenchmarkDomainActivityBatch$' -benchmem -benchtime=500ms -count=5
go test -tags=netgo,osusergo,trace ./control \
  -run '^$' -bench '^BenchmarkDomainActivityIOContention$' -benchmem -benchtime=1s -cpu=1,8,32 -count=3
```

`BenchmarkDomainActivityQueue` 为每个 worker 分配稳定的观察目标，分别测试多个独立目标和所有 worker 共用一个 IP。每 64 次回调采样一次耗时，以减少采样对短入队路径的干扰；后台工作和关闭时的最终批次应用均计入总耗时。评估队列竞争时，应同时测量同步入口和空批次成本：

```sh
go test -tags=netgo,osusergo,trace ./control \
  -run '^$' -bench '^BenchmarkDomainActivityQueue$' -benchmem -benchtime=1s -cpu=1,8,32 -count=3
```

sing-mux 的 smux 测试使用 `pkg/outbound/transport/singmux/smuxtest` 中的最小 v1 服务端：它像 sing-box 服务端一样拒绝版本错误或命令未知的帧，还拒绝带载荷的控制帧和偶数流 ID 以暴露客户端的编码错误（sing-box 服务端不检查这两项），并无限缓冲各流数据，因此会话共享接收缓冲造成的阻塞只可能来自客户端。服务端每帧只调用一次载体 `Write`，避免将帧头和载荷强行拆成两组加密记录；这不保证真实服务端采用同样的分段策略。`BenchmarkConnWrite`、`BenchmarkUDPSmuxRoundTrip` 和 control 的 `BenchmarkSmuxReceive` 经 `net.Pipe` 运行，计入客户端会话与服务端夹具双方的调度和分配；`BenchmarkTCPWriteFrames` 比较 Shadowsocks 2022 把一批两个帧（各自帧头与载荷连续）合并后写入和向量写入的开销：

```sh
go test ./pkg/outbound/transport/singmux -run '^$' -bench '^Benchmark(ConnWrite|UDPSmuxRoundTrip)$' -benchmem -count=5
go test ./control -run '^$' -bench '^BenchmarkSmuxReceive$' -benchmem -count=5
go test ./pkg/outbound/protocol/shadowsocks_2022 -run '^$' -bench '^BenchmarkTCPWriteFrames$' -benchmem -count=5
```

`BenchmarkExchangeTCP` 通过 `net.Pipe` 完成一次 router 请求/响应，包括每查询 socket 和 worker 建立，衡量单次查询的管理成本。在包含 router 的工作区运行：

```sh
go test ./plugins/dns-router -run '^$' -bench '^BenchmarkExchangeTCP$' \
  -benchmem -benchtime=300ms -count=5
```

## UDP 与多路复用排队实验

验收目标、场景分类和有效性要求见[排队目标与验收](queueing-tests.md)。以下描述夹具与报告，不构成统一的端到端时延保证。

`scripts/tests/queueing` 在两个网络命名空间之间运行 control 包中以 `DAE_QUEUE_EXP=1` 开启的 `TestQueueingExperimentClient` 和 `TestQueueingExperimentServer`。客户端扮演 LAN 主机和 dae：UDP 数据报像 ingress 一样进入真实的 `udpTaskPool`，经端点写入走 `writePacketUntil`，再由 direct TCP、Shadowsocks 2022 和 sing-mux smux 组成的出站链发出；TCP 负载直接写出站流。服务端用树内最小夹具中继：`ss2022test` 是按规范编写的 Shadowsocks 2022 服务端，smux 用 `smuxtest`，QUIC 用 third_party 的 quic-go；UDP 探针由反射器带回接收时刻和累计计数，上传汇点定期回报收到的字节数。

客户端的 UDP 流跳过关联建立，直接在 mux 上打开 UDP 关联；建立过程交给拨号的上下文中只模拟嗅探结果：QUIC 流带上 QUIC 标记，与真实建立一样进入 bulk 数据报 lane，不模拟其余真实关联建立上下文。`QEXP_UDP=direct` 时每条 UDP 流改用 direct 出站自己的 socket，如 direct 与 Shadowsocks UDP。设置 `LAN_RATE` 时，回包像 dae 发出的一样，经绑定回包来源地址的透明 socket 发往客户端命名空间 lo 上的 LAN 主机地址 192.168.77.10，lo 用 tbf 限速，队列大于 socket 发送缓冲区，因此先满的是回包 socket；负载停止后 tbf 改为不限速而不删除，以免丢弃排队的回包，最终计数得以送达。未设置时测试直接从端点接收回包。客户端命名空间的 UDP socket 错误计数写入 `LABEL.client.nstat`。写者自旋变体用包装连接给承载写入加延迟，并通过 `ReadPassthrough` 保留读方向的 socket 调优，避免把包装造成的行为变化误算为写者成本。

默认拓扑固定为本机实验条件，并不自动读取路由器配置：客户端出口为 cake，40 Mbit、diffserv3、triple-isolate、nonat、nowash、split-gso、raw，RTT 50 ms，target 保持默认 5 ms。CAKE 的 RTT 参数控制 AQM 时间尺度，不是实际载体 RTT；tc 的 `rtt` 关键字会把 target 一并设为 RTT 的 1/20，即 2.5 ms，因此 cake 由 `TestQueueingExperimentCake` 经 netlink 建立，`run.sh` 校验 Best Effort 档为 target 5ms、interval 50ms。`tc qdisc show` 的摘要行看不出 target，只有 `-s` 的分档统计能区分。开启 BIG TCP（GSO/GRO 524280），`tcp_wmem` 上限 655360；netem 只加在服务端出口，因此上行单向时延不包含配置的回程时延，但仍包含两端处理与排队，不能全部归因于客户端队列。客户端与服务端进程分别固定在两半物理核心上，互不共用 SMT 兄弟线程。服务端的 UDP socket（反射器和每条 smux UDP 流的中继 socket）都用大接收缓冲；`run.sh` 在运行后读取服务端命名空间的 `UdpRcvbufErrors`、`UdpInErrors` 及其 IPv6 计数，非零即判本次运行无效；客户端丢包仍需结合两端计数核对，不能仅凭该检查归因全部损失。

```sh
go test -c -o /tmp/control.test -tags=netgo,osusergo,grpcnotrace,trace \
  -ldflags '-X github.com/daeuniverse/dae/common/consts.MaxMatchSetLen_=1024' ./control
sudo scripts/tests/queueing/run.sh /tmp/control.test w1 QEXP_WORKLOAD=game,bulk:4
SUDO="sudo -n" OUT=/tmp/qexp-ab scripts/tests/queueing/matrix.sh /tmp/before.test,/tmp/after.test 2 normal saturated
```

`run.sh` 的变量说明见脚本开头，包括带宽、回程时延、拥塞控制、ECN、LAN 速率、MPTCP、smux 会话数、UDP 流经 smux 还是各用一个 socket、写者每轮的 CPU 自旋延迟和下行读者停读或慢读。`matrix.sh` 默认只运行 `normal`（纯游戏）与 `saturated`（游戏加四条大流），每个二进制两轮；W1–W4、W6、W7 和 S4 诊断场景需要显式指定。S4 另有 UDP 各用一个 socket、洪泛高于和低于带宽的变体，W6 另有 LAN 慢于回包的变体；W5（经 DNS 中继的 53 端口请求应答）、S5（hysteria2 Brutal 与 TUIC）和 go-yamux 服务端夹具尚未覆盖。给出前后两个测试二进制时，`matrix.sh` 在每轮重复中交替运行二者，并交替先后顺序，使比较按同一轮配对，而不受相隔数小时的机器负载影响；两个二进制的文件名（去掉 `.test`）作为标签，须不同。`OUT` 须为空或不存在，避免混入先前的运行。每次运行在 `OUT` 下写出客户端 JSON 报告、两端日志、cake 统计和服务端 UDP 丢包计数；报告的 `binary` 为测试二进制的 SHA-256，矩阵对每个产物只计算一次并复用；构建参数保存在 `OUT/artifacts`，不同 Go 版本或构建参数会在实验前拒绝。单独运行 `run.sh` 时可传入已记录的 `QEXP_BINARY`，未传入则计算一次。服务端命名空间丢过 UDP 或中途中断的运行不留下 JSON 报告。`conditions` 记录实际使用的负载、拓扑、采样和运行平台。`summarize.py` 按场景和二进制输出有效运行的中位数及范围，并显示无效数量；有两个二进制时，仅对条件齐全、相同且有效的轮次计算配对变化，排除原因输出到 stderr。判断 CPU 等小幅变化应看配对变化及其范围。

报告中的时延只统计预热之后测量窗口内发出的探针：`game_up_ms`、`itcp_up_ms` 为上行单向时延，`flood_up_ms` 为洪泛中每 16 ms 一个满长探针的上行时延，即洪泛自身的排队时延，`game_down_ms` 为回包时延减去 netem 时延，`game_window_unechoed` 为窗口内发出但没有收到回包的探针数，这些探针不在时延分位数中。窗口结束后探针照常发送但不记录，负载也继续，直到每种探针都收到一个窗口之后发出的探针的回应：同一条流中排在它之前的窗口探针此时已在负载下收到回应或丢失。game 与 flood 分别等待各自的探针，纯洪泛场景也保持负载直到洪泛探针完成。等待最长为一个测量窗口，`settle_s` 为窗口结束到负载停止的时长；`settle_timeout` 为 true 表示等待超时，时延结果无效。`late` 为负载停止后才收到回应的窗口探针数，包含洪泛上行和下行；这些探针的时延被截短，应为 0。名称带 `_q1`、`_q4` 的项只统计窗口第一个和最后一个四分之一内发出的探针，二者差距大说明时延仍在增长，结果不是稳态。吞吐来自服务端回报。`QEXP_SOCKET_SAMPLES` 默认开启；关闭时不做 socket 轮询，也不输出 `notsent_bytes`。默认的两种配对场景会关闭它，避免比较不同数量载体的观测成本。开启时，`notsent_bytes` 每 10 ms 用 `SIOCOUTQNSD` 读取全部承载，取其中最大值作为一个样本，空闲承载不会稀释分位数；MPTCP 回落的 socket 上该读数还包含子流的在途字节，按 `TCP_INFO` 的 `bytes_sent − bytes_retrans − bytes_acked` 扣除。`cpu_ms_per_gb` 为测量窗口内进程 CPU 时间除以有效上传量，分子 `cpu_ms` 与分母 `uploaded_bytes` 一并输出。TCP、QUIC 和 UDP 洪泛共用窗口两端采样的服务端累计接收字节增量；洪泛复用探针带回的接收计数，按固定包长换算为字节，入队、socket 或 qdisc 丢弃的数据不计入，`flood_mbit` 为这一增量换算的有效速率。计数回报存在采样间隔与回程延迟，应在稳定负载下配对比较；LAN 回程持续积压时不宜用它验收 CPU。启用 socket 采样、LAN 侧 QUIC 客户端或写者自旋时，不输出 CPU/GB。关闭这些额外工作后，纯游戏负载输出 `cpu_us_per_game_packet`，以测量窗口内发出的探针数 `game_window_sent` 为分母；必须同时检查交付数量和丢包，不能把提前丢弃视为转发效率。`datagram_memory_peak` 为共享 UDP 数据报内存的峰值字节数，`maxrss_kb` 为客户端进程的最大常驻内存。

`drops` 为从打开第一条 UDP 流之前开始的丢包计数增量，与各流的发送计数起点一致。`game_lost`、`flood_lost` 为上行少收的数量，下行少收数量为 game、flood 各流的 `NAME_probes_received − NAME_echoed − NAME_lan_dropped` 之和；`NAME_probes_received` 是反射器收到的探针数，`NAME_lan_dropped` 是 LAN 读者来不及接收的回包。普通洪泛数据报不产生回包，不能用包含它们的 `flood_received` 计算下行丢失。`qdisc_drops` 为同一时段客户端出口 qdisc 的丢包数。`upload_unaccounted`、`download_unaccounted` 分别为上下行少收数量减去对应方向的丢包计数，应为 0；`QEXP_UDP=direct` 且仅有 UDP 负载时，上行再减去 `qdisc_drops`；存在 `bulk`、`itcp`、`ttfb` 或 TCP download 时，qdisc 丢包可能来自 TCP，不能归属到 UDP，因而不输出 `upload_unaccounted`，下行核对仍保留；`summarize.py` 对这两项、`late` 及 `settle_timeout` 输出各次运行中偏离 0 最远的值，不能用中位数掩盖无效运行。LAN 侧 QUIC 流的丢包也会计入，但其数据报不在核对范围内，有 QUIC 流的场景不输出这两项。

## 进程热替换

`TestRestoredProcessNameRoutesInternalRequests` 验证非 leader Go 线程恢复进程名后，内部 DNS 和资源请求仍匹配固定的 `pname()` 规则。真实 exec 夹具检查进程名和实例锁 inode 跨替换不变，并在替换及崩溃恢复后重试第二个 `dae run`，确认始终拒绝额外业务实例。

`TestFailedRecoveryPrunesUDPTimerPinsKernel` 检查失败候选回收无用 timer pins，同时保留仍挂载 guard 的实际引用，包括部分清理的 bundle。`TestFailedRecoveryTimerPinsKernel` 通过两个独立 daemon 进程的活插件构造失败，验证不会累积无用的 runtime timer pins，旧 DROP guard 仍保持。每个用例使用全新的 PID/网络/挂载 namespace、私有 `/run` 和 bpffs。

目标 ELF 在 Block 前运行配置解析、插件 Preflight 和内核能力检查，再构造不绑定业务 BPF 的用户态 plane，读取配置/include、订阅、模块和依赖、geodata 与完整静态 Plan。此阶段不构造活插件、VM 或执行 `Warm`/Worker，不读取 settings/Registry；旧数据面与 API 继续服务。handoff 协议为 5：父进程经 `ExtraFiles` 交给目标一份独立输入 memfd，目标写入并封印，父进程先撤销 PID 豁免再 `Wait`；64 KiB 的交接描述与输入包分开，单输入/完整资源组上限为 128 MiB，整个输入包上限为 512 MiB。

正式 exec 仅为初始化 reader 绑定严格回放，保留配置/include/glob 选择、资产位置和 bytes、完整 cache 组的成功/失败/fallback，以及跳过订阅的决定；缺项、损坏、解释不符或超限不能退回 live I/O，也不能被兼容解码或 skip 吞掉。正式 Runtime 先安装必要的最小 socket-owner hooks，再允许持久代理 socket；用户态准备完成后才加载业务 BPF、构造插件和 `Warm`。连通性保存原 lease，绑定后才发行内核 token。选择器只使用旧内存 hints，准备路由的逻辑 PID/pname 不等于取得临时豁免的真实 kernel TGID。settings 在旧 API 关闭、exec 后首次读取，Registry 在本地 Commit 恢复，Surge store 仍惰性读取；运行期 ctx 和后续 reload 不携带本次 reader 快照。旧写者必须先关闭并完成最终 flush，新写者才读取最终状态并启用持久化，保持单写者约束。完整状态边界见[进程热替换设计](../design/process-replacement.md)。

新运行时完成 Registry 投影、共享导出发布与完整入口覆盖校验后，逐步撤除旧 guard 并进入 `ONLINE`。`ONLINE` 是本运行时的数据面生效点，不是所有 hook 和共享导出的原子提交；READY 是就绪通知，不是全局原子提交回执。晚期 READY 失败或取消仍可安全重新阻断并终止新实例，保留恢复防护；这是失败处置，不是恢复旧进程，也不能忽略 READY 失败。`ConfirmReady` 先在接口冻结期间校验全部 hook，再发送 READY；成功后才解除冻结、移除独立恢复标记并取得正常删除权。已提交运行时的冗余 guard-bundle 清理、无引用旧 UDP timer pins 清理和成功接管后的导出备份清理失败只记录警告；状态/拓扑校验错误及提交完成前的旧 guard 撤除错误仍为 fatal。

先运行不需要特权的协议与生命周期测试：

```sh
go test -race ./internal/daemon ./internal/handoff
```

`internal/handoff` 的 `TestSelfExec` 使用测试 ELF 自身作为最小夹具，覆盖不同内容 ELF 和同 ELF 强制 exec、PID/starttime 恒定、包初始化重新执行及旧 heap 消失、环境/参数保持、旧子进程回收与 FD 不增长，不依赖第三方程序或网络资源。`TestExecFailure` 检查 exec 错误及 FD 白名单；`TestSealedState`、`TestReadStateRejectsInvalidInput` 检查 sealed memfd，`TestSignalsStopDrainsQueuedSIGTERM` 检查停止信号屏障。`TestDrainChildren` 和 `TestChildrenAcrossThreads` 覆盖子进程清理与多线程后代发现。daemon 的 `TestReadReplacementRejectsInvalidState`、`TestStartupRejectsInvalidInheritedDescriptors` 检查内部入口拒绝非法身份、期限和 FD；`TestStopReplacementCandidate` 检查先撤销 PID 豁免再回收、撤销失败保留 PID。内核 `TestReplacementPIDRevokedOnExit` 验证 daemon 或 candidate 退出也会清除临时豁免且不削弱 `STOPPING`，无关进程退出不撤销它。

`TestPreparedInputsRebuildWithoutLiveSources` 在无 root 的跨层路径中录制配置、本地订阅、成功/失败远端订阅和模块；删除配置/本地源并关闭服务器后，经 sealed memfd 解码回放得到相同节点，三个原始请求不增加，且不构造活插件。`TestUserspacePreparationCompilesStaticPlanBeforeInstances` 检查无业务 BPF 时已应用完整静态路由，`TestInputs*` 检查 byte/group/codec 的严格失败语义；config、assets、geodata、routing 和 subscription 包另行覆盖 include/glob 选择、位置及普通/兼容 dat、MMDB、权限/symlink 安全检查和 missing/超限。pluginhost 测试覆盖 Factory 前完整声明、顺序、ctx 所有权、缺声明拒绝与失败释放。

`TestHostIdentityPrecedesBusinessMaps` 需要 root，检查正式装配先仅加载 socket-owner hooks/map，真实 socket 在业务 BPF 创建前已有 kernel TGID，后续业务加载复用同一 map 并释放临时 FD。`TestPreparationConnectivityProjectsOriginalFallbackLease` 检查用户态保存 lease 而不提前发行 token，绑定后投影仍对应原 lease；它也需要内核 map 权限。

在使用 systemd 的测试机上，可单独验证真实 exec 原语的服务管理行为，不挂载 BPF：

```sh
go test -c -o /tmp/dae-handoff.test ./internal/handoff
sudo python3 -I scripts/test-exec-systemd.py /tmp/dae-handoff.test
```

此夹具只创建唯一命名的临时单元，覆盖 `Type=simple` 和 `Type=notify`，均使用 `NotifyAccess=main / Restart=no / KillMode=control-group`。它检查单进程连续 exec 的 MainPID/starttime 恒定、不同 ELF 与同 ELF 强制 exec 的代际证据、环境/参数保持、旧子进程回收、FD 不随代数增长、RELOADING → READY、正常 stop 成功，以及 SIGKILL 后单元 `Result=signal`。输出该最小夹具的 RSS 和一秒空闲 CPU ticks，不代表完整 daemon 的内存或转发成本。退出时停止并清理测试单元，不操作既有 dae 服务。

构建后，用标准库编写的本地夹具验证真实业务交接：

```sh
make
sudo python3 -I scripts/test-process-replacement.py "$PWD/dae"
sudo python3 -I scripts/test-process-replacement.py "$PWD/dae" --wan
```

夹具在独立 PID、网络和挂载命名空间中运行，并挂载私有 `/run` 与 bpffs。它创建本地 DNS、订阅服务器和 LAN 客户端，检查只有一个常驻 dae 业务进程、同内容普通 reload 不换代、不同内容且同版本字符串的替换、同 ELF 强制替换、多次 exec 的 PID/starttime 恒定及 `/proc/<pid>/exe` 身份，并以 API `StartedAt` 和启动日志证明新运行时代际。还检查预检拒绝后旧 API/流量继续、空闲 TCP 客户端无需发送即收到 RST、固定网络对象身份、API/metrics/pprof 监听器复用及端口变更、旧端口关闭、重复替换 FD 稳定，以及连续 SIGKILL 后冷启动恢复。

未缓存订阅使用受控本地服务器，将下载等待窗口保持在 Block 前：此时不应出现本次替换的 guard，旧 API 与捕获流量继续服务，共享导出不变。输入准备后修改或删除配置/include 与本地源，并关闭远端服务器，要求正式 exec 仍使用接受的输入，不重新发现文件或产生额外请求。Block 的验证另行进行：guard 存在时捕获 DNS 必须被阻断且没有意外直出，共享导出尚未提交；成功提交后检查新运行时发布自身的 nft 目标。Block 期间 API 可能返回 503，也可能因仅保留监听 FD 而超时/断连，不能要求 operation 查询整个切换期可用。配置内端口重叠必须在 Block 前失败；坏 settings 和外部进程占用端口的用例必须在 Block 后失败，保留固定对象、旧导出和 guard；修复后通过正常冷启动恢复，原 operation 失败。需要 root、Python 3.12+、iproute2、nftables 和 `util-linux`，不访问外网。夹具仅在自己的 host namespace 中添加最小 nft CT state 引用以启用连接跟踪，不改变宿主防火墙。

`--wan` 额外创建私有 `wan0` veth 和 `upstream` 网络命名空间，将 HTTP 订阅服务器放在真实 WAN 对端，而不是依靠 loopback 绕过捕获。夹具使用随机 URL，先确认没有可用订阅缓存，核对接受响应的 URL 和正文，确认目标在 Block 前完成未缓存 WAN 预取；输入准备后关闭服务器，正式 exec 不得再发请求。到相同目标的普通其他 PID 请求在运行期、预取等待期、Block 期间及接管后都必须被显式 block 规则拒绝；daemon 身份通路不能扩大为其他进程的豁免。两种模式均只使用本地隔离网络，不访问外网。

内存按整个 daemon 进程树读取 `/proc/<pid>/smaps_rollup`，汇总 PSS 与 `Private_Clean + Private_Dirty`，分别记录稳定态和以 20 ms 间隔采样的替换峰值；包括临时预检和插件后代，而非只比较主 PID 的 RSS。采样峰值仍可能漏掉更短的瞬态，须同时报告采样间隔、进程数、配置/资源缓存状态及工具链。替换日志 `Replacement inputs prepared` 的 `duration` 从父进程开始预取计时，直到收到并验证封印包、撤销豁免并完成 `Wait`，`bytes` 是该输入包大小；此 duration 包含目标启动、探测、读取/下载、校验、用户态准备、封印及清理，不是纯磁盘/网络或本地构造耗时。`Replacement datapath ready` 的 `cutover` 字段给出最终描述封印 → 数据面 ready 的交割耗时，包含 API 排空、Block、旧业务关闭及 exec 后初始化，并非纯流量阻断时间；脚本分别输出 `preparation_ms`、`cutover_ms`，连续 DNS 的最大到达间隔另行报告，三者不能混用；DNS 间隔还包含调度、客户端超时和连接重建，跨故障恢复的总间隔也不能当作单次成功切换耗时。不要将最小 exec 夹具的 RSS、单独 BPF map 测量或某个旧进程的 RSS 当作完整替换的内存收益。

`TestReplacementBlockAndIdleResetKernel` 在 Netkit/veth、LAN/WAN、IPv4/IPv6 组合下验证生产 BPF 程序：旧入口阻断捕获流量，旧空闲 TCP 和 backlog 通过未修改的回程收到 RST；随后安装新下游和位于旧入口之后的新 TCX 程序，解除防护后新 TCP/UDP 恢复。设置 `DAE_TEST_ISOLATED=1`，并使用独立 PID、网络、挂载 namespace 和私有 bpffs。

`TestHostConntrackIntegration` 在测试自己的网络 namespace 中完成真实 IPv4/IPv6 回环 UDP 往返，再用未挂载的 BPF probe 检查 ORIGINAL/REPLY；分别覆盖启用跟踪、未启用、NOTRACK 和非默认 zone。生产预检只查询实际服务 namespace 的能力，不添加防火墙规则、不挂接 loopback TC，也不清空 CT；缺少必要能力时冷启动或候选准备失败。测试夹具在私有 namespace 中明确启用 CT，不能跳过生产检查来获得启动成功。回环通过不保证接口专用 NOTRACK、自定义 zone 或未来规则变更的行为。

`control/kern/tests` 中的 `TestUDPForwardConntrackReplacement` 使用隔离的 router、LAN/WAN 端点和真实系统 CT，覆盖 IPv4/IPv6、无 NAT/SNAT 出站的 reply-first/client-first 顺序，以及无 NAT/DNAT 入站在替换后才发送第一份本地应答；它也检查同一 socket 访问其他远端仍执行新路由。`TestUDPInboundStateBehindRedirect` 覆盖 REDIRECT 后的入站应答方向。`TestUDPReplacementWithoutConntrack` 验证缺 CT 时不能凭私有状态缺失获得入站豁免，`TestUDPReplyMarkerWithoutConntrack` 验证内部回包标记不等同于方向证明；`TestUDPNotrackDoesNotExemptReplyAfterReplacement` 验证 NOTRACK 不能给替换后的回复授予豁免。

`TestUDPRelayDoesNotCreateInboundConntrack` 经生产 Netkit/veth 回程验证 LAN/WAN、IPv4/IPv6：只删除测试流自己的 host CT，再发送合成回复。WAN 无正确 REPLY 证据时必须丢弃迟到回复，不能反向创建 CT；LAN 直接回程无需 host CT。之后客户端下一包仍须被捕获。此测试同样要求 `DAE_TEST_ISOLATED=1` 及独立 PID、网络、挂载 namespace 和私有 bpffs，不可在真实服务 namespace 中运行。

daemon 的内核测试逐项使用新的测试进程及 namespace，不能在同一进程中复用已关闭的全局网络运行时。`TestReplacementFailureAfterBlockKernel` 和 `TestReplacementCloseFailureAfterBlockKernel` 运行目标测试 ELF 的真实 parser/plugin Preflight 与用户态输入准备，断言活插件构造、`Warm` 和 Worker 仍被推迟；在可控预检窗口检查旧 API 可用、新配置操作返回 409，以及预检拒绝/取消后旧服务和实例锁仍保留；描述编码超限也必须在 API 排空及 Block 前失败，旧 API、导出和 guards 不变。坏 settings 不阻止用户态预取；最终 API drain 后才返回 503。Block 后分别注入取消和 shared plugin state 关闭错误，检查不执行 exec、不发布新导出，旧 ipset/nft、固定对象和 pinned guard 保留。`TestReplacementGuardsKernel` 使用自编写的最小 BPF 程序和不同布局的 maps，注入部分附件安装失败，关闭进程持有的 FD 后检查阻断 pin 仍然存在；恢复启动必须覆盖所有旧 hook 才能解除防护。`TestReplacementGuardBundleKernel` 检查入口 link 与必要 timer maps 的成组引用、重复 pin 的身份校验、部分失败回滚及清理顺序。`TestFailedRecoveryDoesNotExpandGuardsKernel` 验证 A+B → 失败 A+C → A+B 不会被错误尝试留下的新防护阻挡。`TestStoppingEntryAndExit`、`TestStoppingUDPAndFragments` 验证退出标记不覆盖停机状态，单代 `STOPPING` 下拒绝捕获、不确定流量和非首分片，同时按本代证据放行明确直连；这些用例不证明新旧私有 guard 重叠时的直连连续性。恢复 `ONLINE` 后未知非 SYN 归为 native，新入站 TCP 回复保持可用。进程夹具持续发送捕获 DNS，并检查目标收到的来源，检测交接期间的意外直出。

通过 sealed exec state 校验恢复时，`Run` 不重复执行目标 ELF 已通过的 `CheckKernelFeatures`，但仍对重放出的配置执行插件 Configure/Preflight 并实际加载、验证业务 BPF；普通冷启动和失败后重启仍完整检查，settings/Registry 仍只在旧写者结束后的正式启动中读取，不引入内核能力缓存结构或配置。

`TestReplacementReadinessFailureKernel` 和 `TestReplacementReadinessCanceledKernel` 覆盖数据面已发布但固定对象仍被借用时的失败：READY 通知失败或启动取消必须在退出前重新阻断，保留固定对象和已发布集合；这是 `ONLINE` 后的失败处置，不是回滚旧进程或由 READY 确认的原子提交。原替换操作完成前仍拒绝新的配置操作。`TestReplacementReadinessSuccessKernel` 通过本地 Unix datagram 接收 READY，检查最终就绪成功才结束恢复保护、取得删除权。`TestReplacementClaimKeepsInterfaceFreezeUntilReady` 验证状态/拓扑校验失败保留 `privatePins` 与接口冻结，通知成功才释放；已提交运行时的冗余 bundle 清理失败则应告警而非令就绪失败，测试须将其与 fatal 的校验及旧 guard 撤除错误区分。随后正常关闭会删除已接管的固定网络对象、canonical pins 和 Unix socket。

`TestStartupStopBeforeRunKernel` 在 `OpenStartup` 后、进入 `Run` 前用阻塞 I/O 模拟不接受取消上下文的配置读取，发送 SIGTERM 后必须由 15 秒停机 watchdog 强制退出。Startup 在配置 I/O 前安装唯一的 `watchShutdown`，统一持有取消上下文和恢复期限；`Run` 复用该生命周期，不交接 watchdog，也不重置已开始的停止期限。此测试需 root、`DAE_TEST_ISOLATED=1`、独立 PID/网络/挂载 namespace 和私有 `/run`，不证明 ELF 加载或包初始化阶段可被 daemon watchdog 保护。

`TestStartupLifecycleBudget` 使用虚拟时间检查准备完成、进入 `Run` 前恢复超时、先收到停止信号及重复启动停机宽限；完成准备不能取消业务，重复停机不能延长期限。`TestStartupJoinsExpiredPreparation` 检查停止恢复计时器时必须等待已开始的取消回调，避免就绪后才收到过期取消。这些生命周期测试无需 root。

`TestReplacementSnapshotFileOwnership` 使用本地文件检查 FD 一次性移交、重复释放快照及仅关闭未移交 FD，无需 root。

`TestReplacementRetainsSocketIdentityHooksKernel` 检查旧 WAN socket-owner hooks 临时跨旧 Runtime 关闭保活，与新 `pidLinks` 和本代 `socket_owner_map` storage 分离；正式身份使用 `daemon_identity_map`，新正式启动向旧 guard 重新注册，退出 hook 注销实际退出身份且不覆盖 `STOPPING`，临时预检豁免独立使用 `replacement_pid_map`；通过真实 socket 对照 `KernelProcessID` 的 kernel TGID，覆盖 PID namespace 身份口径。导出 FD 经 `TakeFiles` 转移后，释放快照和关闭旧 Runtime 都不能关闭它们，新 Runtime 仍须能够导入；未移交的 FD 由快照释放。交换身份 hook FD 必须拒绝且不泄漏；取消或拓扑变化保留旧 hooks/guard，成功撤旧后仅新 hooks 继续记录 socket；真实 `PrepareKernel` 路径还检查 Registry 在附件安装前只恢复一次，且不提前启用持久化。`TestReplacementCommitCancellationWithoutHost` 检查没有 MITM host 时也不能忽略 Commit 取消，`TestReplacementRequiresPreparationBeforeCommit` 检查未准备或未暂存的运行时不能提交替换。

`TestReplacementCommitExportsFailureKernel` 的 `prepare` 子用例用不兼容 nft set 验证导出准备失败不消费待安装附件、不添加新 guard、不改变旧导出；`after-apply` 子用例在真实 ipset/nft 发布完成后令 `Host.Start` 失败；`partial-apply` 使用 nft 容量限制触发部分发布失败。两者检查保留已应用集合、保持 staged/guard 且清理临时备份，不恢复旧导出。此测试同样要求 root、`DAE_TEST_ISOLATED=1`、独立 PID/网络/挂载 namespace，以及私有 `/run` 和 bpffs；普通配置 reload 的事务回滚另行保持原有回归。

`TestReplacementRestoresFinalRegistry` 验证新运行时读取旧写者关闭后的最终状态，保留恢复前的 journal 追加、压实和最终续期，使用新 matcher 投影，且后续正常追加不强制重建 baseline；`TestReplacementRegistryCloseBeforePersistence` 覆盖未 Restore 和 Restore 后未 Enable 的关闭不写回，包括完整 `.tmp` 与旧格式文件。`TestReplacementRegistryProjectionFailureKeepsStaged` 验证投影失败不启动插件、不启用持久化或解除 staging；`TestReplacementRegistryRejectsClosedPlane` 检查关闭屏障。`TestReplacementOpensFinalSettings` 检查候选首次 Open 取得旧写者最终的选择器、MITM 覆盖和客户端成员，且后续写入不擦除这些值；`TestReplacementRejectsInvalidInitialSettings` 检查损坏设置在首次 Open 即被拒绝。这些用例使用临时目录和内核 map 回调，可作为非特权定向回归运行：

```sh
go test -race -tags=netgo,osusergo,trace ./control \
  -run '^TestReplacement(OpensFinalSettings|RejectsInvalidInitialSettings|RestoresFinalRegistry|RegistryCloseBeforePersistence|RegistryProjectionFailureKeepsStaged|RegistryRejectsClosedPlane)$' -count=1
```

Surge 的 `TestRuntimePersistentStoreIsLazy` 逐阶段检查构造、`Warm`、不访问 store 的脚本及 `Close` 不加载内容或创建存储目录、JSON、`.lock`；`TestRuntimePersistentStoreSharedBeforeFirstAccess` 检查首次访问前的共享，以及关闭一个 runtime 不影响另一个。store 用例同时覆盖首次 read/write 前的外部原子替换、坏 JSON/FIFO 实际访问失败且可修复重试，以及既有跨进程合并、flock 和 gate 超时：

```sh
CGO_ENABLED=1 go test -race ./plugins/surge \
  -run '^(TestRuntimeStore|TestRuntimePersistentStore|TestRuntimeRetiredStoreIsReleased|TestConfiguredStore)' -count=1
```

QuickJS 和 Node 均运行该组；Node 在命令中加入 `-tags=surge_nodejs`，race 仍需 `CGO_ENABLED=1`，并沿用上文的 delegated cgroup 临时单元。

测量替换恢复成本时，区分首次 `Restore` 的耗时和现有 `cutover` 诊断；后者从最终描述封印前计至数据面 ready，包含封印与 API 排空，不等于纯 Block 时长。完整 Restore 包含校验重放、过期清理、规则匹配及 BPF 投影，不能用文件读取时间代替。比较 CT 方向查询成本时，保持规则、包序列、CPU、内核与工具链一致，结合内核 `bpf-ns/op` 和真实 UDP 转发延迟、吞吐测量；不能只比较 map 内存或不含 CT 的路由缓存命中基准。

`TestTCPProxyTupleKeepsAcceptedSocket` 和 `TestTCPSocketIndexLifecycle` 验证真实 accepted socket 的接收权及可选 SOCKHASH 索引生命周期；`TestTCPFlowEvictionKeepsConnection` 验证 LRU 属性淘汰不关闭真实连接。`TestPinnedMapABI`、`TestPinnedTCPFlowEncoding` 继续约束持久布局和令牌含义；`TestUDPRepliesReleaseRetiredTimerPrograms`、`TestGuardTimerMapReferences` 保留 UDP timer 退休与引用回归。TCP 不使用准入 HASH、FIN/ACK 关闭状态机或 timer takeover。
