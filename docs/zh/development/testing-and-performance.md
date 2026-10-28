# 测试与性能测量

进入 `nix-shell` 或 direnv 开发环境。若没有本地 `plugins.cfg`，先复制 `plugins.cfg.example`；取消本地配置中 DNS cache 和 router 条目的注释，以验证全部自有插件的编译选择。从仓库根目录运行：

```sh
make test
make test SURGE_RUNTIME=nodejs
make client-test
make config-parser-check
make -C web test
```

根测试覆盖核心、`pkg/outbound`、配置解析器和全部自有插件，包括 DNS cache、Surge 与 router 的组合用例。`make test` 同时检查协议库和宿主的依赖方向；`make client-test` 检查无 CGO 的 API/CLI 边界。第三方 fork 保持独立模块，使用单独的测试命令：

```sh
go test -race github.com/buke/quickjs-go/...
(cd third_party/quic-go && GOWORK=off go test -race . ./http3)
```

Web 测试使用本地最小夹具和已安装的 Chromium；可用 `CHROMIUM` 指定浏览器路径，`openssl` 和 NSS `certutil` 须位于 PATH。证书测试使用临时 HOME、浏览器配置和 NSS 信任库，不修改现有信任设置；不使用忽略 TLS 错误的启动参数。额外的 `pnpm --dir web run test:certificate` 需要 Go 工具链，单独运行生产 Go API、CSP 与浏览器请求函数的集成检查，覆盖安装 CA、未安装 CA、手动接受 HTTPS 警告，以及 HTTP/HTTPS 页面。除 IPv4/IPv6 回环地址外，存在私有 IPv4 网卡时也从该地址测试普通 LAN HTTP；没有该网卡时明确报告跳过。普通 Go 测试不替代需要 root 的 `make ebpf-test`。

## 固定内核状态

跨进程保留的表为 `tcp_flow_map`（LRU hash，40 字节键、16 字节值）和 `cookie_pid_map`（socket-local storage，4 字节键、20 字节值）。daemon 重启按表比较类型、键值大小、容量和 flags；匹配的 pin 及其内容直接复用，仅删除并重建明确不兼容的 pin。程序或非固定表的变化不会使这些 pin 失效。同进程 reload 使用 Runtime 的共享表。

固定表的字节布局及含义是稳定约定。TCP 流值的 `route_epoch` 位于偏移 0，`mark` 位于 8，`owner` 位于 12；owner 为 0 表示直通，1 表示用户态代理，其余值为 fallback 令牌。Socket 归属值的 `pid` 位于偏移 0，16 字节 `pname` 位于 4。运行时的 map 元数据比较无法识别字段改名或数值含义变化；`TestPinnedMapABI` 独立于生成类型锁定布局与保留值，不应仅为通过测试而改写不兼容变更的预期。容量仍可在构建时指定；容量不匹配只替换对应的表。

`TestRemoveIncompatiblePinnedMaps` 验证选择性替换及保留表的 ID、内容；`TestPinnedTCPFlowEncoding` 使用固定字节夹具验证直连 mark、代理 ACK/RST 和令牌边界。前者在 root control 测试中运行，后者在内核测试中运行；均使用隔离表，不接触正在运行的 daemon 的 pin。保留内核状态不等于保留跨 daemon 进程替换的用户态 relay socket。Fallback lease 属于单个进程，因此携带令牌的 fallback 流可能随重启结束；不兼容的表也会丢失其自身状态。

## 性能测量

`scripts/runtime-ablation.py` 在临时副本和独立网络命名空间中执行 reload 消融：可通过 `--baseline` 传入源代码快照，对比接入循环额外复制的监听 FD 数量及配置发布开销；`extra-fds` 不含各版本都需要的原始 TCP/UDP 监听 socket 和 map 描述符。逐项移除代际、SYN、长期 TCP 状态、过期、消费、策略归属与关闭屏障，要求相应行为断言失败。日志、固定 CPU 的交错重复样本和统计保存在输出目录。运行前生成生产及内核测试 BPF 对象，需要 Go、Clang 和免密 sudo。

`control/kern/tests` 的 C 用例各自加载独立 maps，避免前一个用例的路由、域名或连通性状态掩盖错误。Go 的捕获与缓存回归直接检查内核返回值和交接状态，不能仅以最终出站名为 direct 证明内核直通。

内核 fixture 构造集中在 `routing_test_helpers_test.go`，功能回归在 `routing_flow_test.go`，计时循环在 `routing_flow_benchmark_test.go`。`make ebpf-lint` 同时检查本项目的内核 C 文件和路由头文件。

`BenchmarkRoutingFlow` 覆盖域名映射缺失、空位图、AND/OR 短路及普通顺序扫描。`BenchmarkRoutingLPM` 覆盖目的 IP、源 IP、MAC 的单次和连续查询，用未命中的路由规则和连续命中的 AND 链分别测量两条路径，单条命中规则直接结束路由；计时前验证实际命中结果，避免意外短路掩盖查询成本。`BenchmarkRoutingConditionalBlock` 比较逐条条件与共享条件块，`BenchmarkHTTPClientAdmission` 比较 HTTP 准入允许和拒绝路径。比较包处理性能时使用 `bpf-ns/op` 指标；`ns/op` 包含批量调用开销。`BenchmarkUDPRoutingCache` 分开测冷路由与缓存命中。生成内核测试后可运行：

```sh
go test -c -tags dae_bpf_tests -o /tmp/dae-kernel.test ./control/kern/tests
sudo /tmp/dae-kernel.test -test.run '^$' -test.bench 'Benchmark(RoutingFlow|RoutingLPM|RoutingConditionalBlock|HTTPClientAdmission|UDPRoutingCache)' -test.benchtime 30x -test.count 3
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

客户端的 UDP 流跳过关联建立，直接在 mux 上打开 UDP 关联，因此建立过程交给拨号的上下文（例如嗅探出的协议）不会传入；`QEXP_UDP=direct` 时每条 UDP 流改用 direct 出站自己的 socket，如 direct 与 Shadowsocks UDP。设置 `LAN_RATE` 时，回包像 dae 发出的一样，经绑定回包来源地址的透明 socket 发往客户端命名空间 lo 上的 LAN 主机地址 192.168.77.10，lo 用 tbf 限速，队列大于 socket 发送缓冲区，因此先满的是回包 socket；负载停止后 tbf 改为不限速而不删除，以免丢弃排队的回包，最终计数得以送达。未设置时测试直接从端点接收回包。客户端命名空间的 UDP socket 错误计数写入 `LABEL.client.nstat`。写者自旋变体用包装连接给承载写入加延迟，包装连接须向承载路径的每一种 socket 查找暴露原生 socket（读方向由 `ReadPassthrough` 暴露，写方向由 `WriteThrough` 暴露），否则测到的是失去 socket 的承载，而不是忙碌的写者。

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
