# 测试与性能测量

`scripts/runtime-ablation.py` 在临时副本和独立网络命名空间中执行 reload 消融：可通过 `--baseline` 传入源代码快照，对比接入循环额外复制的监听 FD 数量及配置发布开销；`extra-fds` 不含各版本都需要的原始 TCP/UDP 监听 socket 和 map 描述符。逐项移除代际、SYN、长期 TCP 状态、过期、消费、策略归属与关闭屏障，要求相应行为断言失败。日志、固定 CPU 的交错重复样本和统计保存在输出目录。运行前生成生产及内核测试 BPF 对象，需要 Go、Clang 和免密 sudo。

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

`BenchmarkDomainRegistryCapacity` 使用一个内核槽位，分别测量已驻留 IP 续期和两个 IP 交替竞争槽位；固定操作数便于比较同一换入换出序列。`BenchmarkDomainRegistryFootprint` 测量上述夹具数据在临时构造对象回收后的常驻 Go 堆，单独以 `-benchtime=1x` 运行，读取 `retained-bytes`、`retained-objects`：

```sh
go test -tags=netgo,osusergo,trace,dae_splice ./control \
  -run '^$' -bench '^BenchmarkDomainRegistryCapacity$' -benchmem -benchtime=1024x -count=3
go test -tags=netgo,osusergo,trace,dae_splice ./control \
  -run '^$' -bench '^BenchmarkDomainRegistryFootprint$' -benchtime=1x -count=5
```

`BenchmarkDomainActivityBatch` 使用同一夹具数据，模拟 64 个连接对共享 IP 的重复 I/O；每 1,024 次观察应用一次批次，计时包含应用成本。`BenchmarkDomainActivityIOContention` 运行真实后台循环，并在计时结束前通过关闭应用最后一批；`p95-ns` / `p99-ns` 衡量前台观察回调耗时，状态实际可见时间还取决于批次应用。它是饱和负载，吞吐更高的实现也会产生更多排队竞争，不能直接把尾延迟当作固定流量下的网络延迟：

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
