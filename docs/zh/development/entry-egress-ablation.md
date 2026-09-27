# 入口 mark / 接口 / 双栈发现消融实验

日期：2026-09-27。

## 方法

使用 `scripts/entry-egress-ablation.py` 生成 **Go overlay**，每次只移除一个条件；源文件和生产配置中不加入实验开关。消融版本必须触发指定断言，编译失败、权限不足、测试跳过均不算成功检出。

环境：Go 1.27.1、Linux 7.2.7、AMD Ryzen 9 9950X，`GOMAXPROCS=4`。性能数据为 5 轮中位数，每轮交替执行版本顺序，`benchtime=100ms`。

三类负载分别验证：

- **CPU**：发现函数立即返回，用于观察路径展开、去重和分配开销。
- **受控延迟**：每次发现等待 1ms，用于观察并发上限；这不是互联网 DNS 延迟测量。
- **真实本地 DNS**：独立的 loopback DNS 服务返回 A 记录，实际查询内核路由和源地址；查询计数包含 A/AAAA 请求。

## 正确性消融

完整版本通过全部验证；以下 10 个删减版本均被指定断言检出。

| 移除或放宽的条件 | 检出的错误 |
| --- | --- |
| 为域名默认补齐双栈地址 | 仅 A 记录也生成 IPv6 候选 |
| 本地地址族可用性检查 | IPv4-only 本机/接口出现 IPv6 候选 |
| 路由查询中的绑定接口 | 借用另一接口的 IPv6 路由 |
| 路由查询中的 mark | 忽略 mark 命中的 prohibit 规则 |
| 源地址归属/有效性检查 | 有 IPv6 路由但无本接口 IPv6 源地址时仍生成候选 |
| 去重键中的接口 | 不同接口错误共享发现结果 |
| 去重键中的 mark | 不同 mark（含显式零与继承）错误共享结果 |
| 双栈显示条件 | 单栈节点重新出现 IPv4/IPv6 标签 |
| socket 的 SO_MARK | 实际 socket mark 与配置不符 |
| socket 的 SO_BINDTODEVICE | 实际 socket 未绑定配置接口 |

接口和 mark 测试在独立 network namespace 中配置 dummy 接口、地址、路由和策略规则；socket 测试使用 `getsockopt`，不是仅检查配置字段。

## 性能结果与取舍

### 保留的机制

| 实验 | 完整版本 | 消融版本 | 结论 |
| --- | --- | --- | --- |
| 去重：128 路径复用 16 入口，真实 DNS | 16 次发现、32 次 DNS 查询、330µs | 128 次发现、256 次查询、2137µs | 保留按入口+mark+接口去重 |
| 并发：128 独立入口，每次等待 1ms | 16.95ms，峰值 8 | 串行 134.86ms，峰值 1 | 保留有界并发 |
| 并发：32 独立入口，真实 DNS | 599µs，峰值 8 | 无界 720µs，峰值 32 | 无界并发未改善此负载，保留上限 8 |
| 缓存字面量地址族：1024 路径复用 32 入口 | 55.85µs，1119 次分配 | 89.36µs，2111 次分配 | 每个唯一入口解析一次 |

无界并发在 1ms 等待模型中能将 128 入口缩短到 1.19ms，但峰值同时工作数升至 128；该结果不能当作真实 DNS 性能收益。8 是本实现的资源边界，不声称对所有 DNS 服务都是最优并发数。

### 整理前后

| 负载 | 整理前 | 整理后 | 耗时变化 |
| --- | --- | --- | --- |
| CPU：1024 路径 / 32 入口 | 105.13µs | 55.85µs | -46.9% |
| CPU：256 路径 / 256 入口 | 109.44µs | 59.55µs | -45.6% |
| DNS：128 路径 / 16 入口 | 360.62µs | 330.30µs | -8.4% |
| DNS：32 路径 / 32 入口 | 670.20µs | 599.01µs | -10.6% |

重复入口 CPU 场景的分配次数从 **2163 降至 1119（-48.3%）**，分配字节从 **179637 降至 112407（-37.4%）**。独立入口场景的字节数略增约 0.9%，分配次数减少约 37.9%。真实 DNS 耗时存在环境波动，应结合操作数和分配指标判断，不能外推为代理转发吞吐量提升。

## 代码整理

- 配置解析保留在 `egress.go`；发现、去重、并发与展开集中到 `entry_discovery.go`；内核路由/源地址检查位于 `entry_families.go`。
- 使用固定数量的 worker 和 Go 1.27 支持的 `WaitGroup.Go`，替代为每个入口创建 goroutine 的 `errgroup`。保持声明顺序输出及有界 DNS 压力。
- 每个唯一入口只解析一次字面量地址族，预分配输出切片；保留 mark/interface 的隔离条件。
- 补充取消前及取消中的检查，避免继续提交排队工作；失败日志按入口声明顺序输出。
- 修复 IPv6 数字 zone（例如 `%3`）与接口名比较导致的误判，并测试 zone 与绑定接口冲突。
- 通过完整路径构造验证：单栈无 IPvX 标签、双栈有标签、增加另一栈不会改变原有候选 ID。

## 复现

```sh
python3 scripts/entry-egress-ablation.py
# 比较之前保存的 component/outbound 快照：
python3 scripts/entry-egress-ablation.py --baseline-source /path/to/before
```

脚本将 overlay、测试二进制、逐轮输出、源文件 SHA-256 和 `summary.json` 写入 `/tmp/opencode/entry-egress-ablation-*`。本次原始结果位于 `/tmp/opencode/entry-egress-ablation.fGiCQf/results`，整理前快照位于同级 `before`。

功能边界仍是：仅为 DNS 和本机/绑定接口共同支持的地址族创建候选，启动/reload 重新发现；单栈不显示 IPvX 标签。健康检查负责已有候选的后续连通性。

## 最终验证

- `go test ./...`、相关包的 `go test -race` 与 `go vet` 通过。
- `make` 通过，已重建 `./dae`。
- 特权 socket/netns 检查通过；实际 eBPF 回归覆盖 SSH、无关 HTTPS、缺少 DNS 映射、目标捕获、mark、must 和 API 直通。

## 回环 DNS 修复的消融与精简

针对“默认出口 v4/v6 + `cu` 出口 v4”缺少第三个候选的问题，新增独立的 `loopback-dns` 实验集。使用整个子进程独占的 network namespace，使 DNS goroutine 和发现 worker 看到相同的接口、路由；真实 DNS 服务返回双栈地址并强制 UDP → TCP 重试。运行时检查实际 socket 的 `SO_MARK`、`SO_BINDTODEVICE`，并验证三个候选的名称、独立 ID 和 `priority: 1`。

实验覆盖系统 DNS 回调与显式 DNS 覆盖、原生 IPv4/IPv6 与 IPv4-mapped IPv6 回环地址、公网/私网 DNS，以及 mark 继承、显式零和覆盖值。每个删减版本均要求命中指定功能断言，编译失败、跳过或单纯进程超时不算检出。

精简依据：

- `net.Resolver.Dial` 的标准库契约保证地址为 IP 字面量与数字端口，因此删去解析成功的重复条件。
- `netip.Addr.IsLoopback()` 已处理 IPv4-mapped IPv6，删去前置 `Unmap()`。
- 每个入口的 bootstrap resolver 是启动/reload 时创建的配置快照，直接构造一个 `net.Resolver`；移除原先附带的可变 policy、原子读、第二个 resolver 与每次拨号的覆盖检查。显式 DNS 地址在构造时规范化。
- 测试中的期望 mark 改为独立常量；接口建链改为表驱动，每个接口只执行一次 `LinkSetUp`，路由地址族由目的前缀推导。

复现：

```sh
python3 scripts/entry-egress-ablation.py --suite loopback-dns --benchtime 200ms --rounds 5
```

其中 `before-cleanup` 恢复整理前的解析检查、`Unmap()` 和可变 resolver；`redundant-parse-guard`、`redundant-unmap`、`mutable-bootstrap` 分别恢复其中一项。性能基准只测量入口 resolver 构造，不包含 DNS 查询或代理转发。

### 实验结果

完整版本与四个等价对照均通过；以下 **7 项行为消融全部检出**：

| 消融 | 指定断言检出的错误 |
| --- | --- |
| 去掉回环 DNS 例外 | 绑定 `cu` 后本机 DNS 超时，无法生成三个候选 |
| 本机 DNS 不设置 mark | socket mark 为零，未继承 `0x100` |
| 外部 DNS 不绑定接口 | socket 的绑定设备为空，而非 `cu` |
| 仅 UDP 使用回环例外 | DNS 截断后的 TCP 重试失败，候选发现失败 |
| 私网 DNS 也豁免接口绑定 | `192.168.1.1` 的 socket 未绑定 `cu` |
| 只识别原生 IPv4 回环 | IPv4-mapped IPv6/原生 IPv6 回环被错误绑定 |
| 根据配置字符串而非最终 DNS 地址判断 | 使用系统 DNS 时错误绑定回环地址 |

同机、`GOMAXPROCS=4`，5 轮交替顺序、每项 `200ms`，中位数如下：

| resolver 构造场景 | 耗时（前 → 后） | 分配次数（前 → 后） | 分配字节（前 → 后） |
| --- | --- | --- | --- |
| 系统 DNS | 156.0ns → 101.8ns（-34.7%） | 11 → 6 | 672 → 528 |
| 显式回环 DNS | 172.9ns → 144.9ns（-16.2%） | 12 → 9 | 688 → 592 |
| 显式外部 DNS | 175.4ns → 142.7ns（-18.6%） | 12 → 9 | 688 → 592 |

恢复可变 resolver 后，分配次数恢复为 11/12/12；恢复解析条件或 `Unmap()` 不影响分配次数。构造基准并不执行这两个回调内操作，不能用其耗时波动推断解析性能收益；删除它们的依据是标准库契约与等价回归验证。

原始结果：`/tmp/opencode/entry-egress-ablation-cud1gqlg/summary.json`。原有出口实验也重跑了全部 10 项功能消融，均检出，结果位于 `/tmp/opencode/entry-egress-ablation-0pw_3hnp/summary.json`。

本轮 `go test ./...`、相关 `go vet`、特权 socket/netns 的 race 测试及 `common/netutils`、`control` 的 race 测试均通过；`make` 通过并重建本地 `./dae`。
