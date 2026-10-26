# 插件 Prometheus 指标

通过现有进程级监听端口开启指标：

```text
global {
    metrics_port: 9091
}
```

采集地址为 `http://localhost:9091/metrics`，同时包含核心和活动插件指标。插件需已编译并启用。
所有插件指标都有 `plugin_type`、`plugin_instance` 标签，Prometheus 的 `instance` 标签仍表示采集目标。

插件准备期间指标不对外发布；准备失败保留当前实例指标。重载复用配置和资源未变的实例及其统计；重建实例时计数器及 Histogram 观测值从零开始。
关闭实例后移除其序列，`dae_plugin_instance_start_time_seconds` 表示实例激活时间。关闭或更改指标监听端口不会重置运行中插件的统计。
累计指标使用 `rate`、`increase` 查询以处理重置。

## 核心流量统计

`dae_process_connections_total{network}` 和 `dae_process_traffic_bytes_total{network,direction}`
保留进程生命周期累计值，与全局 status 的总量共用数据源。明细回收不会减少这些总量。
`dae_group_connections_total{outbound,network}` 和 `dae_group_traffic_bytes_total{outbound,network,direction}`
按出站组名称在进程生命周期内累计，包含已回收路径的总量，与 status 的组总量共用数据源；节点替换不会减少组总量。
组从配置中移除后序列消失，再次加入时从原累计值继续，包括移除期间排空的连接。

路径级连接、流量、拨号耗时和错误序列保留当前配置中的节点；移除路径在连接结束且最近一分钟历史过期后回收。
路径重新出现时明细从零开始，查询历史趋势使用 `rate` 或 `increase`。设备统计不作为 Prometheus 标签导出。
监听变更会先准备所需 socket；任一绑定失败时拒绝配置，保留现有服务。

## UDP 丢包

`dae_udp_packet_drops_total{direction,reason}` 是核心指标，名称不带 `dae_plugin_` 前缀。它由丢弃数据报的那一层计数，按进程生命周期累计，重载不清零；全部组合在首次丢包前即以 0 导出。
`direction` 为 `upload`（LAN 到外网）或 `download`。被告知丢包的调用方不重复计数。每个组合每分钟最多输出一条 Warn 日志；`route_missing`、`filtered`、`closed_stream` 属于正常运行中的丢弃，只计数不输出日志。

| `reason` | `direction` | 含义 |
| --- | --- | --- |
| `socket_overflow` | `upload` | tproxy UDP socket 接收队列溢出，随下一个入队的数据报上报 |
| `truncated` | `upload` | 截断的数据报 |
| `route_missing` | `upload` | 内核路由记录已不存在，或数据报排队期间其端点已移除 |
| `source_queue_full`、`task_limit`、`source_limit` | `upload` | 每源队列、全局任务数或积压源数已满 |
| `packet_memory_limit` | 两者 | 共享数据报内存已满 |
| `expired` | `upload` | 截止前未能发出，包括排队、建立、嗅探超时和阻塞写入；配置换代取消的数据报不计 |
| `setup_capacity`、`endpoint_limit` | `upload` | 并发建立的关联或 UDP 源端点数已满 |
| `packet_resource_limit` | `upload` | 无法打开 UDP 关联或 socket：进程级数据包资源数或单个源的 socket 数已满 |
| `dns_admission` | `upload` | 并发 DNS 查询数已满 |
| `mitm_bridge_full` | 两者 | MITM HTTP/3 桥队列已满 |
| `filtered` | 两者 | 按请求路由的 MITM 源发往其他目的地；改写目的地的 socket 收到非目标来源的回包 |
| `flow_queue_full`、`carrier_queue_full` | `upload` | smux 单流或单会话的数据报队列已满 |
| `socket_full` | `upload` | UDP socket 发送缓冲区已满：direct、Shadowsocks、SSR、SOCKS5、juicity 的 UDP 丢弃数据报而不等待 |
| `too_large` | `upload` | QUIC 数据报超过可发送的包大小 |
| `transport_receive_full` | `download` | hysteria2、TUIC、QUIC 的数据报接收队列或分片重组表已满 |
| `carrier_queue_full` | `download` | 端口跳跃的接收队列已满；队列中是承载 hysteria2 的 QUIC 包，QUIC 可能重传 |
| `closed_stream` | `download` | 回包所属的关联已被 dae 关闭或正在关闭。smux 为已被 dae 关闭的流收到的数据不计：会话已无法判断该流是否承载数据报 |
| `reply_queue_full` | `download` | 推送回包的积压队列已满 |
| `reply_socket_full` | `download` | 发往客户端的回包 socket 发送缓冲区已满：丢弃回包而不等待 |
| `reply_send_failed` | `download` | 回包发往客户端失败，例如无法建立回包 socket；关联继续 |

入口数据报在控制面转交、嗅探重放和 MITM 桥接中保留原始截止时间，不在每次入队时重新计时；过期包在转发或桥接交付前丢弃。这不为传输内部队列或内核队列规定送达期限。

共享的 8 MiB 数据包内存预算覆盖跨控制面代际的入口包、嗅探待发包、MITM 桥接队列和推送回包积压。移动已有包时连同分配和预算预留一起转交，不再复制整包。解析器私有重组数据、DNS 请求副本、传输内部缓冲、空闲池及内核缓冲另计。

## 插件指标名称

以下指标名称均省略 **`dae_plugin_`** 前缀。Histogram 包含 `_bucket`、`_sum`、`_count`，耗时单位为秒，内存单位为字节。
部分有界 Counter 标签组合在首次事件发生后出现。采集只读取内存状态，与日志级别无关。

## DNS 缓存

| 指标 | 类型 | 含义 |
| --- | --- | --- |
| `dns_cache_lookups_total{result}` | Counter | `hit`、`miss`、`bypass`，每次上游查询计一次 |
| `dns_cache_entries` | Gauge | 当前保留条目，包括等待过期清理的条目 |
| `dns_cache_capacity_entries` | Gauge | 条目上限 |
| `dns_cache_memory_bytes` | Gauge | 保守计账内存，不是 RSS |
| `dns_cache_memory_limit_bytes` | Gauge | 计账内存上限 |
| `dns_cache_evictions_total{reason}` | Counter | `expired`：过期；`capacity`：条目或内存容量淘汰 |

命中、未命中和容量统计与插件 status 共用状态。不支持构造缓存 key 的查询计为 `bypass`。
合法 key 无条目即为 `miss`，即使固定 TTL 为零或响应最终不可缓存。惰性过期与后台过期清理均计入 `expired`；同 key 替换不计为淘汰。

## DNS 路由

| 指标 | 类型 | 附加标签 |
| --- | --- | --- |
| `dns_router_requests_total` | Counter | `entrypoint`、`result` |
| `dns_router_request_duration_seconds` | Histogram | `entrypoint` |
| `dns_router_upstream_attempts_total` | Counter | `upstream`、`transport`、`purpose`、`result` |
| `dns_router_upstream_attempt_duration_seconds` | Histogram | `upstream`、`transport`、`purpose` |
| `dns_router_policy_decisions_total` | Counter | `stage`、`action`、`purpose` |
| `dns_router_family_suppressions_total` | Counter | 被抑制的 `family`：`ipv4`、`ipv6` |

- `entrypoint`：`middleware` 或跨插件显式调用的 `resolver`。完整调用耗时包含下游处理和辅助任务收尾。
- 请求 `result`：`success`、`bypass`、`error`、`timeout`、`canceled`。`success` 表示未返回错误，包含 DNS 错误响应码及策略拒绝。
  不支持的查询、前序插件已指定服务器的查询绕过路由策略；下游返回错误时按错误分类。
- `upstream` 使用配置 tag；动态指定服务器统一归入 `explicit`。`transport` 为 `udp`、`tcp`、`tls`、`https`、`quic`、`h3`。
- `purpose`：`query`、`probe`、`explicit`。地址族探测不重复增加客户端调用数；多服务器竞速只算一次 resolver 调用，每个服务器的传输分别计数。
- 上游尝试 `result` 额外支持 `truncated`。地址回退、UDP/TCP 回退各自计数，竞速中取消的其他尝试计为 `canceled`。
  一次尝试对应一次 `transport.Exchange`，包含其内部 TCP 重连。上游主机名解析位于尝试之外，其失败仍影响请求结果。
  独立调用无实例归属的 `Exchange` 辅助函数不产生插件指标。
- 策略 `stage` 为 `request` 或 `response`；请求动作是 `asis`、`upstream`、`reject`，响应动作是 `accept`、`reject`、`reroute`。
  策略指标通过 `purpose` 区分主查询和探测。

## Surge

| 指标 | 类型 | 含义 |
| --- | --- | --- |
| `surge_modules` | Gauge | 已加载模块数 |
| `surge_rules{kind}` | Gauge | 各类已加载规则数 |
| `surge_scripts_total{phase,result}` | Counter | 匹配脚本的处理结果 |
| `surge_script_duration_seconds{phase}` | Histogram | 实际 Runtime 执行耗时 |
| `surge_execution_wait_duration_seconds{kind}` | Histogram | 获取执行槽位的等待，包含失败等待 |
| `surge_execution_slots_in_use` | Gauge | 已占用槽位，包括正文处理与 DNS 脚本后续解析 |
| `surge_execution_slots_limit` | Gauge | 共享槽位上限 |
| `surge_rule_matches_total{kind}` | Counter | HTTP 改写、Map Local、DNS Host 命中 |
| `surge_processing_skips_total{stage,reason}` | Counter | 跳过脚本或改写操作的有界原因分类 |
| `surge_runtime_info{backend}` | Gauge | 编译时选择的后端：`quickjs` 或 `nodejs`，值为 1 |
| `surge_nodejs_workers{state}` | Gauge | 按 `active`、`idle` 区分的工作进程数 |
| `surge_nodejs_worker_limit` | Gauge | 当前实例的工作进程上限 |
| `surge_nodejs_worker_starts_total` | Counter | 成功启动的应用工作进程数 |
| `surge_nodejs_worker_start_failures_total` | Counter | 应用工作进程启动失败次数 |
| `surge_nodejs_worker_reuses_total` | Counter | 从空闲池取得工作进程的次数 |
| `surge_nodejs_worker_retirements_total{reason}` | Counter | 回收原因：`idle` 或 `failed`，后者包含取消 |
| `surge_nodejs_cgroup_memory_bytes` | Gauge | 缓存的进程池 `memory.current`，包含内核计账，不等同于 RSS/PSS |
| `surge_nodejs_cgroup_memory_peak_bytes` | Gauge | 内核记录的进程池 `memory.peak` |
| `surge_nodejs_cgroup_memory_limit_bytes` | Gauge | 进程池的 `memory.max` |
| `surge_nodejs_cgroup_oom_kills_total` | Counter | 进程池及工作进程的内核 `memory.events` 中 `oom_kill` 计数；包含祖先组或宿主 OOM 的受害者，不等同于工作进程超限次数或回收次数 |
| `surge_nodejs_cgroup_sample_timestamp_seconds` | Gauge | 最近一次成功的 cgroup 采样时间，不可用时为 0 |
| `surge_nodejs_idle_timeout_seconds` | Gauge | 多余空闲工作进程的回收超时 |
| `surge_nodejs_rss_bytes` | Gauge | 已采样工作进程的 RSS 之和，共享页可能重复计数 |
| `surge_nodejs_pss_bytes` | Gauge | 已采样工作进程的 PSS 之和，按比例分摊共享页 |
| `surge_nodejs_memory_sampled_workers` | Gauge | 当前纳入内存汇总的工作进程数 |
| `surge_nodejs_memory_sample_timestamp_seconds` | Gauge | 汇总所含最旧样本的时间，无样本时为 0 |

Node.js 指标仅在 Node.js 构建中提供。每个活动工作进程属于一次调用，等待宿主 HTTP 或定时器时仍属于活动状态。含脚本的实例在准备阶段预热一个工作进程，计入应用启动次数；后续按需扩容。维护任务每 5 秒检查一次，回收空闲满 60 秒的多余进程，保留最近归还的一个空闲进程。空闲回收不会终止正在执行的调用。预检使用一次性进程池，不计入应用启动或回收次数；实例关闭也不计为回收。没有脚本的实例不创建运行时工作进程。

后台每 5 秒从 Linux `smaps_rollup` 采样内存；metrics 和状态查询只读取缓存值。应将已采样进程数与活动、空闲进程总数比较，并结合样本时间判断覆盖率和时效。新进程或无法读取的进程不计入汇总；没有样本不代表运行中的进程不占内存。RSS/PSS 包含的范围大于 `memory_limit` 限制的 V8 老生代堆。

`dae plugins surge status` 和 `dae plugins status --verbose` 展示同一底层统计提供的进程池计数、内存汇总、覆盖率及样本年龄。`dae status` 与 `dae status --recent` 展示核心状态，不展开插件运行时报告。`/api/status` 和 `dae status --json` 在各 Surge 报告的 `runtimes` 字段中保留这些值，插件 JSON 命令也包含它们。QuickJS 只报告后端，不提供 Node.js 进程指标。

脚本 `phase` 为 `http-request`、`http-response`、`dns`、`cron`、`generic`；槽位等待的 `kind` 额外包含 `body_rewrite`。
脚本结果为 `unchanged`、`success`、`synthetic`、`abort`、`failed`、`skipped`。
运行耗时不包含执行前跳过、槽位等待、正文缓冲及应用脚本结果。HTTP 脚本失败后继续转发原文仍计为脚本失败；DNS 脚本成功返回服务器后发生的下游解析失败不计为脚本失败。

Cron 与 generic 任务共用执行槽位。在预算内未取得槽位的任务计为跳过；已有调用尚未结束时到达的定时触发增加 `surge_processing_skips_total{stage="cron",reason="overlap"}`，不会另起调用。任务成功表示运行时正常完成，不代表业务逻辑成功。

规则数量包含 `script`、`url_rewrite`、`header_rewrite`、`body_rewrite`、`map_local`、`dns_host`、`destination`、`route`。
命中数只覆盖实际执行的 HTTP/DNS 匹配，DNS alias 每一跳单独计数；匹配不一定导致修改。
跳过阶段为脚本阶段、`body_rewrite`、`map_local`；原因包括 `body_limit`、`buffer_memory_limit`、`timeout`、`canceled`、`read_failed`、`decode_failed`、`error` 等固定分类。
正文准备失败按一次处理计数，单条正文规则失败则分别计数。

## PromQL 示例

可缓存查询的命中率：

```promql
sum by (instance, plugin_instance) (
  rate(dae_plugin_dns_cache_lookups_total{result="hit"}[5m])
)
/
sum by (instance, plugin_instance) (
  rate(dae_plugin_dns_cache_lookups_total{result=~"hit|miss"}[5m])
)
```

主查询上游尝试耗时 P95：

```promql
histogram_quantile(0.95,
  sum by (instance, plugin_instance, upstream, transport, le) (
    rate(dae_plugin_dns_router_upstream_attempt_duration_seconds_bucket{purpose="query"}[5m])
  )
)
```

脚本失败速率，包含失败后继续转发的情况：

```promql
sum by (instance, plugin_instance, phase) (
  rate(dae_plugin_surge_scripts_total{result="failed"}[5m])
)
```

插件开发接入方式见 [Prometheus API](../../../component/plugin/README.md#prometheus-metrics)。
