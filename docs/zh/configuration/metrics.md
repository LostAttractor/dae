# 插件 Prometheus 指标

通过现有进程级监听端口开启指标：

```text
global {
    metrics_port: 9091
}
```

采集地址为 `http://localhost:9091/metrics`，同时包含核心和活动插件指标。插件需已编译并启用。
所有插件指标都有 `plugin_type`、`plugin_instance` 标签，Prometheus 的 `instance` 标签仍表示采集目标。

插件准备期间指标不对外发布；准备失败保留当前实例指标。成功重载会重建实例，计数器及 Histogram 观测值从零开始。
关闭实例后移除其序列，`dae_plugin_instance_start_time_seconds` 表示实例激活时间。关闭或更改指标监听端口不会重置运行中插件的统计。
累计指标使用 `rate`、`increase` 查询以处理重置。

以下指标名称均省略 **`dae_plugin_`** 前缀。Histogram 包含 `_bucket`、`_sum`、`_count`，耗时单位为秒，内存单位为字节。
部分有界 Counter 标签组合在首次事件发生后出现。采集只读取内存状态，与日志级别无关。

## DNS 缓存

| 指标 | 类型 | 含义 |
| --- | --- | --- |
| `dns_cache_lookups_total{result}` | Counter | `hit`、`miss`、`bypass` |
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

脚本 `phase` 为 `http-request`、`http-response`、`dns`；槽位等待的 `kind` 额外包含 `body_rewrite`。
脚本结果为 `unchanged`、`success`、`synthetic`、`abort`、`failed`、`skipped`。
运行耗时不包含执行前跳过、槽位等待、正文缓冲及应用脚本结果。HTTP 脚本失败后继续转发原文仍计为脚本失败；DNS 脚本成功返回服务器后发生的下游解析失败不计为脚本失败。

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
