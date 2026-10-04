# DNS 透传、映射保留与插件

dae 核心负责 **TCP/UDP 目标端口 53 的透明中继**，从成功交付给客户端的 DNS 应答中建立 domain↔IP 证据。`DomainRegistry` 用于域名验证、域名路由及 MITM/DNAT 捕获；完整 DNS 应答缓存和高级解析策略由可选插件负责。

## 透明 DNS 与系统解析

已绑定接口上的 TCP/UDP 53 自动进入 DNS 中继。核心按路由选择目标，不选择 DNS 上游、不重试查询、不切换协议，也不改写上游 TTL、AD、EDNS 或 TC。畸形报文仍透明转发，但不能生成解析证据。

显式 `block` 仍阻断 DNS；`must` 跳过自动 DNS 处理。管理 API 的精确 TCP 地址/端口保持内核直通。DNAT 在插件前执行一次，原目标端口为 53 的连接改到其他端口后仍作为 DNS：

```dae
rules {
    dip(192.0.2.53) && dport(53) -> dnat('198.51.100.53:1053')
}
```

回复使用客户端原本访问的服务器地址/端口。插件改选服务器后按新目标重新选路，保留原客户端、接口、进程和 routing profile。

TCP 使用 30 秒空闲期限，请求及已交付响应均会刷新，包括 AXFR/IXFR 的后续帧。上游关闭时先排空已接收响应，再关闭客户端连接。能够唯一关联的无 Question 错误响应会完成请求，但不生成证据。UDP 插件准入和本地回复同样检查设备路由 epoch 与取消状态，`route_change_behavior: close` 对缓存命中也生效。

dae 内部解析使用 Go 标准库。不配置 `global.dns_resolver` 时，沿用系统 `/etc/resolv.conf` 和 `/etc/hosts`，不要求安装 DNS 插件。Go 解析器使用带 mark 的套接字避免重新捕获，不模拟仅由 libc NSS 提供的名称源或 macOS split-DNS。

### 指定内部 DNS 服务器

```dae
global {
    dns_resolver: '1.1.1.1:53'
}
routing {
    dip(1.1.1.1) && dport(53) -> proxy
    fallback: direct
}
```

`proxy` 可替换为已有节点或出站组。地址支持 IPv4、IPv6 和可选端口，默认 53，例如 `1.1.1.1`、`2001:4860:4860::8888`、`[2001:4860:4860::8888]:53`。服务器必须是 IP 字面量；普通 UDP 查询及截断后的 TCP 重试由标准库处理，`/etc/hosts` 仍优先参与地址解析。

- **启动准备期间**：直接访问指定服务器，以完成订阅、节点检查和插件准备。
- **监听器就绪后**：内部 DNS 传输按当前目的地址规则、flow 和 routing 选路、拨号。使用 DNS 服务器的 IP/端口、实际 TCP/UDP 协议和 dae 进程身份；没有客户端来源或接口。可按需选择代理，保留 mark、DNAT、block 及配置的无连通性处理。查询名不作为该传输的路由域名。
- **节点地址引导**：代理链底层连接及 QUIC 节点地址解析使用独立的直连解析器，也使用指定服务器，避免“建立代理需要 DNS，而 DNS 又需要这个代理”的循环。该服务器需要在引导阶段直接可达。
- **重载**：候选准备期间继续使用当前解析配置；失败不切换。提交交接时切到新服务器的直连引导模式，新监听器就绪后接入新路由。已开始的拨号使用取得的旧策略快照。

这是内部解析服务器覆盖，不是失败后才启用的备用服务器。已就绪时的路由失败不会额外回退到系统 DNS 或绕过 block；未配置时仍使用标准库的系统解析路径。此设置不改变客户端 DNS 服务器，不经过客户端 DNS 插件链，也不向客户端域名证据 Registry 发布内部查询结果。客户端 DNS 策略由 `dns-router` 等插件处理。

## 保留窗口：策略假设，而非客户端缓存寿命

客户端可能忽略 TTL，或者把解析后的 IP 长时间保存在应用内部。TTL 到期无法证明客户端已经放弃映射。因此配置一个滑动保留窗口：

```dae
global {
    dns_retention_window: 168h
}
```

默认七天，必须是正时长。`dns_retention_window` 是 dae 的保留策略，不是测得的客户端缓存寿命，也不是记录的最长存活时间。TTL 更长时取 TTL，后续流量可以持续续期。

每个 `(domain, IP)` 记录保存绝对时间 `retain_until`。DNS 类型在接收证据时校验，不再单独保存，因为规范化后的 IP 已确定地址族。`Verify.Registered` 仍要求该域名在目标地址族中存在证据，`Verify.Paired` 则要求精确的域名—IP 对。令窗口为 `W`：

| 观察事件 | 更新公式 |
| --- | --- |
| 有效 DNS 应答成功交付客户端 | `max(retain_until, delivered_at + max(ttl, W))` |
| 实际连接/流量活动 | `max(retain_until, observed_at + W)` |
| GC | 删除已到 `retain_until` 的 pair，重算受影响 IP 并调整内核驻留集合 |

TTL 使用最终交付应答中的值；CNAME 别名使用从该别名到地址记录的解析链最短 TTL。重复观察只延长、不缩短期限。GC 在更新路径和周期检查中执行；周期为一分钟，静默记录的回收可能相应延迟。Registry 维护最早可能到期时间，在此之前跳过全表回收扫描。

用户态第一版没有内存或条目数上限。内核容量淘汰不删除用户态证据；时间 GC 会同时结束该 pair 的验证资格和内核贡献。`Verify` 是查询操作，本身不续期。已经收集删除的 pair 需要新的有效 DNS 观察才能恢复。

`retain_until` 是可回收时间，不是新的 DNS 信任有效期。活动在实际 GC 删除前到达时，仍可按公式续期已有记录。登记表跨客户端共享；任一客户端的活动都能续期对应 pair。

### DNS 证据的来源

只接受 ID、opcode、question 正确关联、完整成功的普通 IN A/AAAA 应答。沿有界、无环的可达 CNAME 链登记查询名及别名；无关记录、错误/TC 应答、畸形帧和非普通查询响应不生成证据。

按 RFC 2181，最高位为 1 的 TTL 在保留期限计算中视为零，包括 CNAME；透明转发的报文不作修改。

上游、本地合成及缓存回放均在**成功交付后**登记。缓存命中表示客户端刚收到一次新的应答，所以会刷新保留窗口；缓存自身的 TTL 递减和原始 `ReceivedAt` 不受影响。交付失败不生成 DNS 证据。

接收应答时保留 RRSIG 时间检查，但 dae 不验证 DNSSEC 签名。已接受的映射历史独立于签名有效期：签名到期不表示客户端已经忘记该 IP，延长历史保留也不表示签名仍有效。

### 实际流量续期

- sniff 到域名：只刷新该域名与**原始目标 IP** 的已有 pair。
- 未 sniff 到域名：刷新该 IP 的全部已有 pair。
- sniff 到域名但没有对应 pair：不创建证据，也不刷新该 IP 的其他域名。
- 使用客户端原始目标与嗅探名；插件改写的目标和 dae 自身的后台解析不代表客户端持有的映射。

覆盖 TCP/UDP 入口、持续用户态 I/O 和 MITM；已捕获 TCP 转入 sockmap/splice 后，利用现有连接字节计数的增长续期。计数轮询带来约一秒的观察粒度。空闲连接不续期；客户端已经发起访问这一事实不要求上游拨号最终成功。

连接入口、新 UDP 目标的首次活动和 DNS 证据登记同步完成；已有路由判定仍先于首次活动引起的容量晋升。持续 I/O 按 `(原始 IP, 规范化域名或空串)` 在一个队列中合并，每个键只保留最大的 `observed_at`。入队短暂持有队列锁，由同一个 Registry 后台循环每秒尝试应用。排队不改用处理时间续期，空闲批次不延长期限；splice 计数轮询后还需经过此批次应用。

GC、DNS 登记及快照复制先应用此前已入队的活动。消费者在队列锁内交换双缓冲，随后释放锁；这次交换是所有目标共同的观察边界，交换后的入队属于下一批。处理批次和写入内核时不持有队列锁，因此较早的未知 pair 活动不会在后续 DNS 登记后补做续期。状态查询和验证只读取已应用证据，不消费队列；持续活动引起的期限变化、容量晋升在应用批次后可见。同步操作可以提前应用，后台繁忙时则可能晚于下一次秒级检查。

普通连接跨 reload 存活时，活动句柄转交给新 Registry。旧 Registry 关闭时原子截取最后一批活动，按旧窗口应用后最终保存；关闭后交接队列中的活动使用新窗口，并在新 Registry 的 GC 前应用。续期取最大值，与重放顺序无关，因此不额外排序。修改窗口不在 reload 时统一重设既有截止时间；内核 bitmap 使用新规则生成。普通关闭后的新活动不再接收。

## 内核 AND/OR 表：完整 IP 状态的有容量子集

用户态以 domain–IP pair 为证据对象，域名索引和 IP 索引引用同一个 pair，`retain_until` 只保存一份。同一域名的全部地址共享一个 bitmap；IP 节点保存它的全部关联域名及聚合结果。具名续期直接查找 pair，无域名续期只访问该 IP 的关联域名。内核表每个 **IP 占一个槽位**，同一值中原子发布两个 bitmap：

```text
bump    = OR(这个 IP 的全部有效 pair 的 bitmap)
routing = AND(这个 IP 的全部有效 pair 的 bitmap)
priority = max(bitmap 非零的 pair 的 retain_until)
```

每一位对应域名条件，包括普通路由、MITM、DNAT、`bump` 和 `must` 中的域名条件。AND 命中表示已登记的所有域名都命中该条件；仅 OR 命中表示共享 IP 存在歧义，需要结合完整规则决定是否交给用户态。

**不能先删除全零 pair 再计算 AND。** 例如目标域名与无关域名共享 CDN IP：目标的位为 1、无关域名为 0，正确结果是 OR=1、AND=0。删除无关域名会错误地把该 IP 当作确定命中。

容量策略：

1. 整个 OR 为零的 IP 不写入内核，map miss 已能表示其结果。
2. 其他 IP 按上述 `priority` 从晚到早排序，取实际 map 容量允许的数量；同分按 IP 排序。
3. 每个选中的 IP 包含完整 pair 聚合，全零 pair 参与 AND，但不提高排序优先级。
4. 更新、续期、GC 和 reload 重新评估候选并补齐空位。写入替换项前先移除淘汰项。

pair 新增或删除时，只合并受影响 IP 的关联域名，复用该 IP 的 bitmap 缓冲区。同一 DNS 应答的查询名、别名和地址批量登记，每个受影响 IP 只发布一次完整聚合。期限延长只更新 pair 的期限和 IP 优先级；已驻留 IP 排名提高不会改变驻留集合，因此无需重写位图。

容量选择读取已计算好的 IP 聚合。所有可能新增的候选都能放入内核时，只处理本次变化的 IP；涉及容量竞争时重新选择候选，只有候选数超过容量才排序。常驻索引和聚合的内存随保留记录数增长，容量竞争的选择成本随 IP 数增长；待处理活动按批次内不同观察键占用空间，复用的 map 保留已分配容量。应用观察时推进单调时间水位并检查到期回收。组件职责与生命周期见[DNS 架构](../design/project-structure.md#dns)。

### 共享 CDN 与观察盲区

无域名流量刷新全部 pair 是保守选择：活跃 CDN IP 可能使已不再使用的旧域名持续存活，进而长期保留捕获/歧义。这套策略优先减少缺失映射，不能保证同时消除所有旧 CDN 记录。

**未被捕获的 kernel direct 流量第一版不续期。** 内核 `domain()` 和域名 MITM/DNAT 捕获依赖驻留映射；映射未观察到、被 GC 或因容量落选时，沿用普通路由语义，不扩大成全流量捕获。用户态历史存在也不能让一条尚未捕获的连接自动获得 sniff 机会。

这意味着 SSH、无关 HTTPS、无映射的普通 direct 流量仍保持内核直通。客户端使用未被 DNS 插件处理的加密 DNS 时，核心无法被动观察其中的映射。

## 持久化和诊断

有变更时每 60 秒保存，正常关闭时最终保存到 `$DAE_LOCATION_CACHE/domain-registry.json.gz`，默认 `/var/lib/dae/domain-registry.json.gz`。文件内容为 **gzip 压缩的 JSON**。文件权限 0600，将 JSON 以 gzip 最快压缩级别流式写入临时文件，完成 gzip 写入后执行文件 fsync、原子 rename 和目录 fsync。可以直接查看：

```sh
zcat /var/lib/dae/domain-registry.json.gz | jq .
```

JSON 按域名分组，结构为 `domain → IP → retain_until`。每个域名只保存一次，每个 IP 单独保存绝对截止时间，IPv4、IPv6 的期限相互独立，空快照为 `{}`：

```json
{
  "example.com.": {
    "192.0.2.1": "2026-09-19T00:00:00Z",
    "2001:db8::1": "2026-09-20T00:00:00Z"
  }
}
```

重复的域名键或同一域名下重复的 IP 会被拒绝。恢复时先验证完整数据流，包括 gzip 校验和及尾部，全部通过后才发布证据。

冷启动在接口挂载前直接加载校验后的记录，保留原截止时间，回收过期记录，并按当前规则重算 bitmap。快照不设条目数/大小上限，但会检查格式、地址、域名、重复项和尾随数据。

保存失败会记录警告，最终保存也相同。磁盘错误不阻止已经停止写入的旧平面安全退役，reload 仍可继承内存中的证据与活动。

`dae status` / `/api/status` 使用 schema **11**：

- `domain-registry`：`used` 是用户态域名–IP 配对数，`limit: 0` 表示无容量上限。`breakdown.domains` 是域名数，`breakdown.ips` 是跨域名去重后的 IP 总数，`breakdown.ipv4` / `ipv6` 是去重地址的类型分布，二者之和等于 `ips`。同一 IP 对应多个域名会增加配对数，但 IP 只计一次。
- `breakdown.gc` 是累计按时间回收的配对数，跨 reload 延续，冷启动重新统计。查询状态只统计当前保留的记录，不触发 GC 或续期。
- `domain-kernel`：`used` 是驻留 IP 数，`limit` 是容量，`candidates` 是具有非零域名规则 bitmap 的候选 IP 数；`candidates - used` 是因容量未驻留的 IP 数。Registry 的 IP 数还包含无需入表的零 bitmap 地址，因此不等于候选数。

CLI 在内核表中显示 `USED (IPs)`、`CANDIDATES`、`OMITTED`，在 `domain-registry (unlimited)` 明细中显示 `PAIRS / DOMAINS / IPs / IPv4 / IPv6 / GC (PAIRS)`。

启动日志列出窗口及观察范围。容量不足时限频输出候选/驻留/容量摘要；无法对未观察到的 direct 连接逐条报告续期遗漏。

## 构建时设置表容量

```sh
make MAX_DOMAIN_ROUTING_NUM=131072 MAX_UDP_ROUTING_CACHE_NUM=131072
```

用户态读取实际 map 容量。可配置项仅保留原有的 `MAX_MATCH_SET_LEN`，以及 `MAX_DOMAIN_ROUTING_NUM`、`MAX_DST_MAPPING_NUM`、`MAX_DST_MAPPING_NUM_UDP`、`MAX_UDP_ROUTING_CACHE_NUM` 四类流量相关表容量；用途和默认值见[构建说明](../../en/user-guide/build-by-yourself.md#bpf-map-capacities)。接口数、LPM 内部限制、进程元数据和 API 观察表保持内部常量。这些构建参数需要重新构建并重启以创建新 maps；配置 reload 不调整容量。`MAX_MATCH_SET_LEN` 改变 bitmap 宽度，同时影响每个 IP 的内存成本。

## 可选 DNS 插件

在 `plugins.cfg` 加入模块，并通过 `go.work` 引用对应兄弟仓库后运行 `make`：

```text
dns-cache:github.com/daeuniverse/dae-plugin-dns-cache
dns-router:github.com/daeuniverse/dae-plugin-dns-router
```

推荐声明顺序为 **cache → Surge Host → router → 核心中继**，不使用的实例可以省略：

```dae
plugins {
    dns-cache {
        size: 32768
        memory_limit: 67108864
        fixed_domain_ttl { ddns.example.org: 0 }
    }
    surge { module { hosts: 'file:modules/hosts.sgmodule' } }
    dns-router {
        upstream { local: 'udp://192.0.2.53:53' remote: 'https://dns.example/dns-query' }
        routing {
            request { qname(suffix: lan) -> local fallback: remote }
            response { fallback: accept }
        }
    }
}
```

Router 提供策略、IP 版本偏好、UDP/TCP、DoT/DoH/DoQ/HTTP3 和传输回退。`asis` 调用后续处理器；Surge 显式服务器选择优先于后续通用策略。Cache 是独立有界 LRU，保存完整应答并递减 TTL，支持 SOA 负缓存及固定 TTL；签名/事务专属应答保守跳过缓存。

`global.dns_resolver` 从首次查询起指定内部解析服务器。上游、路由和 IP 版本偏好配置在 router 插件中，`fixed_domain_ttl` 配置在 cache 插件中。查看插件使用 `dae plugins status`。更多见[插件配置](mitm-plugins.md)和[Surge Host](surge-module.md#dns-host-与-ip-目标重写)。

## TODO

- 观察未捕获 kernel direct 的实际活动，同时保持内核直通性能和原始连接语义。
- 支持 sniff-only pair，并显式区分来源；**sniff-only 不能作为 verify 依据**。
- 设计用户态内存/条目数管理，明确容量淘汰与历史验证的关系。
- 根据测量结果优化聚合、排序、锁竞争和持久化，保持完整 IP AND/OR 不变量。
- 改善共享 CDN 上未知域名活动造成的长期保留，同时评估映射缺失的代价。
