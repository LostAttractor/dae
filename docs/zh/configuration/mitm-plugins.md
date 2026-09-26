# 插件配置

`plugins` 独立管理有序插件实例，`mitm` 管理 HTTP 证书、客户端开关和正文额度。默认构建包含 `surge`，支持 HTTP/DNS sgmodule 与 QuickJS；其他插件在独立仓库维护，通过 [plugins.cfg](../../../plugins.cfg) 加入 dae 编译。高级 DNS 路由和缓存已拆成两个可选插件，见 [DNS](dns.md)。

```text
mitm {
  enabled: true
  ca_cert: 'mitm-ca.pem'
  ca_key: 'mitm-ca.key'
  client_source_address: '02:00:00:00:00:50'
}
plugins {
  surge {
    module { personal: 'file:modules/personal.sgmodule' }
    store: 'personal-store.json'
    script_timeout: 5s
  }
  work {
    type: surge
    module { work: 'file:modules/work.sgmodule' }
    store: 'work-store.json'
  }
}
```

子段名是实例 ID，也是默认的类型。`type` 用于多个同类实例。空 `store` 为实例独立的内存存储；显式指定相同路径则共享持久数据，读写由同一个存储对象串行执行。实例默认启用，可用 `enabled: false` 关闭；HTTP 总开关默认关闭，不影响 DNS 插件。未知的活动类型、重复 ID 或未知插件字段会报错。显式关闭的插件不加载。

启动和重载会先检查全部启用实例的类型是否已编译，再调用 `Configure` 一次性解析并校验各实例配置，得到准备运行资源的工厂，之后才准备订阅、eBPF、连通性检查及远程模块。例如，后面的 bilijump 未编译时会立即报错，不必等前面的 Surge 模块下载。静态预检失败的重载会保持当前控制平面；依赖证书、远程模块内容等资源的错误在工厂准备阶段报告。加载阶段直接使用已解析的配置，见[插件 API](../../../component/plugin/README.md#configuration-preflight-and-preparation)。

`ca_cert`、`ca_key`、`client_source_address` 放在 `mitm`；module、store 和 JS 限制放在 Surge 实例中。仅贡献 DNS、IP Host 或路由的实例无需 CA；启用 HTTP scope 时要求 CA。客户端开关只控制 HTTP/MITM。相对路径以 `DAE_LOCATION_CACHE` 为基准；新实例缓存位于 `plugins/<ID>/surge-cache`。

`buffer_memory_limit` 放在宿主，默认 `268435456`（256 MiB），按进程共享受管理的正文缓冲额度。它覆盖正文快照、Surge 解压和改写输出，以及脚本 HTTP 响应和待交付的回调数据；转发未完成、只读借用或请求重试仍需保留的数据继续计入额度。分配前申请，扩容同时计算新旧两份容量；额度不足立即返回，不持有部分额度等待其他请求。Surge 跳过当前处理并转发原文，已成功应用的前序规则保留；脚本 HTTP 请求通过回调报告失败。

重载期间新旧宿主共用额度，采用两者中较小的限制，旧宿主退出后使用新限制；调低上限不会丢弃已有正文。`dae plugins status` 显示当前用量、有效上限、进程峰值和申请被拒次数。这个额度不是 RSS 上限，不覆盖 QuickJS 堆、jq 中间对象、插件自行分配的数据、缓存或网络协议缓冲；单脚本 `memory_limit`、正文大小和并发限制仍然生效。

`dae plugins surge configure` 输出的 module 段可放入所选 Surge 实例。

插件按声明顺序执行，请求 A → B → 上游，响应 B → A。每个插件的 scope 独立判断，使用当前请求在插件执行前准入的主机与端口；URL/Host 改写不会激活另一个 scope。一个 Surge 实例内部仍保持原有模块顺序及“每个方向只运行第一个匹配脚本”的行为。

已经准入的 HTTPS/HTTP/2、HTTP/3 连接允许同端口的跨主机请求复用，包括单主机证书未覆盖的业务 authority。未命中任何 HTTP scope 的请求跳过全部插件请求/响应钩子，保留原 Alt-Svc。没有插件显式改写 URL 的 scheme/主机/端口时，所有 stream 保持原接入目标、出站、mark 和上游 TLS 身份，不因 authority 改变而重复 DNS/选路；由原入口按 HTTP authority 分发。仅 path/query 或 Host 头变化不改变网络目标。显式 URL 目标改写和插件主动请求才为新目标解析、选路并验证 TLS。`domain()` 路由匹配实际接入目标，不是逐 stream 业务 authority 的过滤器。插件收到的 `Flow.Host` 是业务 authority，不是独立认证证明；`Source/Destination` 保留捕获地址。端口变化和 HTTP/1 跨主机请求仍返回 421。

下游握手仅签发本地单主机证书，没有上游探测、SAN 镜像或路由证书缓存；证书选择不依赖 scope、脚本阶段和 `PreserveRoute`。本地签发缓存最多 256 项，叶证书有效期不超过 24 小时和 CA 到期时间。真实转发仍验证上游接入点的证书名称、有效期和信任链；失败返回上游错误。本地响应零拨号，原目标 block 不阻止插件先生成本地响应或改写到允许的目标。无需新增配置或重建 CA。详见[证书与跨域连接复用：方案、边界和替代方案](mitm-certificates.md)。

插件的每个 `Plan.Scopes` 项同时保存捕获范围与路由属性；默认在 HTTP 处理后确定路由，仅保持目标且始终转发的纯检查可声明 `PreserveRoute: true`。重叠范围中的请求处理优先。Surge 自动将含脚本、URL Rewrite 或 Map Local 的模块归入请求路由。请求型连接先通过 scope 与客户端准入，再执行 HTTP 规则，最后按有效目标决定出站、mark、must 和 block。原目标的 block 不会阻止已准入请求改写到允许的目标；新目标的 block 仍拒绝。纯检查保留已有内核路由；未准入连接执行普通路由。转发与脚本子请求共用按目标、节点、出站及 mark 隔离的连接池，流量统计归属实际上游连接。

**eBPF direct 是 dae 的核心行为。** 宿主按 HTTP scope 中的正向域名/IP 和各自端口生成 TCP/UDP 捕获条件，只有候选连接才进入用户态；无关 SSH、HTTPS 等 direct 流量仍在内核直通。不能用全 TCP/UDP 或仅按端口捕获来补偿缺少域名信息。

域名条件复用普通 `domain()` 的 DNS 域名—IP 映射，字面 IP 条件无需 DNS。缺少映射时，原本在内核直连的连接不会仅因后续可能出现匹配的 SNI/Host 而被捕获；已因其他规则进入用户态的连接仍可按实际主机名处理。共享 IP 和正向通配符可能带入额外候选，最终仍按原主机名、端口、scope 排除顺序和客户端开关决定是否执行插件。一个 scope 的排除项不会取消另一个 scope 的允许项。

客户端使用的解析结果与 dae 当前保存的域名—IP 映射可能不同步，例如设备切换网络后沿用旧地址。dae 重启恢复磁盘登记表的原期限、重载继承内存表；尚未观察到或已经失效的映射不能支持正向域名捕获。详见 [DomainRegistry](dns.md#持久化和诊断)。

HTTP/3 使用现有 CA、客户端开关与插件 scope，无需新增配置。仅在完整 QUIC ClientHello 声明 `h3` 后解密；客户端请求与上游都使用 HTTP/3，插件主动 HTTP 请求按最终目标重新匹配 TCP 路由并使用 HTTP/1 或 HTTP/2。支持同一源/目标/握手域名下的多连接和重连，以及同端口请求 authority 复用；不支持跨地址迁移或 0-RTT。下游 TLS session ticket 暂时禁用。命中 scope 的请求仅保留同请求主机、同端口的 H3 Alt-Svc 广告；scope 外普通转发保留原 Alt-Svc。

被明确捕获后使用 `direct` 出站的连接依赖 dae 转发，停止 dae 会使它断开；这与未被捕获的 eBPF direct 不同。

重载会取消旧插件的后台任务并排空已开始的 HTTP 请求，默认预算 5 秒，超时后取消请求并关闭连接。后台识别、等待预算、缓存等行为由具体插件定义；宿主没有通用的任务队列，也不能事后补写已返回的响应。

`dae plugins status` 汇总所有已启用实例，`--verbose`（`-v`）聚合各插件的完整 status 输出。整次命令只查询 daemon 一次，`--instance ID` 筛选实例。没有自定义 status 的插件展示完整 JSON 报告；渲染失败时保留原始报告并继续显示其他插件，命令最终返回错误。`--json` 输出完整插件报告，优先于 `-v`。

`dae plugins surge status` 查看 Surge 模块状态；外部插件可注册命令，例如 `dae plugins bilijump status --instance personal`。没有自定义 status 的插件也有通用 status 命令。命令通过 Unix socket 查询 daemon，无需开启 `api_port`。证书命令仍为 `dae mitm ca`。状态字段见[页面/API](api.md)，编译见[构建说明](../../en/user-guide/build-by-yourself.md#external-plugins)，编写插件见[插件 API](../../../component/plugin/README.md)。

插件也可以通过 `Services.Metrics` 注册 Prometheus 指标，与核心指标一起由 `global.metrics_port` 暴露。内置 Surge 和独立的 dns-cache、dns-router 已提供指标；宿主统一添加 `plugin_type`、`plugin_instance` 标签。指标随实例重建而重置，详见[指标与 PromQL 示例](metrics.md)。

Go 插件可以通过 `Services.Storage` 保存实例状态，提供 `Get`、`Put`、`Delete`；单值上限 8 MiB，原子替换并同步磁盘。文件位于 `DAE_LOCATION_CACHE/plugins/state/`（默认基目录 `/var/lib/dae`），新目录权限 `0700`、文件 `0600`。默认实例（实例名等于类型名）直接使用 `<类型>/`，命名实例使用 `<类型>@<实例名>/`：例如 `plugins/state/bilijump/` 和 `plugins/state/bilijump@personal/`。类型和实例名分别做路径转义，名称中的 `@` 也转义，避免不同实例或类型混用状态。路径不随实例数量变化，增加实例不会移动已有状态。相同类型与实例名在重载、重启后复用数据，改名或禁用不会自动删除文件。具体格式、有效期与开关由插件定义。bilijump 默认使用此 API 保存捕获的登录 Cookie，`persist_cookie: false` 可改为仅内存；重载恢复时保留原有效期。开发约定见[持久化 API](../../../component/plugin/README.md#persistent-storage)。

## 排查偶发 HTTP / gRPC 失败

临时将 `global.log_level` 设为 `trace`，可记录 MITM 请求从入口到响应处理结束的过程，适用于仅声明捕获域名、不改写请求的透传模块。按 `connection_id` 和 `request_id` 关联事件；`path_id` 是不含查询参数的转义路径的 SHA-256 前 16 位十六进制摘要，可比较失败与重试是否为同一路径。`host` 和 `connection_host` 表示连接最初的主机，`request_authority` 是当前请求规范化后的主机及端口；无效 authority 只记录为 `invalid`。自动诊断不记录原始路径、查询参数、认证头或正文。

| 事件 | 观察内容 |
| --- | --- |
| `mitm_request_begin` | 捕获主机、端口、原始源/目标地址、客户端 HTTP 协议与路径摘要 |
| `mitm_certificate` | 本地单主机证书（`certificate_source=single`）、证书摘要和 DNS/IP SAN（`trace`） |
| `mitm_authority_coalesced` / `mitm_authority_rejected` | 接受 H2/H3 跨主机请求（`trace`，`plugin_scope=false` 表示跳过插件）或拒绝 authority（`debug`），同时记录连接与请求的主机身份；插件执行后才决定实际转发目标 |
| `mitm_upstream_connection` | 上游连接本地/对端地址、`reused`、`was_idle`、`idle_ms`；传输层重试可能产生多条 |
| `mitm_upstream_tls` / `mitm_upstream_written` / `mitm_upstream_first_byte` | TLS 协商 ALPN、请求写出与首字节耗时；`elapsed_ms` 从本次上游转发开始计算 |
| `mitm_upstream_response` | 上游 HTTP 状态、协议与正文长度声明，只表示取得响应头 |
| `mitm_request_end` | 最终 HTTP 状态、总耗时、正文读写字节数、`body_eof`、错误及最终 `grpc_status` |
| `mitm_response_failed` | 响应正文读取或下游写入/flush 失败，`debug` 即可见 |
| `mitm_http2_error` / `mitm_connection_end` | 客户端 HTTP/2 协议错误（`debug`）及 TCP 连接结束（`trace`） |

`mitm_request_end.outcome` 区分 `completed`、`local_rejection`、`processing_error`、`transfer_error`、`aborted`、`canceled` 和 `upgrade`。`completed` 表示宿主 HTTP 处理完成，仍需检查 HTTP / gRPC 状态；写入字节数表示交给 HTTP 服务器的正文，不是客户端接收回执。gRPC 状态在正文 EOF 后读取，兼容普通 trailer 与 trailers-only 响应头；`missing` 表示没有最终状态，`invalid` 表示格式不合法。Upgrade 隧道不记录 HTTP 正文字节数。

421 的 `reason` 区分 `scheme_mismatch`（请求 scheme 与透明监听连接不一致）、`invalid_authority`（格式不合法）、`authority_port_mismatch`（端口不一致）和 `authority_mismatch`（该协议不支持跨主机）。不再因 SAN 未覆盖、证书快照或 scope 不匹配而拒绝跨域请求。上游自身仍可能返回 421，应结合 `outcome` 判断是否为本地拒绝。同一连接的日志 `host` 相同不代表每个请求的 `:authority` 相同，应比较 `connection_host` 和 `request_authority`；scheme 问题可比较 `connection_scheme` 与 `request_scheme`。

出现错误时记录操作时间，再正常重试一次，保留前后几分钟的完整日志。systemd 部署可使用：

```sh
sudo journalctl -u dae --since "10 minutes ago" -o short-iso-precise > mitm-failure.log
```

若没有对应的请求入口，应继续检查捕获映射、TLS 握手和连接层；仅凭没有 `upstream_error` 不能认定响应完整。日志中的 HTTP 200 也不代表 gRPC 成功。响应头已发送后发生正文传输错误时，宿主中止 HTTP/1 连接或重置 HTTP/2、HTTP/3 流，不把半截响应作为正常完成返回。
