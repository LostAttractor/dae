# Surge Module 支持范围

`surge` 插件以 Surge script 兼容为目标，重点是 MITM 请求/响应脚本及其配套模块能力。使用方法见[配置指南](surge-module.md)，证书与设备开关见[证书文档](mitm-certificate.md)。以下按 [Surge Module](https://manual.nssurge.com/profile/module.html)、[HTTP 处理](https://manual.nssurge.com/http/overview.html)和[脚本 API](https://manual.nssurge.com/scripting/api.html)整理；未列出的功能不视为支持，加载无警告不等于完整兼容。

执行职责、内核直通及 rule/event 的限制见[脚本兼容边界](../development/surge-compatibility.md)。

## 已支持

| 范围 | 能力 |
| --- | --- |
| 来源与参数 | file、HTTP(S)、全局资源缓存；相对依赖；名称和描述；`#!arguments` 默认值、中文名称、空值、文本替换及交互生成配置。回车继承默认值，显式填写才生成覆盖 |
| HTTP 脚本 | `http-request` / `http-response`；pattern、argument、timeout、requires-body、binary-body-mode、full-header-mode、max-size、enable。每方向仅执行首个匹配的启用脚本 |
| 定时脚本 | `cron`；五字段或六字段 cronexp、本地时区、`$cronexp`、共享持久存储与脚本名额、后台路由 HTTP 客户端；status 显示计划与最近执行状态 |
| 手动脚本 | `generic`（也是省略 type 时的默认类型）；CLI/API 按名称执行，`$trigger=http-api`；与 cron 共用后台执行、存储、通知、名额及状态；`list` 发现两类任务 |
| 重写 | Header add/del/replace/replace-regex；URL header/302/307/reject；Map Local file/text/base64/tiny-gif、自定义头和状态；请求/响应 regex 与 jq Body Rewrite |
| 脚本数据 | `$request`、`$response`、`$done`；数字 status、字符串或 Uint8Array body、修改/合成响应/abort；保留目标脚本使用的 h2_trailers |
| 运行时 | console、Promise、async/await、定时器、`$persistentStore`、`$httpClient` 七种方法、`$utils.ungzip`；通知写入日志并保留在 status 近期通知中；UTF-8 编解码、Base64、基础 fetch/Headers/Request/Response、有限 URL/DOM API |
| MITM | HTTP/1.1、TLS HTTP/2、HTTP/3（QUIC v1/v2）、gzip/deflate/br；主机通配、排除、端口；模块独立作用域；CA 管理、设备 MAC/IP 筛选和网页开关 |
| 目标重写 | `[Host]` 字面 IP → 单个或多个 IPv4/IPv6；保留端口，按连接随机选址；对 direct 和 proxy 生效 |
| DNS Host | 域名/通配符 → 混合 A/AAAA、别名、显式服务器、DOMAIN-SET/RULE-SET；DNS script 的 `$domain` 与 address/addresses/server/servers/ttl 结果；域名条目不自动生成 DNAT |
| 路由 | DOMAIN/SUFFIX/KEYWORD、基础 WILDCARD、AND/OR/NOT；DIRECT、REJECT、pre-matching、extended-matching 的 dae 映射 |

## 缺失与行为差异

### 模块与重写

| 范围 | 当前边界 |
| --- | --- |
| Host 代理行为 | `use-local-host-item-for-proxy` 决定已截获代理连接是否保留静态 Host 的 DNS IP；direct 保留，且不扩大捕获范围 |
| 条件与其他段 | 支持模块 `#!system` / `#!requirement`、行首及行尾 REQUIREMENT、平台 ONLY 条件；按 Linux 宿主信息求值，CORE_VERSION 比较项忽略，AND/OR/NOT 只保留其它条件；其它未知变量警告并跳过对应模块或行。无 `#!include`；General 除 `use-local-host-item-for-proxy` 外、WireGuard、Ruleset 等忽略 |
| 注释 | 各段支持 # / ; / // 整行及行尾注释；行尾标记须在引号外并由空白分隔，保留 URL 和引号内文本。参数替换后也可禁用整行 |
| 模块作用域 | hostname 在每个模块内独立合并；无 hostname 的模块执行路由与 IP 目标重写，无需 CA。增删、排序、改参需重载，没有模块管理 UI/API |
| 其他脚本类型与参数 | 无 rule/event。声明须包含名称；省略 type 默认为 generic。dns 脚本通过 Host 引用且无需 HTTP pattern。script-update-interval 控制远程脚本自动检查（默认 86400 秒，0 关闭）；debug=true 在每次执行前重读本地脚本。无 Surge 请求备注界面；img-url、wake-system 忽略，仅在 trace 级别记录。`enable=false` 的脚本不加载或执行。未知参数仍警告，已支持参数的非法值仍报错 |
| cron 边界 | 按 daemon 本地时区，支持通配、列表、范围、步长及英文月/星期名（星期 0–6）；无 TZ/CRON_TZ、@every 或系统唤醒。支持 CLI/API 手动触发，任务统一由运行中的 daemon 执行；实例 store 默认持久化（`store: false` 关闭）。上次仍在等待/运行时定时触发跳过、手动触发返回冲突；启动不补跑历史任务，运行中延迟/休眠恢复时每个到期任务至多触发一次，不逐次补跑积压。状态历史与计数随重载重置。success 表示运行时完成，不保证业务签到成功 |
| generic 边界 | 无自动触发；只执行 daemon 已加载的命名脚本，不提供任意脚本文本 evaluate 或界面启动上下文。手动执行忽略 `$done` 返回值，仍须调用 `$done`；每次独立 VM，超时包含共享名额等待。同一任务等待/运行时手动触发返回冲突；重载/停止取消并等待清理，状态计数重置 |
| 引擎 | auto/jsc/webview 都用 QuickJS，webview 会提示；无真实 WebView/JSC/JIT |
| URL/Host 匹配 | 脚本 pattern 匹配当前 URL 及替换为 Host/SNI 的 URL，仍按脚本声明顺序首个命中；仅在连接已准入的模块内匹配，不扩大捕获或模块作用域。URL Rewrite 仅 HTTP(S)，非法目标返回 502。无内置 `{{{GATEWAY_ADDRESS}}}` |
| Body Rewrite | `http-request` / `http-response` 按顺序执行 regex/replacement 对，支持捕获组替换和多行锚点，仅处理有效 UTF-8；对应 `-jq` 类型处理 JSON。gojq 不保证支持 Surge 全部 jq 扩展；无效 jq 表达式跳过，非 JSON、空 jq 输出或执行失败保留前一步正文。chunked / Expect 请求跳过正文重写 |
| 处理顺序 | 请求 Header → URL → Map Local → Body Rewrite → script；响应 Header → Body Rewrite → script。本地响应不进入响应重写链 |
| 分帧和正则 | 静态重写声明 Content-Length/Transfer-Encoding 会加载失败，脚本分帧由 dae 管理；regexp2 ECMAScript 有 50 ms 预算，不保证全部 Surge 正则细节 |

### 脚本与 HTTP

| 范围 | 当前边界 |
| --- | --- |
| 正文失败 | 请求脚本超限 413；响应正文在读取或解压后超限则跳过脚本，回放完整原响应。完整缓冲后解压耗尽脚本预算时跳过处理、回放原文；原请求取消或正文读取失败仍返回错误。脚本生成的替换正文超限仍拒绝；响应未 requires-body 时返回 body 会中止连接。Body Rewrite 请求读取/解压超限返回 413，响应超限回放原正文；单条表达式失败保留前一步正文，读取失败除外 |
| 请求正文 | chunked / Expect: 100-continue 请求不应用脚本返回的 body，仍允许头字段修改；空正文不暴露 body 属性 |
| 异常与 `$done` | 普通 JS 异常/超时保留进入脚本阶段的内容，不回滚之前重写；正文读取或非法结果可失败。重复 `$done` 忽略；未调用时等待脚本超时，即使没有待处理任务 |
| headers | 默认字符串值对象，重复 Cookie 值用分号合并，其它重复值用逗号合并。full-header-mode 使用 `{field,value}[]`，返回头可用对象或数组；保留 Set-Cookie 等重复值及同名字段顺序。Go HTTP 栈不保留原始大小写及不同字段之间的线上顺序 |
| 元数据 | `$script` 包含每次执行独立的 sessionID，startTime 为 Unix 秒；console 日志带 module/script/session_id。`$environment` 提供 Linux 系统、进程 locale、硬件型号（不可用时为架构）及 dae 构建信息；surge-version/surge-build 为空字符串。显式空 argument 仍注入 `$argument`；cron/generic 手动执行的 `$trigger` 为 `http-api`（包括 CLI 调用），定时执行不注入 |
| 存储与工具 | 省略键按解析后的 script-path 区分，同一实例内相同路径共享默认条目；显式键须为不含路径分隔符的非空字符串。值只接受字符串，null 删除。通知在每个实例内按脚本各保留最近 50 条，文本默认每脚本显示 3 条，`-v` / JSON 返回全部保留记录，重载清空；标题等各限 1024 UTF-8 字节，正文 4096 字节，截断会标记；额外选项忽略，不产生系统通知。ungzip 解压失败返回 null |
| HTTP 客户端 | 原主机和端口沿用当前路由；新主机或端口经系统解析器、目的地址规则和 routing 重新选择出站，保留客户端身份。文本与二进制响应均自动解压 gzip/deflate/br（含叠加编码），解压后移除 Content-Encoding/Content-Length；压缩正文及各层解压结果均受大小和内存预算限制，解码失败通过回调 error 返回。请求默认 timeout 为 5 秒，并受脚本剩余预算约束，覆盖响应读取、解压及回调数据生成。对象 body 自动编码 JSON 并设置 Content-Type。支持 full-header-mode、auto-redirect 和 auto-cookie；后两者默认 true，CookieJar 仅在本次脚本执行内共享。policy 可选 DIRECT、REJECT 或当前已加载的 dae 出站组；保留目的地址规则与 mark，仅覆盖该主动请求的出站，重定向沿用。未知组或组不可用时报错，不切换备用出站。脚本专用组通过 http_policies 预加载，不增加捕获。policy-descriptor 和 insecure=true 明确报错，insecure=false 使用正常 TLS 校验 |
| Web API | fetch 支持合法 HTTP 方法（禁用 CONNECT/TRACE/TRACK）、Headers/Request/Response、text/json/arrayBuffer/bytes、clone/bodyUsed、字符串/URLSearchParams/二进制正文及其它值的字符串转换；网络响应头不可修改，元数据只读。完整缓冲，共用正文和并发限制，扩展支持 policy/timeout；默认使用脚本剩余预算。AbortController/AbortSignal 支持单请求取消及 abort()/timeout()。无浏览器源或 CORS：默认不自动带 Cookie，credentials=include 使用本次执行的 CookieJar；manual 返回实际 30x，error 不跟随。无流、Blob/FormData、缓存/完整性/来源控制或 crypto；不支持的请求选项报错。编解码仅 UTF-8；URL/DOM 为有限实现，不执行页面脚本或加载资源 |
| 宿主接口 | 无 geoip/ipasn/ipaso、`$network`、`$httpAPI`、`$surge`；不提供 Node.js、QuickJS std/os 或任意文件访问 |
| 共享内存 | 固定大小 SharedArrayBuffer 受堆限制；无可增长共享缓冲，Atomics.wait 不能阻塞线程 |

### MITM 与路由

| 范围 | 当前边界 |
| --- | --- |
| MITM 选项 | 仅解析 hostname；skip-server-cert-verify 等忽略，无 hostname-disabled、p12/Keystore。特殊主机占位符报错；非 443 TLS 端口须显式填写 |
| 信任与协议 | 不探测客户端信任或在握手失败后透传；无自动 QUIC 阻断、h2c、跨主机 HTTP/2/3 复用。HTTP/3 不支持跨地址迁移、0-RTT、跨主机/端口 Alt-Svc、WebTransport/CONNECT-UDP；上游仍使用 H3，不自动回退 TCP。CONNECT 返回 405，WebSocket 只处理 HTTP1 握手；无 `force-http-engine-hosts` / `always-raw-tcp-hosts` |
| 路由类型 | 无 HTTP/IP/进程/端口/来源/规则集/SCRIPT 等模块规则；两字段 FINAL,DIRECT 加载失败。WILDCARD 无字符类，逻辑规则叶子限域名类型 |
| 拒绝与选项 | REJECT 映射 dae block；无 DNS No Record、TCP RST、自适应拒绝或 REJECT-TINYGIF。extended-matching 使用当前目标的 DNS/可信域名上下文，不匹配 URL 路径；未知选项整条跳过 |
| 优先级 | 目的地址规则 → flow → pre-matching 拒绝 → dae 显式规则 → 普通模块规则 → fallback。脚本、URL Rewrite、Map Local 范围先执行 HTTP 处理，再按最终目标运行该流程；原目标 block 不抢先终止已准入请求。纯检查保留有效原路由。302/307 返回客户端自行请求 |
| Host 范围 | 多个普通 IP DNS 服务器可并发解析，保留捕获身份并取消、等待其余查询；加密服务器需要 dns-router。DNS 脚本的正 TTL 地址结果按脚本、域名和路由身份缓存，命中递减 TTL；每实例最多 4096 条，重载清空。Linux system/syslib/force-syslib 使用 Go 内部解析器，默认系统 nameserver，可由 global.dns_resolver 覆盖；不模拟 macOS 分域解析或 libc-only NSS。用法见[DNS Host](surge-module.md#dns-host-与-ip-目标重写) |
| 诊断 | 有执行事件和分级 console 日志，无 Surge 抓包查看器、notes 或证书固定诊断页面 |

## 资源限制

近期通知每脚本最多 50 条，并共享每实例 1 MiB 保守 JSON 编码预算；超限时优先淘汰较长历史中的最旧记录，数量相同则淘汰最旧的一条。详见[近期通知](surge-module.md#近期通知)。

[配置指南](surge-module.md#配置与运行)列出主要限制。脚本 HTTP 并发上限 20，不设累计次数上限；请求/响应正文与 ungzip 输出限 min(memory_limit/4, 32 MiB)，HTML 限 min(memory_limit/4, 8 MiB)，持久存储单值 4 MiB、实例 JSON 总计 64 MiB。同时待处理定时器最多 64 个；另有 DOM 节点、规则展开和声明数上限。QuickJS 堆限制不覆盖 Go 缓冲、进程 RSS 或 jq 中间对象。
