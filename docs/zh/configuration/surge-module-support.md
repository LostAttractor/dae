# Surge Module 支持范围

dae 实现 Surge 的 HTTP 模块子集和部分路由功能。使用方法见[配置指南](surge-module.md)，证书与设备开关见[证书文档](mitm-certificate.md)。以下按 [Surge Module](https://manual.nssurge.com/profile/module.html)、[HTTP 处理](https://manual.nssurge.com/http/overview.html)和[脚本 API](https://manual.nssurge.com/scripting/api.html)整理；未列出的功能不视为支持，加载无警告不等于完整兼容。

## 已支持

| 范围 | 能力 |
| --- | --- |
| 来源与参数 | file、HTTP(S)、显式 `http(s)-file` 缓存；相对依赖；名称和描述；`#!arguments` 默认值、中文名称、空值、文本替换及交互生成配置。回车继承默认值，显式填写才生成覆盖 |
| HTTP 脚本 | `http-request` / `http-response`；pattern、argument、timeout、requires-body、binary-body-mode、max-size。每方向仅执行首个匹配脚本 |
| 重写 | Header add/del/replace/replace-regex；URL header/302/307/reject；Map Local file/text/base64/tiny-gif、自定义头和状态；response-jq Body Rewrite |
| 脚本数据 | `$request`、`$response`、`$done`；数字 status、字符串或 Uint8Array body、修改/合成响应/abort；保留目标脚本使用的 h2_trailers |
| 运行时 | console、Promise、async/await、定时器、`$persistentStore`、`$httpClient` 七种方法、`$utils.ungzip`；通知写入日志；UTF-8 编解码、Base64、有限 URL/DOM API |
| MITM | HTTP/1.1、TLS HTTP/2、gzip/deflate/br；主机通配、排除、端口；模块独立作用域；CA 管理、设备 MAC/IP 筛选和网页开关 |
| 目标重写 | `[Host]` 字面 IP、域名或通配符 → 单个或多个 IPv4/IPv6；保留端口，按连接随机选址；`use-local-host-item-for-proxy` 控制代理出站是否应用 |
| 路由 | DOMAIN/SUFFIX/KEYWORD、基础 WILDCARD、AND/OR/NOT；DIRECT、REJECT、pre-matching、extended-matching 的 dae 映射 |

## 缺失与行为差异

### 模块与重写

| 范围 | 当前边界 |
| --- | --- |
| 条件与其他段 | 无 system/requirement 筛选、`#!include`、行条件执行；General 除 `use-local-host-item-for-proxy` 外、WireGuard、Ruleset 等忽略。行首条件被跳过，Rule 行尾条件被去掉后规则仍可能执行 |
| 注释 | 支持 # / ; 整行，参数替换后也可禁用整行；仅 Rule 专门处理 // 和行尾注释 |
| 模块作用域 | hostname 在每个模块内独立合并；无 hostname 的模块执行路由与 IP 目标重写，无需 CA。增删、排序、改参需重载，没有模块管理 UI/API |
| 其他脚本类型与参数 | 无 rule/dns/event/cron/generic、无名称旧声明或省略 type；full-header-mode、script-update-interval、debug、enable 忽略，仅在 trace 级别记录，`enable=false` 不会禁用脚本。未知参数仍警告，已支持参数的非法值仍报错 |
| 引擎 | auto/jsc/webview 都用 QuickJS，webview 会提示；无真实 WebView/JSC/JIT |
| URL/Host 匹配 | 只匹配当前 URL，不组合 URL/Host/SNI 变体；URL Rewrite 仅 HTTP(S)，非法目标返回 502。无内置 `{{{GATEWAY_ADDRESS}}}` |
| Body Rewrite | 仅响应 jq；无请求 jq、请求/响应 regex。gojq 不保证支持 Surge 全部 jq 扩展；无效表达式跳过，非 JSON、空输出或执行失败保留原正文 |
| 处理顺序 | 请求 Header → URL → Map Local → script；响应 Header → jq → script。本地响应不进入响应重写链 |
| 分帧和正则 | 静态重写声明 Content-Length/Transfer-Encoding 会加载失败，脚本分帧由 dae 管理；regexp2 ECMAScript 有 50 ms 预算，不保证全部 Surge 正则细节 |

### 脚本与 HTTP

| 范围 | 当前边界 |
| --- | --- |
| 正文失败 | 请求脚本超限 413；响应正文在读取或解压后超限则跳过脚本，回放完整原响应。脚本生成的替换正文超限仍拒绝；响应未 requires-body 时返回 body 被忽略。jq 超限可回放原正文，读取失败除外 |
| 请求正文 | chunked / Expect: 100-continue 仍可替换 body；空正文的暴露不完全等同 Surge |
| 异常与 `$done` | 普通 JS 异常/超时保留进入脚本阶段的内容，不回滚之前重写；正文读取或非法结果可失败。重复 `$done` 忽略，无待办任务且未调用时立即报错 |
| headers | 字符串值对象，重复值合并；不保留完整重复字段和顺序，Set-Cookie 不能保证往返保留 |
| 元数据 | `$script` 缺 sessionID，startTime 使用毫秒；`$environment` 固定版本，不提供真实系统/语言/机型信息；空 argument 不注入 `$argument` |
| 存储与工具 | 存储省略键共用 undefined，不按脚本路径选键；非字符串值用 String 转换。通知不产生系统通知；ungzip 失败抛异常 |
| HTTP 客户端 | 沿用当前出站，未设 timeout 时继承脚本预算；不自动 JSON 编码对象 body。无 policy/policy-descriptor/insecure/auto-redirect/auto-cookie/full-header-mode，使用正常 TLS 校验和 Go 跳转行为，无 CookieJar |
| Web API | 编解码仅 UTF-8、无 streaming；URL/DOM 为有限实现，不执行页面脚本或加载资源；无 fetch/crypto/Headers/Request/Response |
| 系统接口 | 无 geoip/ipasn/ipaso、`$network`、`$httpAPI`、`$surge`、面板/Shortcuts 启动契约；不提供 Node.js、QuickJS std/os 或任意文件访问 |
| 共享内存 | 固定大小 SharedArrayBuffer 受堆限制；无可增长共享缓冲，Atomics.wait 不能阻塞线程 |

### MITM 与路由

| 范围 | 当前边界 |
| --- | --- |
| MITM 选项 | 仅解析 hostname；skip-server-cert-verify 等忽略，无 hostname-disabled、p12/Keystore。特殊主机占位符报错；非 443 TLS 端口须显式填写 |
| 信任与协议 | 不探测客户端信任或在握手失败后透传；无 HTTP/3 解密、自动 QUIC 阻断、h2c、跨主机 HTTP/2 复用。CONNECT 返回 405，WebSocket 只处理 HTTP1 握手；无 `force-http-engine-hosts` / `always-raw-tcp-hosts` |
| 路由类型 | 无 HTTP/IP/进程/端口/来源/规则集/SCRIPT 等模块规则；两字段 FINAL,DIRECT 加载失败。WILDCARD 无字符类，逻辑规则叶子限域名类型 |
| 拒绝与选项 | REJECT 映射 dae block；无 DNS No Record、TCP RST、自适应拒绝或 REJECT-TINYGIF。extended-matching 使用 DNS/可信 SNI/Host，不逐请求重新匹配；未知选项整条跳过 |
| 优先级 | pre-matching 拒绝 → dae 显式规则 → 普通模块规则 → fallback。脚本请求与 HTTP 改写沿用已选出站，不按新 URL 重跑路由 |
| Host 范围 | 支持字面 IP、域名和通配符到 IP 的拨号覆盖；无别名、指定 DNS、DNS script 或 ruleset 引用，不修改 DNS 应答。不支持的 Host 项使模块加载失败，错误包含行号。用法见[目标重写](surge-module.md#ip-目标重写) |
| 诊断 | 有执行事件和分级 console 日志，无 Surge 抓包查看器、notes 或证书固定诊断页面 |

## 资源与验证

[配置指南](surge-module.md#配置与运行)列出主要限制。脚本单次 HTTP 并发 16、累计 64；HTTP 响应/ungzip 输出限 min(memory_limit/4, 32 MiB)，HTML 限 min(memory_limit/4, 8 MiB)，持久存储总计 4 MiB。另有定时器、DOM 节点、规则展开和声明数上限。QuickJS 堆限制不覆盖 Go 缓冲、进程 RSS 或 jq 中间对象。

HTTP/TLS、模块作用域、取消/隔离及 Bilijump、Maasea 样例测试只验证受控场景，不等于所有 Surge 功能或 iOS 应用的端到端验证。
