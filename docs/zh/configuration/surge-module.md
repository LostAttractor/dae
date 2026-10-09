# Surge Module

内置 `surge` 插件使用 [buke/quickjs-go](https://github.com/buke/quickjs-go) 运行 QuickJS-NG，重点兼容 MITM 中的 Surge 请求/响应脚本，并提供模块重写、存储、DNS、cron 和 generic 等配套能力。HTTPS 使用本地 CA，功能默认关闭。参见[支持范围](surge-module-support.md)与[静态 musl 构建](../../en/user-guide/build-by-yourself.md#musl)。

## 配置与运行

先[生成 CA 并让客户端安装、信任证书](mitm-certificate.md)，在主配置中加入：

```text
global {
  api_port: 9080
  resource_cache: true # 默认开启，统一缓存订阅、模块及远程依赖
}

mitm {
  enabled: true
  # 替换为已信任 CA 的客户端 MAC；全部启用填写 'all'。
  client_source_address: '02:00:00:00:00:50'
  ca_cert: 'mitm-ca.pem'
  ca_key: 'mitm-ca.key'
}
plugins {
  surge {
    module {
      demo: 'file:modules/demo.sgmodule'
      # 名称可省略，声明顺序决定匹配优先级：
      # 'https://example.com/module.sgmodule'
    }
  }
}
```

插件实例放在 `plugins {}` 中。多个实例的配置见[插件配置](mitm-plugins.md)。

模块使用 `名称: '来源'` 或匿名 `'来源'`，参数配置见下节。名称不可重复；显示名优先使用配置名称，其次 `#!name`、文件名。

| 来源 | 行为 |
| --- | --- |
| `file:modules/demo.sgmodule` | 相对 `DAE_LOCATION_CACHE`，默认 `/var/lib/dae` |
| `file:///opt/dae/demo.sgmodule` | 绝对路径 |
| `http://`、`https://` | 优先联网；`global.resource_cache` 开启时保存完整模块及依赖快照，失败时整体回退 |

`ca_cert`、`ca_key` 的相对路径也使用 `DAE_LOCATION_CACHE`。脚本持久存储默认开启，自动保存到该目录下的 `plugins/<实例ID>/surge-store.json`。模块内相对脚本及 Map Local 文件相对模块目录或重定向后的最终 URL；远程模块不能读本地文件，HTTPS 下载不能降级 HTTP。`global.resource_cache` 默认开启，适用于所有 HTTP(S) 模块和依赖；本地文件始终读取当前内容。缓存按来源和显式参数区分，与名称无关；写入和目录规则见[缓存目录](cache-directory.md#全局资源缓存)。

启动或重载时，先等待节点的初始连通性检查阶段结束，再用系统解析器解析模块主机，按普通路由下载模块，加载完成后接管流量。初始检查最多等待 60 秒；超时按现有断网策略继续。模块列表共用两分钟刷新预算，模块自身规则在加载后才生效。没有可用来源或缓存时加载失败，重载保留旧实例。重载会停止旧实例的新请求并在 5 秒预算内排空请求；普通 TCP/UDP 连接按各自生命周期处理。远程脚本按 `script-update-interval`（秒，默认 `86400`，`0` 关闭）自动检查；模块、订阅及普通依赖使用 `global.resource_update_interval`。reload 和[资源刷新 API](api.md#资源刷新)会立即尝试刷新。

| 设置 | 默认值 | 含义 |
| --- | --- | --- |
| `script_timeout` | `5s` | 默认单阶段预算，含等待名额、正文准备和脚本内 HTTP 请求；脚本显式配置的 `timeout`（秒）优先，可延长或缩短 |
| `memory_limit` | `134217728` | 单次 QuickJS 堆上限，字节 |
| `max_body_size` | `33554432` | 正文缓冲上限，字节；脚本可进一步缩小 |
| `max_concurrent_scripts` | `16` | 同时执行脚本或 Body Rewrite 的名额 |
| `http_policies` | 空 | 预加载脚本主动请求使用的出站组，逗号分隔，如 `proxy,api`；不增加捕获或路由规则 |
| `store` | `true` | 是否持久化 `$persistentStore`；`false` 仅保存在实例内存中，文件名自动确定 |

每次脚本调用创建独立 VM。脚本默认 `max-size` 为 1 MiB；模块限 4 MiB，单依赖 16 MiB，总依赖 64 MiB。QuickJS 堆限制不等于进程内存限制，也不约束 jq 中间对象。

同一实例的 HTTP、DNS、cron 和 generic 脚本共享存储，不同实例按 ID 隔离。默认文件例如 `/var/lib/dae/plugins/surge/surge-store.json`；改名会使用新的存储，旧文件保留。`store: false` 不读取或修改已有文件，重载后内存数据丢失；重新开启会恢复文件内的数据。

store 单值上限为 4 MiB，实例 JSON 总计上限为 64 MiB。省略键时按解析后的 script-path 区分条目；同一实例内相同脚本路径共享默认条目，显式键可用于不同脚本共享数据。值只接受字符串，null 删除；显式键须为不含路径分隔符的非空字符串。写入通过同目录的 `surge-store.json.lock` 跨进程锁保护，合并最新数据后原子替换；读取检查文件身份、大小和修改时间，只有变化时才重新加载 JSON，未变时复用内存数据。锁等待受脚本超时约束，数据和锁文件使用 `0600`。单次键写入有并发保护，脚本的多次 read/write 不构成事务。

## 模块参数与交互配置

模块用 `#!arguments=名称:默认值,...` 声明参数，在正文中写 `{{{名称}}}`。中文名称可用、大小写敏感；参数按原文替换，不自动 JSON 编码。未知或重复参数、未提供的必填项、值中的换行/NUL 会报错。

```sh
dae plugins surge configure 'file:modules/youtube.sgmodule' \
  --name youtube > youtube-module.dae
```

命令显示模块说明和参数，直接回车继承默认值，显式输入固定该值，`""` 表示空字符串；无默认值必须填写。仅显式值写入配置，全部继承时生成简写。`--name` 默认 `module`。

提示写入 stderr，stdout 输出的 `module` 段放入 `plugins` 中对应的 Surge 实例。例如：

```text
module {
  youtube {
    link: 'file:modules/youtube.sgmodule'
    arguments {
      '屏蔽上传按钮=false'
      '字幕翻译语言=zh-CN'
    }
  }
}
```

也可手工填写 `'名称=值'`，`'名称='` 表示空值。命令只读取模块文本，不下载依赖或写缓存；使用主机网络及 `HTTP_PROXY` / `HTTPS_PROXY`，来源语法与上表一致。

## 模块条件与注释

支持 `#!system`、`#!requirement`，以及行首 `#!REQUIREMENT 表达式 指令`、行尾 `#!REQUIREMENT 表达式` / `//!REQUIREMENT 表达式`。含空格的行首表达式用双引号包裹。比较、AND/OR/NOT、括号及 BEGINSWITH/ENDSWITH/CONTAINS/LIKE/MATCHES 可用。

条件中的 SYSTEM 为 `linux`，SYSTEM_VERSION 为内核版本，DEVICE_MODEL、DEVICE_NAME、LANGUAGE 来自宿主。iOS/macOS/tvOS ONLY 条件不启用；CORE_VERSION 比较项被忽略，不模拟 Surge 版本；组合表达式只保留其余条件，全部为版本条件时视为满足。例如 `CORE_VERSION>=20 OR SYSTEM='iOS'` 仍只由 SYSTEM 条件决定。其它未知变量会警告并跳过对应行或模块。模块条件不满足时状态为 `disabled`，不加载依赖或注册捕获规则。

各段支持 `#`、`;`、`//` 注释；行尾标记须在引号外并由空白分隔。例如：

```ini
[MITM]
hostname = example.com # 主机范围
[Rule]
DOMAIN,example.com,DIRECT #!REQUIREMENT SYSTEM='linux'
```

## 主机与模块作用域

模块声明处理的主机，排除项应放在通配项前：

```ini
[MITM]
hostname = %APPEND% -private.example.com, *.example.com
```

支持 `*`、`?`、`-` 排除，首项匹配决定结果。HTTPS 默认端口 443；其他端口写 `example.com:8443`，全部端口写 `example.com:0`。匹配主机的明文 HTTP 80 端口也会处理。

每个模块独立计算 hostname：`%APPEND%` 追加、`%INSERT%` 前插、无标记则替换。连接只使用匹配其最初主机和端口的模块，URL/Host 改写不会激活其他模块。无 hostname 的模块执行受支持的 `[Rule]` 和 `[Host]`，无需配置 CA。重叠模块按声明顺序处理，每个方向只运行首个匹配脚本。

### DNS Host 与 IP 目标重写

`[Host]` 域名/通配符条目处理 DNS，应答支持多个混合 IPv4/IPv6、`*`/`?`、别名、`server:`、`script:`、`DOMAIN-SET:`/`RULE-SET:`。按模块和条目顺序首个命中；别名重新查找并有循环/深度限制。DNS script 使用 `$domain` 和 `$done({address|addresses|server|servers, ttl?})`，只允许一种结果形式；`$done({})` 调用后续处理器。

静态地址按 A/AAAA/ANY 类型返回；其它类型返回空应答。`server:IP[:port]` 重定向原请求；多个普通 IP 服务器支持并发解析并返回成功应答，捕获身份保持不变；加密服务器由可选 `dns-router` 提供。`system`、`syslib`、`force-syslib` 在 Linux 上使用 dae 的 Go 内部解析器：地址查询支持 `/etc/hosts`，默认 DNS 服务器来自 `/etc/resolv.conf`，可由 [`global.dns_resolver`](dns.md#指定内部-dns-服务器) 覆盖；不模拟 macOS 的分域系统解析器或 libc-only NSS。域名集和规则集使用模块依赖下载及全局资源缓存。

system 查询保留绝对域名，不附加本机 search 域。Go 地址查询无法区分 NXDOMAIN 与 NODATA 时，通过同一内部 DNS Dial 服务再取得协议响应，保留 rcode 和 authority。别名响应在改写前必须匹配实际 alias 查询。

集合 URL 含 `=` 时，在赋值符两侧使用空格或 tab，以免与 URL 查询参数混淆。例如：

```ini
[Host]
DOMAIN-SET:https://lists.example/domains?token=abc = 192.0.2.1
RULE-SET:https://lists.example/rules?token=abc = server:https://dns.example/query?token=def
```

DNS 脚本的预算包含等待执行名额；`$httpClient` 保留原 DNS 客户端的路由身份，支持二进制 body，连接池只在该次 DNS 调用内使用。

域名 Host 不生成 DNAT，也不扩大 HTTP 捕获。`use-local-host-item-for-proxy` 决定已截获代理连接是否保留静态 Host 的 DNS IP（默认 false）；direct 保留该 IP。字面 IP → IP 生成原生目的地址规则，例如：

```ini
[Host]
192.0.2.1 = 198.51.100.1,198.51.100.2
```

仅含 Host 的模块无需 CA 或客户端 MITM 开关。字面 IP 映射按模块及条目顺序首个命中，保留原端口；后续路由使用重写后的目标。多个目标按连接随机选择，UDP 固定会话目标并还原回包来源。

字面 IP Host 与原生 [rules / DNAT](destination-rules.md) 共用目的地址规则，原生 rules 排在插件贡献之前。只有完整过滤条件命中的流量才进入用户态，新目标 block 仍生效。DNS 的透明转发和持久化域名登记见 [DNS](dns.md)。

字面 IP 映射对 direct 和 proxy 生效，优先于 `dial_target_override`，不影响代理服务器自身地址。域名条目的静态 DNS TTL 为 60 秒；系统与脚本默认 TTL 为 0。脚本返回地址及正 TTL 时，结果按脚本、域名和路由身份缓存，命中时返回剩余 TTL；0 不缓存，每实例最多 4096 条，过期或重载后重新执行脚本。

### 限制客户端来源

`client_source_address` 支持 IPv4/IPv6、CIDR、MAC、`all` 和 `-` 排除；逗号或重复字段按顺序拼接，首个匹配项决定结果。IP 与 MAC 独立匹配。未填写或未匹配时关闭；全部启用必须显式填写 `all`，例如：

```text
client_source_address: '-02:00:00:00:00:10,all'
```

也可在[全局页面/API](api.md)的 **HTTPS Modules** 区域设置当前设备开关，设备覆盖优先于配置。安装步骤见[证书文档](mitm-certificate.md)。

只启用已信任 CA 的设备；dae 不探测信任状态，也不在 TLS 失败后重试透传。未启用的客户端沿原路由透传。未知 MAC 可在配置中用 IP/CIDR 匹配。

## 正文重写

`[Body Rewrite]` 支持请求/响应正则替换和 jq；同一行的替换对、各规则依次执行，结果交给该方向的脚本。

```ini
[Body Rewrite]
http-request ^https://api\.example\.com/ "old" "new"
http-response ^https://api\.example\.com/ "(item)-([0-9]+)" "$1:$2"
http-response-jq ^https://api\.example\.com/ ".enabled = true"
```

请求 jq 使用 `http-request-jq`。正则正文须为有效 UTF-8，`^` / `$` 按行匹配，替换可为空；jq 处理单个 JSON 文档，空输出或执行失败保留前一步正文。请求 chunked / `Expect: 100-continue` 跳过正文重写。读取或解压超限时，请求返回 413，响应回放原文；本地合成响应不进入响应重写链。

## 转发与协议

启用 HTTP scope 后，仅按模块的正向 hostname 和对应端口捕获 TCP/UDP 候选连接，再按实际主机名、排除项和客户端开关决定是否解密。无关 direct 流量保留 eBPF 内核直通。含脚本、URL Rewrite 或 Map Local 的模块先执行 HTTP 处理，随后按最终目标执行目的地址规则 → flow → 模块 pre-matching 拒绝 → dae 显式规则 → 普通模块规则 → fallback。原目标的 block 不会抢先阻止这些已准入的请求；新目标命中 block 则拒绝。未准入客户端仍按普通连接路由处理。

HTTP 转发和脚本 `$httpClient` 共用请求路由：原主机及端口使用截获 IP，其他目标经系统解析器解析，再执行目标规则和路由，保留客户端来源、接口及策略。请求型模块在 HTTP 处理后确定路由；纯检查模块保留原路由。出站、节点、mark 或实际目标变化会隔离连接池。302/307 返回客户端请求新目标，reject 和 Map Local 可直接生成响应。

支持 HTTP/1.1、TLS HTTP/2 和 HTTP/3（QUIC v1/v2）。HTTP/3 自动使用现有 CA、客户端开关和 hostname 范围；只有完整 ClientHello 的 ALPN 包含 `h3` 才解密，其它 QUIC/UDP 保持转发。客户端与上游都使用 HTTP/3，支持同一源/目标/域名下多连接及重连；上游握手失败不会自动改用 TCP 重试。HTTP/3 上游按最终目标匹配 UDP 路由；命中 block 时不会建立上游连接，模块的本地响应仍可直接返回。

若希望拒绝特定目标的 HTTP/3 上游，可在已有 `routing` 段前部加入对应规则（客户端是否重试 TCP 由客户端决定），例如：

```text
domain(httpbin.org) && l4proto(udp) && dport(443) -> block
```

内核的域名捕获依赖已有 DNS 域名—IP 映射；缺少映射时不会通过捕获全部 TCP/UDP 或仅按 HTTPS 端口捕获来兜底，原本的 direct 流量继续在内核转发。已因其他规则进入用户态的连接仍可使用 SNI/Host。共享 IP 可能带入额外候选，最终匹配和普通出站路由仍受各自的 scope、域名验证策略约束；无法嗅探主机名、ECH 或证书固定可能使处理失败。HTTP/2 和 HTTP/3 不允许跨原主机复用；HTTP/3 暂不支持跨地址迁移、0-RTT、WebTransport/CONNECT-UDP。仅保留上游同主机、同端口的 H3 Alt-Svc 广告。WebSocket 只处理 HTTP/1 握手。

## 脚本 HTTP 请求

`$httpClient` 和基础 `fetch` 使用宿主路由、正常 TLS 校验及共享正文预算。`policy` 可填 `DIRECT`、`REJECT` 或当前已加载的 dae 出站组名；仅由脚本使用的组须在插件设置中写 `http_policies: proxy,api`，否则未被路由引用的组不会加载。它仅覆盖主动请求的出站，保留目的地址规则、客户端身份及 mark，并在重定向时沿用。未知或不可用的组返回错误。`policy-descriptor` 和 `insecure: true` 会明确报错；`insecure: false` 保持正常 TLS 校验。

```javascript
(async () => {
  const response = await fetch("https://api.example.com/data", { policy: "DIRECT" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const data = await response.json();
  $persistentStore.write(JSON.stringify(data), "data");
})().catch(console.error).finally(() => $done());
```

fetch 提供 Headers、Request、Response 和 `text()` / `json()` / `arrayBuffer()` / `bytes()`，支持复制及一次性正文消费。响应完整缓冲后交付；`timeout` 单位为秒，可进一步限制脚本剩余预算。默认不自动发送 Cookie，`credentials: "include"` 使用本次脚本的 CookieJar。`redirect: "manual"` 返回实际 30x，`"error"` 拒绝跟随。支持 `AbortController`、`AbortSignal.abort()` / `timeout()`；取消只终止对应请求。未指定 fetch `timeout` 时使用脚本剩余预算。无流式正文、Blob/FormData、浏览器 CORS 或缓存/来源控制；不支持的选项会报错。

## 执行与调试日志

初始化完成后，以 `info` 记录各模块的加载结果。详细模块状态按需查询，不在日志中重复打印表格。

运行中查询当前模块：

```sh
./dae plugins surge status
```

查询复用 daemon 的状态服务，无需开启 `global.api_port`。`disabled` 表示模块条件不满足；`loaded` 表示资源已加载；`cached` 表示整模块使用上次完整缓存；`cached dependencies` 表示部分依赖使用缓存。加载失败时报告具体原因，`debug` 可查看各模块已加载、失败或尚未加载的进度；失败重载后的查询仍显示运行中的旧实例。加载状态不代表脚本已匹配或执行。

`IP MAPS` 显示 IP 映射条目数。实际重写可查看 `debug` 路由日志：`destination_ip` 是原目标，`destination` 是拨号目标，`outbound` 是出站。

`WARNINGS` 统计模块解析、加载和缓存回退的警告，命令在表格下按模块列出完整内容。TLS 握手失败和脚本运行日志不计入此列。

`TASKS` 显示 cron 和 generic 脚本数量（包含在 `SCRIPTS` 总数中）。`Surge script tasks` 列出类型、表达式、时区、超时、当前状态及下次执行时间；generic 没有表达式、时区和下次执行时间。`Last script runs` 列出最近一次尝试的起止时间、耗时、触发来源、结果和运行/失败/重叠跳过次数。`TRIGGER` / `last_trigger` 为 `cron`（定时）或 `http-api`（CLI/API 手动触发）。JSON 中对应 `details.modules[].tasks`，`type` 区分两类任务；也可通过 `./dae plugins status -v` 查看。

状态包括 `pending`（等待插件激活）、`ready`（generic 可手动运行）、`scheduled`、`waiting`（等待共享名额）、`running`、`unscheduled`（cron 表达式没有可计算的下次时间，如 2 月 31 日）和 `stopped`。起止时间与超时包含等待名额；`last_error` 只提供 `timeout`、`canceled`、`error` 等错误类别，详细异常见日志。`success` 只表示脚本正常调用 `$done`：脚本自行捕获的接口失败仍可能显示 success，应同时查看近期通知或业务日志。

```sh
journalctl -u dae -f -o cat
```

下载选路、客户端旁路和单请求失败为 `debug`，自动执行步骤为 `trace`。脚本失败后转发原始内容、处理上限导致跳过等行为退化为 `warn`；正常取消和脚本主动中断不告警。`console.log/info/debug/warn/error` 保留脚本选择的级别（log 为 info），`$notification.post` 写 info；日志受 `global.log_level` 过滤，近期通知的状态记录不受影响。

脚本参数 `enable=false` 禁止该脚本加载和执行；`full-header-mode=true` 使用字段数组传递头，保留重复值。`debug=true` 使本地脚本每次运行前重读，读取失败沿用该类脚本的失败处理；不提供 Surge 请求备注界面。`img-url`、`wake-system` 忽略，仅在 `trace` 记录。未知参数与影响行为的警告仍为 `warning`，支持参数的非法值仍会导致加载失败。

| 日志事件 | 含义 |
| --- | --- |
| `upstream_dial` | HTTP 转发、脚本请求或后台下载实际使用的出站、节点、mark 与目标；来自客户端时包含 source |
| `mitm_bypass` | 主机匹配但客户端未启用 MITM |
| `request_begin` → `script_match` → `script_start` → `script_end` | 请求、命中、执行及结果 |
| `*_rewrite_match` / `map_local_match` | 静态规则命中 |
| `request_failed` | Surge 请求处理失败 |
| `task_start` / `task_end` | cron/generic 脚本开始、结束；包含模块、脚本名称和类型、结果及耗时 |

启用 `trace` 后，Surge 请求与脚本事件通过结构化 `event` 字段标识，使用 `connection_id` 和 `request_id` 关联。`script_end` 含脚本、阶段、耗时与 outcome；加载成功不代表脚本已执行，执行 success 也不保证应用效果。没有 `request_begin` 时依次检查来源开关、hostname、TCP/QUIC、TLS 信任、域名验证策略和网卡绑定。自动事件不记录 URL 路径、查询参数、认证头和正文，脚本自行打印的内容不受此限制。

### 近期通知

脚本调用 `$notification.post(title, subtitle, body)` 时，除 info 日志外，还会在当前插件实例的内存中**按脚本各保留最多 50 条**通知。身份由模块名、脚本名和脚本类型共同确定；HTTP 请求/响应、DNS、cron 和 generic 均支持。普通 `console.log` 不计入。

每个实例另有 **1 MiB 的保守 JSON 编码预算**（按文本最坏转义长度计费）。达到总量上限时，优先从记录最多的脚本删除最旧记录；记录数相同则删除最旧的一条。高频脚本会先缩短自己的历史；若单条历史的脚本总量也超过预算，较旧记录仍会淘汰。因此实际保留数量可能少于每脚本 50 条，verbose/JSON 返回当前预算内的全部记录。

```sh
dae plugins surge status --instance surge
dae plugins surge status --instance surge --verbose
dae plugins surge status --instance surge --json
dae plugins status -v
```

文本输出的 `Recent Surge notifications` 默认**每脚本显示最近 3 条**，包含通知时间、实例/模块/脚本、脚本类型、标题、副标题和正文，最新在前。有省略时提示隐藏数量；`--verbose`（`-v`）展示当前保留的全部通知，`dae plugins status -v` 也会完整展示。不同实例和模块中的同名脚本分别计数。

`--json` 始终返回全部保留记录，位于实例的 `details.notifications`，也可从 `GET /api/status` 的 `plugins[].details.notifications` 获取；没有通知时省略该字段。verbose 展示的是当前内存中保留的记录。单个脚本超过 50 条时淘汰其最早记录，重载/重启会清空。例如：

```json
{
  "id": 3,
  "created_at": "2026-09-29T09:05:00+08:00",
  "module": "cron_demo",
  "script": "demo.cron",
  "script_type": "cron",
  "title": "任务完成",
  "subtitle": "演示通知",
  "body": "本次运行已完成"
}
```

`id` 按实例递增；历史与编号在重载/重启后重置，不写入 `$persistentStore`。模块名、脚本名、标题和副标题各最多 1024 UTF-8 字节，正文最多 4096 字节；超长时按字符边界截断并返回 `truncated: true`。通知发送后，即使脚本随后失败，该条记录仍保留。

通知内容是脚本显式提交的文本，保留换行，使用现有 status 管理访问权限。CLI 显示时移除终端控制字符，JSON 保留原文。额外通知选项仍忽略，不产生系统弹窗或手机推送。

## cron 定时脚本

以下是一个只输出日志的演示模块 `modules/cron-demo.sgmodule`：

```ini
[Script]
demo.cron = type=cron,cronexp="5 9 * * *",script-path=cron.js
```

在模块同目录创建 `cron.js`：

```javascript
console.log("Cron demo: " + $cronexp);
$done();
```

在 Surge 实例的 `module` 段加入：

```text
cron_demo: 'file:modules/cron-demo.sgmodule'
```

`cronexp` 必填：五字段依次为分、时、日、月、星期；六字段在最前面加秒。支持 `*`、逗号列表、范围、步长和英文月/星期名，星期用 `0–6`（周日为 0）。按 **daemon 本地时区** 调度；例如 `5 9 * * *` 每日 09:05，`*/10 * * * * *` 每十秒。时区以 daemon 的系统环境为准，而不是手机时区。

插件激活后安排下一次未来执行；准备模块时不运行任务，启动不补跑历史任务。运行中因延迟或休眠错过多个时间点时，每个到期任务至多触发一次，再安排未来时间，不逐次补跑积压。同一任务上次仍在等待或运行时，新的定时触发记为 skipped，手动触发返回冲突。不同任务共用 `max_concurrent_scripts`，单次预算包含等待名额、JS 和 HTTP 调用；默认继承 `script_timeout`，声明的 `timeout`（秒）优先。重载/停止会取消任务及其 HTTP 请求并等待清理完成，新实例重新调度，运行历史与计数重置。

运行时提供 `$script.type = "cron"`、`$cronexp` 和配置的 `$argument`，不注入 `$request`/`$response`；必须调用 `$done()`，返回值被忽略。与同一插件实例的 HTTP 脚本共享 `$persistentStore`，默认跨重启保留 Cookie；`store: false` 可关闭持久化。后台 `$httpClient` 使用 daemon 的路由客户端，没有被截获设备的来源身份。只有 cron 的模块无需 MITM hostname 或 CA；Cookie 抓取仍需按原 hostname、证书信任、设备开关和 DNS 映射条件启用 MITM。

`console.log` 和 `$notification.post` 的输出写入 daemon 日志；后者还会出现在 status 的[近期通知](#近期通知)中。

## generic 手动脚本

`generic` 没有自动触发器，只在 CLI/API 按名称调用时执行。模块 `modules/tools.sgmodule`：

```ini
[Script]
demo.tool = type=generic,script-path=tool.js,argument=hello,timeout=10
```

省略 `type` 同样表示 generic；脚本仍需名称和 `script-path`。同一模块内启用的 cron/generic 任务名称不得重复。在模块同目录创建 `tool.js`：

```javascript
$notification.post("Generic demo", $argument, "Triggered by " + $trigger);
$done();
```

在实例的 `module` 段加入 `tools: 'file:modules/tools.sgmodule'`，重载后使用 `dae plugins surge run demo.tool --instance surge --module tools` 执行。

运行时提供 `$script.type = "generic"`、`$trigger = "http-api"` 和配置的 `$argument`，没有类型专用输入。必须调用 `$done()`，手动执行忽略其返回值，未调用则等待超时。每次执行使用独立 VM。

generic 与 cron 共用后台任务执行器、实例存储、通知、路由 HTTP 客户端及 `max_concurrent_scripts` 名额；超时包含排队时间。同一任务等待/运行时拒绝重复触发。插件激活后为 `ready`，完成后回到 `ready`；停止/重载取消并等待执行清理。纯 generic 模块无需 MITM hostname 或 CA，也不产生流量捕获规则。

## 手动触发

daemon 运行时，先列出支持手动执行的 cron 和 generic 脚本，再按列表中的 `SCRIPT` 名称触发：

```sh
dae plugins surge list
dae plugins surge list --instance surge --module cron_demo
dae plugins surge list --json
dae plugins surge run demo.cron --instance surge --module cron_demo
dae plugins surge run demo.tool --instance surge --module tools
dae plugins surge status --instance surge
```

`list` 显示实例、模块、脚本名、类型、当前状态和 cron 表达式，并给出运行命令用法。它读取 daemon 的已加载任务；HTTP 请求/响应和 DNS 脚本不属于手动执行列表。`--instance`、`--module` 可组合筛选；`--json` 返回任务数组，每项含 `instance`、`module` 及任务状态字段（`name` 是脚本名，`type` 为 `cron` 或 `generic`），无匹配任务时为 `[]`。

等待中或运行中的任务仍会列出，重复触发会返回冲突；`unscheduled` 的 cron 仍可手动运行。名称含空格时请加引号，例如 `run '演示任务'`。

脚本名唯一时可省略 `--module`，跨实例也唯一时可省略 `--instance`。命令返回已受理的任务与运行编号；任务继续由 daemon 执行，结果通过 status 查看。`--json` 输出结构化受理信息；`run` 对应本任务的 `runs` 计数，仅在当前实例生命周期内有效。status 只保存最新一次尝试，重载重置历史。手动执行复用路由客户端、store、超时和执行名额，不改变原定时计划。脚本内 `$trigger` 为 `http-api`；定时执行时不注入 `$trigger`。

对应管理 API 为 `POST /api/plugins/{实例ID}/scripts/run`，例如正文 `{"module":"tools","script":"demo.tool"}`，需要正常管理权限及 `X-Dae-API: 1`。成功返回 `202`；任务不存在 `404`、同名不唯一 `400`、正在等待/运行 `409`、worker 未激活或已停止 `503`。仅接受已有 cron/generic 任务，不接受脚本文本或参数覆盖。

## 示例

将 [`demo.sgmodule`](../../../examples/surge/demo.sgmodule)、[`request.js`](../../../examples/surge/request.js)、[`response.js`](../../../examples/surge/response.js) 放入 `/var/lib/dae/modules/`，使用首个配置示例。从已信任 CA 的客户端访问 `https://httpbin.org/get`，请求增加 `X-Dae-Runtime`，响应增加 `dae.runtime = "quickjs"`；`/dae-redirect` 测试 302。

API 支持范围、行为差异和限制见[支持范围](surge-module-support.md)。
