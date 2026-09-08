# Surge Module

内置 `surge` 插件使用 [buke/quickjs-go](https://github.com/buke/quickjs-go) 的 cgo 绑定运行 QuickJS-NG，在透明转发中处理 Surge HTTP 模块，并支持部分路由与 IP 目标重写。HTTPS 使用本地 CA，功能默认关闭。参见[支持范围](surge-module-support.md)与[静态 musl 构建](../../en/user-guide/build-by-yourself.md#portable-static-musl-build)。

## 配置与运行

先[生成 CA 并让客户端安装、信任证书](mitm-certificate.md)，在主配置中加入：

```text
global {
  api_port: 9080
}

mitm {
  enabled: true
  # 替换为已信任 CA 的客户端 MAC；全部启用填写 'all'。
  client_source_address: '02:00:00:00:00:50'
  ca_cert: 'mitm-ca.pem'
  ca_key: 'mitm-ca.key'

  surge {
    module {
      demo: 'file:modules/demo.sgmodule'
      # 名称可省略，声明顺序决定匹配优先级：
      # 'https-file://example.com/module.sgmodule'
    }
    store: 'surge-store.json'
  }
}
```

旧顶层 `surge {}` 不再接受，请使用 `mitm` 下的实例配置。多个插件实例的配置见 [MITM 插件](mitm-plugins.md)。

模块使用 `名称: '来源'` 或匿名 `'来源'`，参数配置见下节。名称不可重复；显示名优先使用配置名称，其次 `#!name`、文件名。

| 来源 | 行为 |
| --- | --- |
| `file:modules/demo.sgmodule` | 相对 `DAE_LOCATION_CACHE`，默认 `/var/lib/dae` |
| `file:///opt/dae/demo.sgmodule` | 绝对路径 |
| `http://`、`https://` | 联网读取，不缓存模块 |
| `http-file://`、`https-file://` | 保存完整模块及依赖快照，刷新失败时整体回退 |

`ca_cert`、`ca_key`、`store` 的相对路径也使用 `DAE_LOCATION_CACHE`。模块内相对脚本及 Map Local 文件相对模块目录或重定向后的最终 URL；远程模块不能读本地文件，HTTPS 下载不能降级 HTTP。本地及普通远程模块只允许显式 `-file` 依赖使用缓存。缓存按来源和显式参数区分，与名称无关；写入和目录规则见[缓存目录](cache-directory.md)。

启动或重载时，先等待节点的初始连通性检查阶段结束，再按 dae DNS/路由规则下载模块，加载完成后接管流量。初始检查最多等待 60 秒；超时按现有断网策略继续。模块列表共用两分钟刷新预算，模块自身规则在加载后才生效。没有可用来源或缓存时加载失败，重载保留旧实例。重载会停止旧实例的新请求并在 5 秒预算内排空 HTTP 请求；普通 TCP/UDP 连接按各自生命周期处理；不按 `script-update-interval` 定时刷新。

| 设置 | 默认值 | 含义 |
| --- | --- | --- |
| `script_timeout` | `5s` | 默认单阶段预算，含等待名额、正文准备和脚本内 HTTP 请求；脚本显式配置的 `timeout`（秒）优先，可延长或缩短 |
| `memory_limit` | `134217728` | 单次 QuickJS 堆上限，字节 |
| `max_body_size` | `33554432` | 正文缓冲上限，字节；脚本可进一步缩小 |
| `max_concurrent_scripts` | `16` | 同时执行脚本或 jq 正文处理的名额 |
| `store` | 空 | `$persistentStore` 文件；空值仅保存在内存 |

每次脚本调用创建独立 VM。脚本默认 `max-size` 为 1 MiB；模块限 4 MiB，单依赖 16 MiB，总依赖 64 MiB。QuickJS 堆限制不等于进程内存限制，也不约束 jq 中间对象。

## 模块参数与交互配置

模块用 `#!arguments=名称:默认值,...` 声明参数，在正文中写 `{{{名称}}}`。中文名称可用、大小写敏感；参数按原文替换，不自动 JSON 编码。未知或重复参数、未提供的必填项、值中的换行/NUL 会报错。

```sh
dae mitm surge configure 'file:modules/youtube.sgmodule' \
  --name youtube > youtube-module.dae
```

命令显示模块说明和参数，直接回车继承默认值，显式输入固定该值，`""` 表示空字符串；无默认值必须填写。仅显式值写入配置，全部继承时生成简写。`--name` 默认 `module`。

提示写入 stderr，stdout 输出的 `module` 段放入 `mitm` 中对应的 Surge 实例。例如：

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

## 主机与模块作用域

模块声明处理的主机，排除项应放在通配项前：

```ini
[MITM]
hostname = %APPEND% -private.example.com, *.example.com
```

支持 `*`、`?`、`-` 排除，首项匹配决定结果。HTTPS 默认端口 443；其他端口写 `example.com:8443`，全部端口写 `example.com:0`。匹配主机的明文 HTTP 80 端口也会处理。

每个模块独立计算 hostname：`%APPEND%` 追加、`%INSERT%` 前插、无标记则替换。连接只使用匹配其最初主机和端口的模块，URL/Host 改写不会激活其他模块。无 hostname 的模块执行受支持的 `[Rule]` 和 `[Host]`，无需配置 CA。重叠模块按声明顺序处理，每个方向只运行首个匹配脚本。

### IP 目标重写

`[Host]` 支持 IP、域名或通配符 → 单个或多个 IPv4/IPv6，适用于 TCP/UDP。例如 [FKTG](https://github.com/BOBOLAOSHIV587/Rules/blob/main/JS/FuckTelegram/FKTG.sgmodule)：

```text
mitm {
  enabled: true
  surge {
    module {
      telegram: 'https-file://raw.githubusercontent.com/BOBOLAOSHIV587/Rules/main/JS/FuckTelegram/FKTG.sgmodule'
    }
  }
}
```

已有 `mitm.surge` 实例时只追加模块。仅含 Host 的模块无需 CA 或客户端 MITM 开关。映射按模块及条目顺序首个命中，保留原端口；后续路由使用重写后的目标。多个目标按连接随机选择，UDP 固定会话目标并还原回包来源。只有命中完整捕获条件的流量会进入用户态，新目标的 block 仍然生效。

Host 转换成与原生 [rules / DNAT](destination-rules.md) 共用的目的地址规则。内核保留完整过滤条件筛选候选连接，域名条件使用已有 DNS 域名—IP 映射，字面 IP 条件无需 DNS；用户态再按本连接的 SNI、HTTP Host 或可嗅探的 QUIC 判断实际目标。原生 rules 排在插件贡献之前，不修改 DNS 请求或应答。

Host 映射始终对 direct 和 proxy 生效，优先于 `dial_target_override`，不因出站选择撤销映射。模块包含 Host 映射且未设置 `[General] use-local-host-item-for-proxy = true`（未填写或为 false）时，加载日志和模块状态会提示与 Surge 的行为差异；设置 true 只消除此提示。映射不影响代理服务器自身地址。不支持 Host 别名、指定 DNS、DNS script 或 ruleset 引用，加载时报错并报告行号。不会自动测速、重试或递归重写。

### 限制客户端来源

`client_source_address` 支持 IPv4/IPv6、CIDR、MAC、`all` 和 `-` 排除；逗号或重复字段按顺序拼接，首个匹配项决定结果。IP 与 MAC 独立匹配。未填写或未匹配时关闭；全部启用必须显式填写 `all`，例如：

```text
client_source_address: '-02:00:00:00:00:10,all'
```

也可在[全局页面/API](api.md)的 **HTTPS Modules** 区域设置当前设备开关，设备覆盖优先于配置。安装步骤见[证书文档](mitm-certificate.md)。

只启用已信任 CA 的设备；dae 不探测信任状态，也不在 TLS 失败后重试透传。未启用的客户端沿原路由透传。未知 MAC 可在配置中用 IP/CIDR 匹配。

## 转发与协议

启用 HTTP scope 后，仅按模块的正向 hostname 和对应端口捕获 TCP/UDP 候选连接，再按实际主机名、排除项和客户端开关决定是否解密。无关 direct 流量保留 eBPF 内核直通。含脚本、URL Rewrite 或 Map Local 的模块先执行 HTTP 处理，随后按最终目标执行目的地址规则 → flow → 模块 pre-matching 拒绝 → dae 显式规则 → 普通模块规则 → fallback。原目标的 block 不会抢先阻止这些已准入的请求；新目标命中 block 则拒绝。未准入客户端仍按普通连接路由处理。

HTTP 转发和脚本 `$httpClient` 共用请求路由：原主机及端口使用截获 IP，其他目标经 dae DNS 解析，再执行目标规则和路由，保留客户端来源、接口及策略。请求型模块即使只改路径，也在 HTTP 处理后确定路由；纯检查模块保留原路由。路由在连接池查找前执行，出站、节点、mark 或实际目标变化会隔离连接池。302/307 返回客户端请求新目标，reject 和 Map Local 可直接生成响应，无需上游拨号。

支持 HTTP/1.1、TLS HTTP/2 和 HTTP/3（QUIC v1/v2）。HTTP/3 自动使用现有 CA、客户端开关和 hostname 范围；只有完整 ClientHello 的 ALPN 包含 `h3` 才解密，其它 QUIC/UDP 保持转发。客户端与上游都使用 HTTP/3，支持同一源/目标/域名下多连接及重连；上游握手失败不会自动改用 TCP 重试。HTTP/3 上游按最终目标匹配 UDP 路由；命中 block 时不会建立上游连接，模块的本地响应仍可直接返回。

若希望拒绝特定目标的 HTTP/3 上游，可在已有 `routing` 段前部加入对应规则（客户端是否重试 TCP 由客户端决定），例如：

```text
domain(httpbin.org) && l4proto(udp) && dport(443) -> block
```

内核的域名捕获依赖已有 DNS 域名—IP 映射；缺少映射时不会通过捕获全部 TCP/UDP 或仅按 HTTPS 端口捕获来兜底，原本的 direct 流量继续在内核转发。已因其他规则进入用户态的连接仍可使用 SNI/Host。共享 IP 可能带入额外候选，最终匹配和普通出站路由仍受各自的 scope、域名验证策略约束；无法嗅探主机名、ECH 或证书固定可能使处理失败。HTTP/2 和 HTTP/3 不允许跨原主机复用；HTTP/3 暂不支持跨地址迁移、0-RTT、WebTransport/CONNECT-UDP。仅保留上游同主机、同端口的 H3 Alt-Svc 广告。WebSocket 只处理 HTTP/1 握手。

## 执行与调试日志

初始化完成后，以 `info` 记录各模块的加载结果。详细模块状态按需查询，不在日志中重复打印表格。

运行中查询当前模块：

```sh
./dae mitm surge status
```

查询复用 daemon 的状态服务，无需开启 `global.api_port`。`loaded` 表示资源已加载；`cached` 表示整模块使用上次完整缓存；`cached dependencies` 表示部分依赖使用缓存。加载失败时报告具体原因，`debug` 可查看各模块已加载、失败或尚未加载的进度；失败重载后的查询仍显示运行中的旧实例。加载状态不代表脚本已匹配或执行。

`IP MAPS` 显示 IP 映射条目数。实际重写可查看 `debug` 路由日志：`destination_ip` 是原目标，`destination` 是拨号目标，`outbound` 是出站。

`WARNINGS` 统计模块解析、加载和缓存回退的警告，命令在表格下按模块列出完整内容。TLS 握手失败和脚本运行日志不计入此列。

```sh
journalctl -u dae -f -o cat
```

下载选路、客户端旁路和单请求失败为 `debug`，自动执行步骤为 `trace`。脚本失败后转发原始内容、处理上限导致跳过等行为退化为 `warn`；正常取消和脚本主动中断不告警。`console.log/info/debug/warn/error` 保留脚本选择的级别（log 为 info），`$notification.post` 写 info；均受 `global.log_level` 过滤。

已知不支持的脚本参数 `script-update-interval`、`debug`、`enable`、`full-header-mode` 忽略，仅在 `trace` 记录。`enable=false` 不禁用脚本；模块启停通过 dae 配置和重载完成。未知参数与影响行为的警告仍为 `warning`，支持参数的非法值仍会导致加载失败。

| 日志事件 | 含义 |
| --- | --- |
| `upstream_dial` | HTTP 转发、脚本请求或后台下载实际使用的出站、节点、mark 与目标；来自客户端时包含 source |
| `mitm_bypass` | 主机匹配但客户端未启用 MITM |
| `request_begin` → `script_match` → `script_start` → `script_end` | 请求、命中、执行及结果 |
| `*_rewrite_match` / `map_local_match` | 静态规则命中 |
| `request_failed` | Surge 请求处理失败 |

启用 `trace` 后，Surge 请求与脚本事件通过结构化 `event` 字段标识，使用 `connection_id` 和 `request_id` 关联。`script_end` 含脚本、阶段、耗时与 outcome；加载成功不代表脚本已执行，执行 success 也不保证应用效果。没有 `request_begin` 时依次检查来源开关、hostname、TCP/QUIC、TLS 信任、域名验证策略和网卡绑定。自动事件不记录 URL 路径、查询参数、认证头和正文，脚本自行打印的内容不受此限制。

## 示例与验证

将 [`demo.sgmodule`](../../../examples/surge/demo.sgmodule)、[`request.js`](../../../examples/surge/request.js)、[`response.js`](../../../examples/surge/response.js) 放入 `/var/lib/dae/modules/`，使用首个配置示例。从已信任 CA 的客户端访问 `https://httpbin.org/get`，请求增加 `X-Dae-Runtime`，响应增加 `dae.runtime = "quickjs"`；`/dae-redirect` 测试 302。

第三方 sgmodule 兼容夹具覆盖 [Bilijump](https://github.com/qingmeng1/bilijump-ai/blob/main/script/bilijump.sgmodule) 的 JSON、protobuf、空降、皮肤、网页脚本，以及 [Maasea YouTube](https://github.com/Maasea/sgmodule) 的 request/response 脚本。FKTG 已验证模块加载、目标选址和 UDP 回包还原。测试不等于 iOS 应用端到端验证；完整缺口见[支持范围](surge-module-support.md)。
