# Surge Module

内置 `surge` 插件在编译时选择 JavaScript 后端：默认通过 [buke/quickjs-go](https://github.com/buke/quickjs-go) 运行 QuickJS-NG，也可编译为 Node.js 后端。插件重点兼容 MITM 中的 Surge 请求/响应脚本，并提供模块重写、存储、DNS、cron 和 generic 等配套能力。HTTPS 使用本地 CA，功能默认关闭。参见[支持范围](surge-module-support.md)与[构建指南](../../en/user-guide/build-by-yourself.md#surge-javascript-runtime)。

## 配置与运行

在主配置中加入以下设置。dae 自动初始化持久化 CA；让客户端[安装并信任证书](certificate.md)后再将其加入 `client_source_address`：

```text
global {
  api_port: 9080
  resource_cache: true # 默认开启，统一缓存订阅、模块及远程依赖
}

mitm {
  enabled: true
  # 替换为已信任 CA 的客户端 MAC；全部启用填写 'all'。
  client_source_address: '02:00:00:00:00:50'
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

自定义 CA 使用顶层 `certificate`；其中 `ca_cert`、`ca_key` 的相对路径使用 `DAE_LOCATION_CACHE`。脚本持久存储默认开启，自动保存到该目录下的 `plugins/<实例ID>/surge-store.json`。模块内相对脚本及 Map Local 文件相对模块目录或重定向后的最终 URL；远程模块不能读本地文件，HTTPS 下载不能降级 HTTP。`global.resource_cache` 默认开启，适用于所有 HTTP(S) 模块和依赖；本地文件始终读取当前内容。缓存按来源和显式参数区分，与名称无关；写入和目录规则见[缓存目录](cache-directory.md#全局资源缓存)。

模块及脚本属于受信任配置，能够通过 dae 访问本地网络；`http_policies` 是出站预加载声明，不是权限白名单。只加载可信来源。模块或依赖使用 HTTP 时，日志及模块状态会警告传输内容可能被篡改；HTTP 跳转 HTTPS 和缓存回退不会消除该警告。HTTPS 模块不能引用 HTTP 依赖，模块和依赖的 HTTPS 下载也不能重定向至 HTTP。HTTPS 保护传输过程，不保证模块作者或内容可信。

启动或重载时，先等待节点的初始连通性检查阶段结束，再用系统解析器解析模块主机，按普通路由下载模块，加载完成后接管流量。初始检查最多等待 60 秒；超时按现有断网策略继续。模块列表共用两分钟刷新预算，模块自身规则在加载后才生效。没有可用来源或缓存时加载失败，重载保留旧实例。重载会停止旧实例的新请求并在 5 秒预算内排空请求；普通 TCP/UDP 连接按各自生命周期处理。远程脚本按 `script-update-interval`（秒，默认 `86400`，`0` 关闭）自动检查；模块、订阅及普通依赖使用 `global.resource_update_interval`。reload 和[资源刷新 API](api.md#资源刷新)会立即尝试刷新。

| 设置 | 默认值 | 含义 |
| --- | --- | --- |
| `node_path` | `node` | 仅 Node.js 构建接受：可执行文件路径或 PATH 中的名称；不接受命令行参数 |
| `script_timeout` | `5s` | 默认单阶段执行预算；HTTP 阶段含正文解码、改写和脚本内 HTTP 请求，不含读取原始正文或等待实例执行名额；DNS 与后台任务仍包含排队。脚本显式配置的 `timeout`（秒）优先 |
| `memory_limit` | `134217728` | QuickJS 单次堆上限；Node.js 每个工作进程的 V8 老生代上限，向下取整为 MiB；字节 |
| `max_body_size` | `33554432` | 正文缓冲上限，字节；脚本可进一步缩小 |
| `max_concurrent_scripts` | `16` | 规则匹配、改写、脚本和诊断共用的并发名额 |
| `http_policies` | 空 | 预加载脚本主动请求使用的出站组，逗号分隔，如 `proxy,api`；不增加捕获或路由规则 |
| `isolate_lan` | `true` | 默认按可信 MAC 隔离 LAN 脚本状态；dae 模块描述符可按模块或脚本覆盖，本机始终使用本机分区 |
| `store` | `true` | 是否持久化 `$persistentStore`；`false` 仅保存在实例内存中，文件名自动确定 |

每次脚本调用创建独立执行上下文。脚本默认 `max-size` 为 1 MiB；模块限 4 MiB，单依赖 16 MiB，总依赖 64 MiB。JavaScript 堆限制不等于进程内存限制；Node.js 的 `memory_limit` 只约束 V8 老生代，工作进程另受下述 cgroup 限制；jq 使用其独立进程内存限制。

### Node.js 后端

使用 `make SURGE_RUNTIME=nodejs` 编译 dae，并在运行 dae 的系统中安装 Node.js 22.13 或更新版本。此构建默认 `CGO_ENABLED=0`，不编译或链接 QuickJS。需要指定 Node.js 路径时，在插件实例中设置：

```text
plugins {
  surge {
    node_path: '/usr/bin/node' # 按实际安装路径填写；省略时从 dae 的 PATH 查找 node
    module {
      demo: 'file:modules/demo.sgmodule'
    }
  }
}
```

Node.js 通过外部进程运行，无需 npm 包或额外脚本文件。模块资源准备完成后，仅含脚本的实例会按 `node_path` 创建并预热运行时；失败会拒绝候选配置，保留正在运行的实例。纯 Host、改写等无脚本模块不需要 JavaScript 运行时。每个二进制只包含一种脚本后端，所有 Surge 实例使用该后端，配置文件不提供运行时切换。`make SURGE_RUNTIME=quickjs` 编译 QuickJS 后端，运行脚本不需要安装 Node.js。

每个模块最多包含 1024 个用于 HTTP 匹配和替换的正则表达式。一次 HTTP 请求及其响应共用 250 ms 的累计正则执行预算和 4096 次正则操作上限；诊断查询使用同样的预算。计时仅覆盖正则执行，不包含上游网络等待或正文读取。单条正则仍有独立超时，最后一次操作可能因底层超时检查粒度而超过累计预算。预算耗尽或单条正则超时时终止本次处理，诊断返回不完整结果并标注 `regex_budget`，不会把尚未计算的条件当作确定的不匹配。

HTTP 规则匹配前取得并发名额，排队服从请求取消，不消耗脚本执行预算。读取网络正文期间释放名额，读取完成后重新排队取得名额，再开始正文解码、改写和脚本的执行预算；转发上游时也释放名额。慢速上传或下载不会占住其他请求的执行名额。URL/标头正则替换结果最多 1 MiB；正文替换继续使用正文大小和共享内存限制。

包含脚本的实例在准备阶段预热 1 个工作进程，完成协议初始化和共享 bootstrap 编译，不执行用户脚本；预热失败会拒绝本次启动或重载，当前运行的配置不受影响。只有重写、Hosts 或路由规则的实例不创建 JavaScript 运行时。并发增加时按需启动额外进程，最多 `max_concurrent_scripts` 个。多余进程空闲 60 秒后，在每 5 秒一次的维护中回收，保留最近使用的 1 个空闲进程；正在执行或等待脚本 HTTP、定时器的进程不会被空闲回收。每次脚本执行使用独立的新上下文。实例关闭会终止并回收进程。脚本超时、取消、执行异常或进程崩溃时丢弃该进程，后续调用重新创建。扩容和故障替换时的冷启动、正文跨进程复制及同步宿主调用有额外开销；计算密集的脚本可受益于 V8，短脚本不保证更快。Node.js 工作进程通常比 QuickJS 占用更多内存。

Node.js 预热需要可写且已委派 memory 控制器的 cgroup v2。每个 worker 的 `memory.max` 为 `2 × memory_limit + 64 MiB`，`memory.swap.max` 为 0；父组上限为该值乘以 `max_concurrent_scripts + 1`，多出的一份额度用于退出进程尚未释放的内核计账。这些额度覆盖被内核计入 cgroup 的堆、ArrayBuffer、原生分配及相关内核内存，不等同于 RSS/PSS，也不覆盖 dae 宿主的桥接缓冲。进程创建时直接进入对应组；回收时终止组内进程、等待退出并删除组；父组的回收余量避免将统计更新延迟变成每次脚本的等待。固定的运行时余量需要按目标 Node 版本和工作负载校准。各实例及重载期间的新旧运行时分别拥有自己的父组额度。

仓库提供的 systemd unit 使用 `Delegate=memory` 和 `DelegateSubgroup=daemon`，需要 systemd 254 或更新版本；自行定义服务时也需设置这两项。Node 和 jq 的资源组始终位于所属服务内部，不会向上越过 service、scope 或 slice 边界寻找权限。因此服务的 `MemoryMax` 仍覆盖 dae、本服务内的全部 worker，以及重载期间同时存在的新旧实例。其他进程管理器需事先把 dae 放入叶子组，并提供已启用 memory 控制器的可写父组；dae 不主动迁移宿主进程。委派不足时加载失败，不降级为无限额运行。内核 OOM kill 会作为明确的脚本执行错误返回；它可能由 worker、祖先组的限额或宿主整体内存不足触发，不能仅凭该事件认定 worker 达到自身上限。故障进程及其后代被回收后可创建替代进程。清理失败会保留资源所有权并在后台重试，期间暂停该池的新任务；清理完成后恢复接单，已经进入最终关闭的池则不会恢复。

`dae plugins surge status` 和 `dae plugins status --verbose` 显示进程池忙碌/空闲数量、容量、启动/复用/回收/失败计数及 RSS/PSS。另行显示 cgroup 当前用量、峰值、上限、内核 OOM-kill 次数及其采样年龄；这些值与 Prometheus 共用缓存。内存每 5 秒后台采样，查询只读取缓存；输出同时显示采样覆盖的进程数和最旧样本年龄，未采样不代表零占用。PSS 按比例分摊共享页，比直接相加 RSS 更适合观察进程池内存。Prometheus 提供同口径的 `dae_plugin_surge_nodejs_*` 指标，详见[指标说明](../../en/configuration/metrics.md#surge)。启动探测使用独立的临时进程池，不计入业务进程计数；准备阶段保留的预热进程计入业务启动计数，实例关闭不计入失败或空闲回收。

两个后端使用同一套 Surge API、存储、定时器与 Go HTTP 客户端；脚本主动请求仍受 dae 出站策略和正文预算约束。脚本可通过 `$environment['dae-runtime']` 读取 `quickjs` 或 `nodejs`。Node.js 后端不暴露 `process`、`require`、原生模块、文件或直接网络 API，也不继承 `NODE_OPTIONS`、`NODE_PATH` 等进程环境配置。它使用独立上下文与 Node 权限模式，但 [node:vm 不构成安全沙箱](https://nodejs.org/api/vm.html)，应只加载可信脚本。

### 持久存储

存储按 **实例 × 有效执行域 × key** 分区。本机调用始终共享实例的本机分区。实例 `isolate_lan` 默认 `true`；dae 模块描述符可设置模块级 `isolate_lan`，也可用 `script { name: '脚本名' isolate_lan: false }` 逐脚本覆盖。优先级为**脚本覆盖 > 模块覆盖 > 实例默认**，未声明时逐层继承，适用于 HTTP request/response、DNS、cron 和 generic。sgmodule、JavaScript 和持久化 key 均不需要修改。开启隔离的 LAN 调用按宿主确认的直连设备 MAC 使用独立分区；来源未知或 LAN 身份不能确认时，`read` 返回 null、`write` 和删除返回 false，不使用 IP、网关 MAC 或零 MAC 猜测本机。关闭隔离后，所有来源共用本机分区。默认文件例如 `/var/lib/dae/plugins/surge/surge-store.json`；实例改名使用新文件，旧文件保留。`store: false` 仅控制持久化，不改变隔离规则；不读取或修改已有文件，重载后内存数据丢失，重新开启后首次访问时恢复文件内的数据。

运行时构造不读取 store 内容；绝对路径和 symlink 规范化仍可能访问文件系统元数据。`Warm` 不执行用户脚本，不访问 store 的脚本和 `Close` 也不读取或写回 store；未实际访问时，不创建存储目录、JSON 或 `.lock`。首次 read 或 write 才加载最新文件，即使此前没有 read，首次 write 也先载入快照再修改单键，保留其他键。坏 JSON、FIFO、权限等存储错误延至实际 read 报错或 write 返回 false，不会因构造或预热而提前报错；失败不以空缓存覆盖坏文件，修复后可重试。

同一文件的 JSON 结构为 `分区 → keys → strings`，本机使用保留分区名，设备使用规范 MAC；全部分区合计上限为 64 MiB，单值上限为 4 MiB。同一实例、同一有效执行域内，HTTP、DNS、cron 和 generic 按原 key 共享，不按脚本或模块另行切分；省略键时使用解析后的 script-path，相同路径共享默认条目。显式键须为不含路径分隔符的非空字符串，值只接受字符串，null 删除。写入通过同目录的 `surge-store.json.lock` 跨进程锁保护，合并最新数据后原子替换；读取检查文件身份、大小和修改时间，仅变化时重新加载 JSON。锁等待受脚本超时约束，数据和锁文件使用 `0600`。单次键写入有并发保护，多次 read/write 不构成事务。

抓取 Cookie 的 capture 脚本与读取它的 cron/generic 脚本必须采用一致的隔离策略，并选择同一有效执行域，才能读取同一份状态。例如在 dae 的 Surge 实例中，将模块内名为 capture 和 job 的脚本设为共享，其他脚本仍按模块默认隔离：

```text
module {
  account {
    link: 'file:modules/account.sgmodule'
    isolate_lan: true
    script { name: 'capture' isolate_lan: false }
    script { name: 'job' isolate_lan: false }
  }
}
```

若整个模块都需要共享，直接设置模块的 `isolate_lan: false`，不必列出各脚本。`script` 描述符可重复，但每项必须包含非空 name 与布尔 isolate_lan，同一名称不能重复配置。名称按模块参数替换和条件筛选后的脚本名精确匹配，可包含中文、点号和空格；未找到或匹配多个定义会拒绝加载。不同模块的同名脚本互不影响。描述符可与 `arguments {}` 共存，不新增 Surge 参数或头部元数据；远程模块更新不会覆盖本地策略，但脚本重命名或移除后需要同步调整描述符。

关闭隔离会有意让不同客户端与本机共享 Cookie/token，后写入的数据可能覆盖其他账户。更改隔离设置只改变访问的分区，不自动迁移、合并或删除已有分区。MAC 是设备标识而非认证凭据，更换或复用 MAC 会改变或继承对应分区。

### MAC 变更后的数据迁移

设备更换 MAC 后，可通过运行中的 daemon 移动该设备的整个脚本存储分区：

```bash
dae plugins surge store migrate 02:00:00:00:00:11 02:00:00:00:00:22 --instance surge
# 自动化调用可追加 --json；独立 dae-client 使用相同的 plugins 子命令。
```

位置参数依次为旧、新 MAC。先停止旧 MAC 的流量并取消其后台执行资格，核对新地址和目标分区，再执行迁移。新旧设备无需在线或当前启用 MITM；命令需要管理员访问权限。未指定 `--instance` 时只允许唯一 Surge 实例，不会批量处理多个实例。

- 迁移保持所有 key/value 原样，成功后删除旧分区；不按脚本或模块切分，不涉及本机分区。
- 源分区不存在返回 `404`；目标分区已存在（即使为空）返回 `409`，不覆盖、不合并，也没有强制模式。非法或相同 MAC 返回 `400`。
- 源或目标 MAC 有脚本正在执行时返回 `409`，不会中断脚本；待其完整清理后可重新执行命令。无关设备、本机和 unknown 执行不构成该冲突。磁盘写入复用原有锁与原子替换，锁等待受服务端五秒 context 预算约束，文件系统 I/O 不保证可即时中断。
- 成功后，使用同一 store 的设备域 DNS 脚本缓存失效，本机缓存不变；已在途的响应和外部 DNS 缓存不能撤回。
- 不迁移通知、任务历史、MITM 授权、client 集合或路由规则，也不改写排队任务的 MAC。迁移不是永久别名：旧 MAC 的新执行仍可能重新创建旧分区，设备授权需另行调整。
- `store: false` 只移动当前运行时的内存数据，不读写磁盘或增加跨重载保留能力；实例没有脚本运行时则返回 `503`，不打开历史文件。

成功返回移动的键数量；`--json` 包含 `instance`、规范化的 `from_mac`、`to_mac` 和 `keys_moved`，不输出存储值。若原子替换已完成但目录同步失败，会返回 `500` 并明确提示迁移已发布、持久性未确认：数据已经移动，不应自动重试。超时或连接中断也不证明数据未变，CLI 不自动重试。

执行期保护覆盖当前 daemon 及同路径的重载代际；跨进程文件锁只保护单次更新，不能保护另一进程整段脚本的读—计算—写。如果另一个进程也操作同一存储，迁移前必须停止其写入。MAC 不是身份认证；迁移可能转交 Cookie/token，管理员应确认新 MAC 属于预期设备。

## 模块参数与交互配置

模块用 `#!arguments=名称:默认值,...` 声明参数，在正文中写 `{{{名称}}}`。中文名称可用、大小写敏感；参数按原文替换，不自动 JSON 编码。未知或重复参数、未提供的必填项、值中的换行/NUL 会报错。

```sh
dae plugins surge configure 'file:modules/youtube.sgmodule' \
  --name youtube > youtube-module.dae
```

命令显示模块说明和参数，直接回车继承默认值，显式输入固定该值，`""` 表示空字符串；无默认值必须填写。仅显式参数值和隔离覆盖写入配置，两者都未设置时生成简写。`--name` 默认 `module`。

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

也可手工填写 `'名称=值'`，`'名称='` 表示空值。命令读取模块，以及参数替换、条件过滤后启用的脚本。相对脚本路径以模块最终 URL 或本地目录为基准，重复脚本 URL 只读取一次；不加载 Host 集合、Map Local 等其他资源。脚本不会执行，source map 不会读取，也不会写入配置、脚本存储或磁盘缓存。读取使用主机网络及 `HTTP_PROXY` / `HTTPS_PROXY`，并沿用现有资源上限和超时预算；来源语法与上表一致。任一脚本读取失败都会终止生成，不输出配置片段。

### 存储隔离问答

只有语法分析识别到未被局部绑定遮蔽的 `$persistentStore.read(...)` 或 `.write(...)` 调用时，才显示隔离选项；也支持方法名为 `"read"` 或 `"write"` 字符串字面量的下标调用。注释、字符串、正则表达式和同名局部绑定不算命中。这只证明存在调用表达式，不证明相应分支一定执行。别名、动态属性名、生成代码可能无法确认；`eval`、`with` 或明显 API 改写也可能阻止确认。不支持的语法会产生警告，不等于证明脚本无状态。`$prefs` 和 Web Storage 不是 dae 的存储接口。没有确认的调用时，跳过隔离问答，不生成隔离覆盖，保留原有继承关系。

至少一个脚本命中时，先选择模块策略，再按需选择单个脚本：

```text
Module isolation [inherit/isolate/share, Enter=inherit, cancel]: share
Script override [Enter=done, list, <number>, cancel]: list
1  "capture" (http-request) [inherit]
2  "refresh" (cron) [inherit]
Script override [Enter=done, list, <number>, cancel]: 1
Policy for "capture" (inherit from module) [inherit/isolate/share, Enter=inherit, cancel]: isolate
Script override [Enter=done, list, <number>, cancel]:
```

脚本目录只包含确认命中的名称，并按名称排序。歧义检查覆盖所有脚本，包括未确认项；歧义名称不能设置单脚本覆盖。`inherit` 删除覆盖，`isolate` 写入 `isolate_lan: true`，`share` 写入 `isolate_lan: false`；显式选择即使与父层当前值相同也保留。可重复选择脚本进行修改，回车保留当前策略；在脚本选择处回车结束，在隔离问答中输入 `cancel` 取消整个配置片段。完成前遇到 EOF 会报错，不视为默认答案。参数问答仍把 `cancel` 当作普通参数值。

模块策略作用于**模块内的所有脚本**，包括未确认项；过滤只限制交互选择入口。`share` 让 LAN 客户端与本机执行共享状态，可能混用 Cookie 和 token。首次选择共享时会提示风险，但不会迁移、合并或删除已有数据。本机执行仍保持本机身份。命令不读取或修改实例设置；模块继承在片段加载时使用实例策略。无法静态确认存储调用的脚本，仍可手写已有描述符。

以 `accounts` 模块为例，上述选择生成：

```text
module {
  accounts {
    link: 'file:modules/accounts.sgmodule'
    isolate_lan: false
    script {
      name: 'capture'
      isolate_lan: true
    }
  }
}
```

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

字面 IP 映射对 direct 和 proxy 生效，优先于 `dial_target_override`，不影响代理服务器自身地址。域名条目的静态 DNS TTL 为 60 秒；系统与脚本默认 TTL 为 0。脚本返回地址及正 TTL 时，结果按有效执行域、脚本、域名和插件链缓存：本机与关闭隔离的脚本共享本机缓存，开启隔离的 LAN 结果按可信 MAC 区分，同设备 IP/端口变化不影响归属；命中返回剩余 TTL。有效执行域 unknown 或 TTL 为 0 时绕过缓存，每次执行。每实例最多 4096 条，过期或插件实例、顺序变化后重新执行脚本，仅路由变化的重载保留结果。存储复用公共有界 LRU，但合成结果不混入上游答案。

### 限制客户端来源

`client_source_address` 支持 IPv4/IPv6、CIDR、MAC、`all` 和 `-` 排除；逗号或重复字段按顺序拼接，首个匹配项决定结果。IP 与 MAC 独立匹配。未填写或未匹配时关闭；全部启用必须显式填写 `all`，例如：

```text
client_source_address: '-02:00:00:00:00:10,all'
```

也可在[全局页面/API](api.md)的 **HTTPS Modules** 区域为当前设备选择 **On** 或 **Off**，设备覆盖优先于配置；选择 **Router default** 清除覆盖。安装步骤见[证书文档](certificate.md)。

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

jq 的解析、编译、JSON 解码与执行由 Surge 插件启动同一 dae 二进制的内部工作进程完成，使用 gojq，不需要外部 jq。所有 Surge 实例及重载期间的新旧实例共享最多 4 个进程，每个进程同时执行一个任务，额外等待任务最多 16 个。网络正文读取完成并取得实例的 `max_concurrent_scripts` 名额后，正文解码、jq 工作进程排队和执行共用 `script_timeout`；队列满、超时、进程退出或超限均保留前一步正文。取消时终止并回收对应进程，后续任务按需创建新进程。每个进程缓存最多 32 个已编译表达式，单表达式最多 64 KiB；正文传输受 `max_body_size` 约束，返回正文仍计入宿主共享正文预算。

包含 jq 规则的模块需要可写的 cgroup v2 memory 控制器：每个 worker 的 `memory.max` 为 128 MiB，整个池为 512 MiB，`memory.swap.max` 为 0。加载时验证限额并在受限进程中编译表达式；无法建立限制时报错。未使用 jq 时不创建这些资源。限额涵盖 worker 的解析对象、求值中间对象和进程开销，内核允许某些情况下短暂超限，不能将其视为逐瞬间的 RSS 上限。复杂表达式或大正文即使未超过正文大小限制，也可能因进程内存不足而保留原文。最后一个使用 jq 的实例关闭后，工作进程及其 cgroup 一并回收。

## 转发与协议

启用 HTTP scope 后，仅按模块的正向 hostname 和对应端口捕获 TCP/UDP 候选连接，再按实际主机名、排除项和客户端开关决定是否解密。无关 direct 流量保留 eBPF 内核直通。含脚本、URL Rewrite 或 Map Local 的模块先执行 HTTP 处理，随后按最终目标执行目的地址规则 → flow → 模块 pre-matching 拒绝 → dae 显式规则 → 普通模块规则 → fallback。原目标的 block 不会抢先阻止这些已准入的请求；新目标命中 block 则拒绝。未准入客户端仍按普通连接路由处理。

HTTP 转发和脚本 `$httpClient` 共用请求路由：原主机及端口使用截获 IP（代理连接按 `dial_target_override` 发送域名），其他目标经系统解析器解析，每个地址分别执行目标规则和路由，保留客户端来源、接口及策略。请求型模块在 HTTP 处理后确定路由；纯检查模块保留原路由。出站、节点、mark 或实际目标变化会隔离连接池。302/307 返回客户端请求新目标，reject 和 Map Local 可直接生成响应。

支持 HTTP/1.1、TLS HTTP/2 和 HTTP/3（QUIC v1/v2）。HTTP/3 自动使用现有 CA、客户端开关和 hostname 范围；只有完整 ClientHello 的 ALPN 包含 `h3` 才解密，其它 QUIC/UDP 保持转发。客户端与上游都使用 HTTP/3，支持同一源/目标/域名下多连接及重连；上游握手失败不会自动改用 TCP 重试。HTTP/3 上游按最终目标匹配 UDP 路由；命中 block 时不会建立上游连接，模块的本地响应仍可直接返回。

若希望拒绝特定目标的 HTTP/3 上游，可在已有 `routing` 段前部加入对应规则（客户端是否重试 TCP 由客户端决定），例如：

```text
domain(httpbin.org) && l4proto(udp) && dport(443) -> block
```

内核的域名捕获依赖已有 DNS 域名—IP 映射；缺少映射时不会通过捕获全部 TCP/UDP 或仅按 HTTPS 端口捕获来兜底，原本的 direct 流量继续在内核转发。已因其他规则进入用户态的连接仍可使用 SNI/Host。共享 IP 可能带入额外候选，最终匹配和普通出站路由仍受各自的 scope、域名验证策略约束；无法嗅探主机名、ECH 或证书固定可能使处理失败。HTTP/2 和 HTTP/3 允许同端口跨主机 authority 复用，普通转发保持原接入目标。TLS HTTP/2 收到 `:scheme=http` 时返回 421，详见 [请求 scheme](../design/mitm-http.md#请求-scheme)。HTTP/3 暂不支持跨地址迁移、0-RTT、WebTransport/CONNECT-UDP。仅保留上游同主机、同端口的 H3 Alt-Svc 广告。WebSocket 只处理 HTTP/1 握手。

## 脚本 HTTP 请求

`$httpClient` 和基础 `fetch` 使用宿主路由、正常 TLS 校验及共享正文预算。`policy` 可填 `DIRECT`、`REJECT` 或当前已加载的 dae 出站组名；仅由脚本使用的组须在插件设置中写 `http_policies: proxy,api`，否则未被路由引用的组不会加载。它仅覆盖主动请求的出站，保留目的地址规则、客户端身份及 mark，并在重定向时沿用。未知或不可用的组返回错误。`policy-descriptor` 和 `insecure: true` 会明确报错；`insecure: false` 保持正常 TLS 校验。

自动重定向逐跳禁止 HTTPS 降级到 HTTP，包括 HTTP 升级到 HTTPS 后再跳回 HTTP；拒绝时通过原有回调或 Promise 返回错误。跨域重定向、直接 HTTP 请求及 HTTP 升级到 HTTPS 均可用。`$httpClient` 的 `auto-redirect: false` 和 fetch 的 `redirect: "manual"` 仍返回原始 30x 响应。

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

`TASKS` 按 cron 和 generic 脚本定义计数（包含在 `SCRIPTS` 总数中），不会因多个执行域重复计数。`Surge script tasks` 按有效执行域显示：每个脚本始终有本机行，只有开启隔离才有设备行，本机在前、设备按 MAC 排序。`SCOPE` 显式区分 `local`、`device MAC …` 与 `unknown`，不能根据空 MAC 推断本机；unknown 不是可执行任务目标。其余列为类型、表达式、时区、超时、当前状态及下次执行时间；generic 没有定时字段。`Last script runs` 按相同执行域列出最近一次尝试、耗时、结果和运行/失败/重叠跳过次数。`TRIGGER` / `last_trigger` 为 `cron` 或 `http-api`。JSON 对应 `details.modules[].tasks`，每行显式包含 `scope: "local"|"device"`，仅 device 带 `mac`。也可用 `./dae plugins status -v` 查看。

需要 LAN 目标时，目标列表在插件启动、定时到期和指定 MAC 手动触发时刷新；启动及定时发现异步进行，最多一个自动查询在途，本机任务的准入和派发不等待它。status/list 只读取最近快照，不做设备发现 I/O；展示快照不作为新设备任务的授权依据，设备执行前仍复核当前资格。LAN 查询失败不阻断本机执行，也不沿用旧 LAN 目标派发任务；已知非 busy 设备行显示 `unavailable/device_query_failed`，没有设备行时通过模块 Warnings 报告。运行中的任务保留真实状态。查询恢复清除发现告警，不抹除执行历史；正常快照确认移除且没有进行中任务的设备会从列表删除，其计数不作为持久历史保留。全部脚本关闭隔离时不查询 LAN 目标。

状态包括 `unavailable`（LAN 目标查询失败）、`pending`（等待插件激活）、`ready`（generic 可手动运行）、`scheduled`、`waiting`（等待共享名额）、`running`、`unscheduled`（cron 没有可计算的下次时间，如 2 月 31 日）和 `stopped`。本机不受 LAN 发现状态影响；没有设备时仍保留正常本机行。LAN 批量发现完成、确认目标后才创建执行记录；起止时间与超时包含准入后的共享名额排队和执行前资格复查，不包含此前的批量发现；`last_error` 只提供 `timeout`、`canceled`、`error`、`device_query_failed` 等类别，详细异常见日志。`success` 仅表示脚本正常调用 `$done`，不保证业务操作成功。

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

启用 `trace` 后，Surge 请求与脚本事件通过结构化 `event` 字段标识，使用 `connection_id` 和 `request_id` 关联。脚本事件的 `scope` 报告有效执行域，仅 device 带 MAC；共享模式的 LAN 请求显示 local。`script_end` 含脚本、阶段、耗时与 outcome；加载成功不代表脚本已执行，执行 success 也不保证应用效果。没有 `request_begin` 时依次检查来源开关、hostname、TCP/QUIC、TLS 信任、域名验证策略和网卡绑定。自动事件不记录 URL 路径、查询参数、认证头和正文，脚本自行打印的内容不受此限制。

### 近期通知

脚本调用 `$notification.post(title, subtitle, body)` 时，除 info 日志外，还会在当前实例内存中**按有效执行域与脚本各保留最多 50 条**通知。分组为 scope、MAC、模块名、脚本名与类型，HTTP 请求/响应、DNS、cron 和 generic 均支持。`scope` 明确为 `local`、`device` 或 `unknown`，仅 device 带 `mac`，本机与未知来源不会混组。展示的是有效执行域而非原始来源：关闭隔离的 LAN 请求显示 local，不表示其来源已被认证成本机。普通 `console.log` 不计入。

每个实例另有 **1 MiB 的保守 JSON 编码预算**（包含 scope、MAC，文本按最坏转义长度计费）。超限时优先从记录最多的执行域与脚本分组删除最旧记录，记录数相同则删除最旧的一条。高频分组先缩短自己的历史；分组总量仍超过预算时也会淘汰较旧单条历史。因此每组实际可能少于 50 条，verbose/JSON 返回预算内全部记录。MAC 不加入 Prometheus 指标标签。

```sh
dae plugins surge status --instance surge
dae plugins surge status --instance surge --verbose
dae plugins surge status --instance surge --json
dae plugins status -v
```

文本输出的 `Recent Surge notifications` 默认**每执行域每脚本显示最近 3 条**，包含时间、实例/模块/脚本、执行域及设备 MAC、类型和正文，最新在前。有省略时提示隐藏数量；`--verbose`（`-v`）与 `dae plugins status -v` 展示全部保留通知。不同实例、执行域和模块中的同名脚本分别计数。

`--json` 始终返回全部保留记录，位于实例的 `details.notifications`，也可从 `GET /api/status` 的 `plugins[].details.notifications` 获取；无通知时省略该字段。同一执行域与脚本超过 50 条时淘汰最早记录，重载/重启清空。例如：

```json
{
  "id": 3,
  "created_at": "2026-09-29T09:05:00+08:00",
  "module": "cron_demo",
  "scope": "device",
  "mac": "02:00:00:00:00:50",
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

插件激活后安排下一次未来执行；准备模块时不运行，启动不补跑历史任务。每次到期始终执行**本机一次**；该脚本有效隔离开启时，再对**当前 MITM 启用的 LAN 设备**每 MAC 执行一次，关闭隔离时所有来源共享本机状态且只执行本机一次。LAN 资格要求宿主 MITM 开启、CA 就绪；显式启用 MAC 不要求在线，`all`、IP 和 CIDR 只枚举宿主已知 LAN 设备，设备显式关闭覆盖配置。本机不依赖设备服务、LAN 目标、MITM 开关或 CA，慢查询或查询失败都不阻断本机准入和派发。自动发现未完成时，每个脚本只保留一项 LAN 待办，重复到期合并为 skipped，不逐次补跑；后来到期的其他脚本使用后续的新查询。运行中错过多个时间点时，每个到期任务对每个执行域至多触发一次，再安排未来时间。同一任务同一有效执行域仍在等待/运行时，定时触发记为 skipped，手动触发返回冲突；发现期间已完成的重叠执行也不迟到补跑，其他执行域独立。全部任务共用 `max_concurrent_scripts`，本机没有独立或优先名额；预算从实际准入开始，包含共享名额排队、执行前资格复查、JS 和 HTTP，不包含此前的批量发现。默认继承 `script_timeout`，脚本 `timeout` 优先。重载/停止取消任务、自动发现及 HTTP 请求并等待清理，新实例重新调度、重置运行历史与计数。

设备候选来自当前 MITM 策略中的 MAC、已发布路由及其引用的 clientset MAC，以及 LAN 邻居表，不从脚本存储或流量统计推断。仅导出 ipset/nftset、未被路由引用的离线 clientset 成员不会单独成为候选。无 IP 的候选只能按不依赖 IP 的确定结果执行；设备覆盖设为 On 不要求在线。`all` 或 CIDR 无法枚举宿主从未识别到的终端，也不会触发主动扫描。

运行时提供 `$script.type = "cron"`、`$cronexp` 和配置的 `$argument`，不注入 `$request`/`$response`；必须调用 `$done()`，返回值被忽略。同一实例、同一有效执行域的 HTTP/DNS/generic 共享 `$persistentStore`，capture 与 cron 的隔离设置须一致；`store: false` 可关闭持久化。后台 `$httpClient` 使用 daemon 路由，选定 MAC 只决定状态归属，不模拟设备网络来源。纯 cron 模块无需 MITM hostname，也不新增捕获规则，本机任务无需 MITM/CA；LAN Cookie 抓取仍须满足 hostname、证书信任、设备开关和 DNS 映射条件。

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

在实例的 `module` 段加入 `tools: 'file:modules/tools.sgmodule'`，重载后使用 `dae plugins surge run demo.tool --instance surge --module tools` 在本机执行。

运行时提供 `$script.type = "generic"`、`$trigger = "http-api"` 和配置的 `$argument`，没有类型专用输入。必须调用 `$done()`，手动执行忽略其返回值，未调用则等待超时。每次执行使用独立 VM。

generic 与 cron 共用后台执行器、有效执行域存储与通知、daemon 路由 HTTP 客户端及共享执行名额；超时包含排队。同一任务同一域等待/运行时拒绝重复触发。插件激活后本机目标为空闲 `ready`，不依赖 MITM、CA 或设备服务；开启隔离的设备目标仍须满足当前 MITM 资格。停止/重载取消并等待清理。纯 generic 模块无需 MITM hostname，也不产生捕获规则。

## 手动触发

daemon 运行时，先列出支持手动执行的 cron 和 generic 脚本，再按列表中的 `SCRIPT` 名称触发：

```sh
dae plugins surge list
dae plugins surge list --instance surge --module cron_demo
dae plugins surge list --json
dae plugins surge run demo.cron --instance surge --module cron_demo
dae plugins surge run demo.tool --instance surge --module tools
dae plugins surge run demo.tool --instance surge --module tools --mac 02:00:00:00:00:50
dae plugins surge status --instance surge
```

`list` 按有效执行域显示实例、模块、脚本名、scope/设备 MAC、类型、状态和 cron 表达式，并给出用法。它只读取 daemon 已加载的 cron/generic 任务快照；HTTP 与 DNS 不在手动列表中。`--instance`、`--module` 可组合筛选；`--json` 返回含 `instance`、`module`、`scope`、可选设备 `mac` 及任务字段的扁平数组，无匹配定义时为 `[]`。每个定义都有本机行；同一实例/模块/名称的多个执行域行不构成名称歧义。

等待或运行中的任务仍会列出，同任务同执行域重复触发返回冲突；`unscheduled` cron 仍可手动运行。名称含空格时加引号，例如 `run '演示任务'`。

脚本名唯一时可省略 `--module`，跨实例也唯一时可省略 `--instance`。**省略 `--mac` 始终执行本机一次**，不会自动选择唯一 LAN 设备。`--mac` 只用于开启隔离的脚本，选择当前 MITM 启用设备；关闭隔离时显式指定 MAC 会返回 `400`，要求省略 MAC，不会静默改为本机。命令返回有效执行域与运行编号，任务由 daemon 继续执行，结果从 status 查看；`--json` 的 `status.scope` 标识执行域，仅 device 有 `status.mac`。`run` 对应该执行域本任务的 `runs`，仅当前实例生命周期内有效；status 保留最新一次尝试，重载重置。手动执行不改变定时计划；脚本内 `$trigger` 为 `http-api`，定时执行不注入该变量。

对应管理 API 为 `POST /api/plugins/{实例ID}/scripts/run`，本机正文如 `{"module":"tools","script":"demo.tool"}`，设备执行另加 `"mac":"02:00:00:00:00:50"`；需要管理权限及 `X-Dae-API: 1`。成功 `202`，不存在 `404`，名称歧义、MAC 格式错误或未隔离脚本指定 MAC 为 `400`，设备禁用或同执行域任务忙碌为 `409`，worker 未激活/停止或设备发现服务不可用为 `503`。不接受脚本文本或参数覆盖。

## 示例

将 [`demo.sgmodule`](../../../examples/surge/demo.sgmodule)、[`request.js`](../../../examples/surge/request.js)、[`response.js`](../../../examples/surge/response.js) 放入 `/var/lib/dae/modules/`，使用首个配置示例。从已信任 CA 的客户端访问 `https://httpbin.org/get`，请求增加 `X-Dae-Runtime`，响应增加 `dae.runtime`，其值为编译时选定的 `quickjs` 或 `nodejs`；`/dae-redirect` 测试 302。

API 支持范围、行为差异和限制见[支持范围](surge-module-support.md)。
