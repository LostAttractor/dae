# API 与独立客户端开发

`dae status`、`dae status --verbose`、`dae status --recent` 和 `dae plugins surge status` 通过 HTTP API 读取运行状态，Web 通过 API 获取状态和修改设置。独立客户端无需加载配置、读取运行时状态文件、链接 QuickJS 或生成 eBPF。

## 构建与使用

需要 Go 1.27.2+；可在 `nix-shell` 中运行：

```sh
make client
sudo ./dae-client status
./dae-client status --api https://192.168.1.1:9080 --recent
./dae-client plugins status --api https://192.168.1.1:9080 --json
./dae-client plugins status --api https://192.168.1.1:9080 --verbose
./dae-client plugins surge status --api https://192.168.1.1:9080 --instance personal
./dae-client status --api unix:///var/run/dae.sock --json
```

`make client` 等价于 `CGO_ENABLED=0 go build -trimpath -o dae-client ./cmd/dae-client`，不执行 `make ebpf`，不需要 clang、内核头文件或初始化守护进程所用的 submodule。Go 模块下载仍需要网络或已有缓存。独立客户端也可交叉编译，例如 `GOOS=darwin GOARCH=arm64 make client`。

连接参数对两种命令入口相同：

| 参数 | 默认值与含义 |
| --- | --- |
| `--api` | `DAE_API_ENDPOINT`，未设置时为 `unix:///var/run/dae.sock` |
| `--timeout` | `10s`，单次请求超时；取消命令上下文也会取消请求 |
| `DAE_API_KEY` | `user_key` 或 `admin_key`；仅 HTTPS 发送 Bearer 凭据 |
| `--api-key-file` / `DAE_API_KEY_FILE` | 从文件读取 key，优先于 `DAE_API_KEY` |
| `--api-ca` / `DAE_API_CA` | 严格固定客户端 TLS 仅信任该 PEM CA 文件 |
| `--json` | `status` 输出完整 API 快照，与 `--verbose`、`--recent` 互斥；MITM 报告命令输出筛选后的实例数组 |
| `--color` | `status` 文本输出的颜色模式：`auto`（默认）、`always` 或 `never` |

`status --color always`（也可写成 `--color=always`）在管道或重定向输出中仍保留 ANSI 颜色，`--color never` 强制禁用颜色；两者均覆盖环境变量。默认的 `auto` 沿用终端检测及 `FORCE_COLOR`、`NO_COLOR`、`TERM` 设置。该选项适用于普通、`--verbose` 和 `--recent` 文本视图，`--json` 始终输出无颜色的 JSON。使用 `watch` 时还需加上它的 `--color`（`-c`）选项来显示颜色：

```sh
watch --color -n 2 'dae status --recent --color always'
```

独立客户端同样支持，例如 `watch --color -n 2 'dae-client status --recent --color always'`。

等待 API 响应的命令（`status`、`selector`、`client`、`explain` 及插件的 status/list/run/store migrate 命令）在等待超过 150 ms 后，通过终端 stderr 显示加载动画，并在输出结果或错误前清除。`--json`、stderr 重定向或 `TERM=dumb` 时禁用动画，stdout 可正常用于管道和重定向。脚本 run 命令只等待请求被接受，不等待脚本执行结束。

### 管理 selector

`dae` 和 `dae-client` 均提供以下命令：

```sh
dae selector                         # 列出所有 selector 及候选，* 表示实际选择
dae selector proxy                   # 查看单个组和候选 ID
dae selector set proxy '香港 01'      # 按完整显示名称选择
dae selector set proxy NODE_ID       # 按候选 ID 选择，可区分重名或不同入口
dae selector reset proxy             # 清除保存偏好，恢复显式 selector(n) 默认
dae selector proxy --json
```

节点名必须精确匹配；重名时要求使用 ID，不按列表顺序猜测。`--api`、`--timeout`、`DAE_API_ENDPOINT` 和 `DAE_API_KEY` 与 status 相同。选择与持久化由守护进程负责，CLI 不直接修改状态文件。保存路径缺失或有歧义时，文本输出同时显示保存偏好和临时实际选择；后续 reload 可恢复返回的路径。没有显式默认的 selector 不支持 `reset`。

本地 socket 权限仍为 `0600`，不依赖 `api.listen`。两种命令入口均不自动提权；访问默认 socket 时使用 `sudo` 或已有的文件系统权限。

使用 Unix socket 时，CLI 不读取远端 key 和 CA 文件，SDK 也不发送 Bearer key。

TCP 需要启用 [API 配置](api.md)。通过 HTTPS 使用 `user_key` 或 `admin_key` 时，设置 `DAE_API_KEY` 或 `--api-key-file`；只有显式开启 `allow_lan_anonymous`，已验证 LAN 入口的客户端才可以无凭据查询状态。客户端忽略环境中的 HTTP 代理，不跟随重定向，避免改变设备身份或把密钥发往其他地址。原生直连使用实际 API IP:port，并信任 daemon CA；也可把 endpoint 指向下述 HTTPS 反代的域名并信任其前端证书，但自身设备接口及 CA/MITM 验证必须直连。CLI、SDK 和 Prometheus 使用显式 key，不需要浏览器 Cookie；无 Origin 的 key 请求不受 `web_origins` 限制。

Go SDK 自建 transport，不依赖应用对 `http.DefaultTransport` 的修改。未设置 `client.Options.Timeout` 时，普通请求默认 10 秒；`Profile` 自动使用实际采集时长加 10 秒传输余量，例如默认 CPU 采集 30 秒对应 40 秒请求超时。显式 Timeout 和调用者 context 仍优先约束请求；profile 不修改并发共享客户端的超时。成功响应上限为 32 MiB，错误正文上限为 8 KiB；错误正文过长时仍可通过 `client.Error.StatusCode` 判断 HTTP 状态。

状态表中的 `UP/24H` 和流量的 `AVG/MAX` 使用复合表头，与数据共用各子字段的宽度：标题与数值都从各自字段左侧开始，`/` 在各行中的位置固定。显示宽度计算支持中文和 ANSI 颜色。

## 容量表

普通、`--verbose` 和 `--recent` 状态视图渲染同一份 `tables` 快照。`domain-registry (unlimited)` 显示配对数、域名数、IP 数、地址类型和 GC 明细；其余表与资源池按 `Kernel tables`、`Userspace tables` 分组，以 `NAME`、`USED`、`LIMIT`、`USAGE%`、`ON FULL` 紧凑展示，包括内核动态 hash/LRU 表和全局 UDP source、packet resource、reply socket 三个池。`--verbose` 列出全部条目；普通和 `--recent` 视图只列出需要关注的条目（包括 registry）：用量不可用、有待重试的内核变更、有被省略的候选，或 `reject` 表使用率达到 70%，没有这类条目的分组整体省略。`domain-kernel` 的说明保留 `CANDIDATES`、`OMITTED`、`PENDING`；pending 表示等待重试的内核变更。

每项的 `scope` 为 `kernel` 或 `userspace`，`on_full` 描述满载行为：`evict` 按 LRU 淘汰已有条目，`reject` 拒绝新增，`omit` 不把超额域名候选投影进内核，`unlimited` 无容量上限。`limit: 0` 始终表示无限容量。LRU 满载属于正常淘汰，不等于硬耗尽；只有 `reject` 的使用率应用容量告警色。非空 `error` 表示 `used` 不可用，文本显示 `unavailable` 及具体错误，不显示误导性的零或 0%；`--json` 原样保留这些字段。Web 的 **Tables** 区域使用相同的范围、满载行为和可用性字段。插件自定义报告仍单独显示在插件状态中。

## 流量表

对于 `selector` 组，API 的 `nodes` 只包含当前选中、持续追踪、正在测试或仍有活动连接的节点；所有 status 模式均遵守此范围，组及全局统计仍保留未展示路径的累计量。完整候选及其上次测试结果通过 `/api/selectors` 查询。

所有文本状态模式都在底部显示统一的 `Traffic` 表：

```text
GROUP / DIALER       UPLOAD 1M     DOWNLOAD 1M   AVG /MAX ↑     AVG /MAX ↓     TOTAL ↑  TOTAL ↓
ALL                  ▂▂▂▂▂▂▂▂▂▂▂▂  █▂▂▂▂▂▂▂▂▂▂▂  54.3/146Kbps   2.48/20.8Mbps  7.21M    85.5M
direct              ▃▂▄▅▃▃▃▃▃▂▃▃  ▄▅▅█▄▅▆▄▃▃▃▃  2.77/6.00Kbps  5.26/11.2Kbps  63.5K    112K
proxy_jp(lightsail)  ▂▂▂▂▂▂▂▂▂▂▂▂  █▂▂▂▂▂▂▂▂▂▂▂  51.5/144Kbps   2.47/20.8Mbps  7.15M    85.4M
```

- 普通 status 显示有活动连接或累计有效载荷字节的 group，组内列出当前选中、有活动连接或累计字节的 dialer。`--recent` 只显示最近一分钟上传或下载样本非零的 group/dialer；仅有当前选择、活动连接或历史累计量不会保留该行。筛选后只有一个 dialer 时合并为 `group(dialer)`；多个时显示 `group (total)` 和缩进明细。同名但不同 ID 的 dialer 分开统计。`--verbose` 展开全部 group，并包含空闲 dialer。
- 内置 direct 在各模式下都使用一行 `direct` 展示组级总量，不重复展开同名节点。
- `ALL` 始终显示并使用全局统计；group 行（包括合并行）使用 API 的 group 统计，包含已退休路径。同一 dialer 在不同 group 中分别计量，各统计层级不应相加。`TOTAL ↑`、`TOTAL ↓` 是累计上传、下载的有效载荷字节数，跨 reload 保留，重启清零。
- `UPLOAD 1M`、`DOWNLOAD 1M` 使用最近十二个已完成的五秒吞吐样本，时间从左到右。同一行上下行共用高度尺度，各行分别缩放；没有历史时显示 `-`。
- `AVG/MAX` 位于趋势图之后、`TOTAL ↑/↓` 之前，显示同一窗口内已有样本的平均和最大比特率。完整表格超出终端宽度时，普通和 recent 视图隐藏这两个速率列；`--verbose` 始终包含它们。剩余溢出从右缘截断。
- `GROUP / DIALER` 标签列最多占 52 个显示列，超长以 `…` 省略；名称内部的空白统一为空格，确保每个条目只占一行。

## 近期状态视图

所有文本模式都单独显示内置 direct 的活动连接数、累计连接数及非零的 `Fallback Total`。direct 没有连通性检查或可用率历史；`--verbose` 额外显示其分网络连接数。内置 block 由 daemon 隐藏。

`status --recent` 每个代理组一行显示当前选择与连通性，底部再显示统一的流量表。例如无颜色输出：

```text
direct: 8 active · 120 total · Fallback Total 3

GROUP     STATE  24H      1H            SELECTED              ACTIVE
proxy_hk  UP     100.00%  [......++++]  香港 2                0
proxy_jp  UP     100.00%  [......++++]  lightsail             108
proxy_tw  UP     100.00%  [......++++]  台湾 3                0
proxy_us  UP     100.00%  [......++++]  美国 1                0
tor       UP     100.00%  [......++++]  tor                   0
```

- `ACTIVE` 显示组的活动连接数。fallback 是进程级的单一 direct 计数，不按节点、组或网络分别维护。它累计因无可用节点而回退到 direct 且在用户态成功建立的连接，不含内核直连转发的 fallback 流，跨 reload 保留，重启清零，不表示当前正在 fallback 的连接数。
- `SELECTED` 按 `selected_node_ids` 显示当前选中的节点。紧凑视图只列出已确认支持或已经有选择的网络；没有当前选择的 `unknown` 和 `unsupported` IP 家族、协议均省略。所有显示的网络选中同一节点时只写节点名。只有选择不同才用 `ipv4:`、`ipv6:`、`tcp:`、`udp:` 或具体网络名区分，并用分号连接。已确认支持但没有当前选择时显示 `-`；所有网络都没有选择时也显示 `-`。`random` 表示逐连接随机选择，没有稳定的组级节点。已有连接可能仍使用先前选择的节点。
- `STATE`、`24H`、`1H` 分列显示当前状态、时间加权可用率和十个六分钟连通性桶。表头和数据统一左对齐，百分比与历史图也保持各自固定的左侧起点。无颜色时 `+` / `x` / `.` 分别表示可用、不可用、未观察；彩色终端使用绿点、红点和灰色空心点。无连通性检查的组显示 `N/A`，可用率和历史显示 `-`。
- 组名最多占 18 个显示列，每个节点选择最多占 32 个显示列，超长部分以 `…` 省略，支持中文和 ANSI 颜色。表头、组行和全局摘要超过终端宽度时直接截断右侧，不生成续行，右侧的部分节点或计数可能因此不可见。无法获取终端宽度时不做整行截断。

## Web 独立更新

```sh
make web
# 或直接在前端目录构建
make -C web
```

`web/` 的前端源码、构建配置和测试均使用 TypeScript。`make web` 输出到 `build/web/`（可通过 `WEB_OUTPUT` 修改）；`make -C web` 输出到 `web/dist/`。两者需要 Make、Node.js 22.13+ 和 pnpm，不需要 Go；Make 会按需安装锁定版本的前端依赖，并在构建前执行严格类型检查。`dae-client` 只包含终端命令，不携带 Web 资源。

产物包含 `index.html`、`assets/` 下的 JavaScript 和 CSS、`dae-web.json` API 目标元数据，以及依赖许可声明。React 界面使用 Cloudflare 的 Kumo 组件，浅色/深色配色跟随系统设置，流量图表使用 Recharts 并自适应宽度。Overview 展示快捷节点选择、访问设备设置和状态；Setting 分区提供设备管理、全局节点选择与诊断。所有前端依赖均打包到本地资源中。要独立更新页面，将产物部署到目录，并给 dae 进程设置环境变量：

```sh
DAE_WEB_ROOT=/opt/dae-web dae run -c /etc/dae/config.dae
```

也可在服务管理器中设置 `DAE_WEB_ROOT`。该目录替代内嵌静态资源；资源按请求读取，替换完整目录即可更新前端，无需重新编译 dae。目录中的文件及子目录均为公开静态资源，只应存放前端产物；缺失资源返回 `404`。新增 JS、CSS 或嵌套资源无需修改 dae 路由。`/api/` 与证书下载路径由 API handler 优先处理。

流量图表在 Overview 有采样数据时按需加载。构建产物包含 gzip 文件，dae 根据客户端支持情况直接提供，无需运行时压缩。`assets/` 下文件名含内容哈希的 JS/CSS 使用一年期不可变缓存，HTML 与其他文件使用 `no-store`。发布时应一并部署所有分块及 gzip 文件，不得修改已有哈希文件名对应的内容。

静态产物可由 nginx 等服务器独立托管。`DAE_API_URL` 在开发和生产构建时固定 API 目标，未设置时使用相对 `/api/`；显式值只能是 HTTPS origin（可为反代域名），不接受路径前缀、userinfo、query 或 fragment。页面不提供运行时地址切换，也不在浏览器存储中覆盖该目标。修改目标后重新构建并完整部署产物。

前端常量与 `dae-web.json` 来自同一次目标解析。daemon 从实际内嵌或 `DAE_WEB_ROOT` 目录读取该元数据，结合证书证明目标生成 CSP，不另设一份 API 目标配置；元数据缺失或非法时不提供页面。独立静态服务器应使用与产物一致的 CSP：默认同源反代只需 `connect-src 'self'`，同站直连则仅放行固定 API 与所需证明端点，不能开放任意 `https:`。IPv6 的 CSP 主机约束存在浏览器限制，客户端和服务端仍校验精确端点。

### 同站直连

原生 dae API 只接受 IP 字面地址。以下示例把独立静态页部署到同一 IP 的 HTTPS 8443 端口，浏览器直连 dae 的 HTTPS 9080 端口：

```sh
DAE_API_URL=https://192.168.1.1:9080 make web
```

```text
global { lan_interface: br-lan }
api {
  listen: '9080'
  user_key: 'replace-with-a-user-key'
  admin_key: 'replace-with-a-different-admin-key'
  web_origins: 'https://192.168.1.1:8443'
}
```

静态服务器的页面证书与 dae CA 都须被浏览器信任。两者同站但不同源，因此仍需精确 `web_origins` 与 credentialed CORS；Cookie 的 `SameSite=Strict` 不允许任意跨站部署。不同 LAN IP、HTTP 页面到 HTTPS API 均不能当作等价的同站登录部署。直连保留真实入口身份；设备自助仍要求 LAN/MAC 证据。

### 同源 HTTPS 反向代理

将默认构建（不设置 `DAE_API_URL`）部署到 `https://dae-ui.example.com`，页面通过同源 `/api/` 访问 nginx。浏览器信任 nginx 页面证书，nginx 通过可信渠道取得 daemon 的公开 CA 并验证上游；绝不复制 CA 私钥或在代理中注入长期 API key。dae 配置例如：

```text
api {
  listen: '192.168.1.1:9080'
  admin_key: 'replace-with-a-private-admin-key'
  web_origins: 'https://dae-ui.example.com'
}
```

最小 nginx `server` 配置（替换证书、静态目录和实际 API IP）：

```nginx
server {
    listen 443 ssl;
    server_name dae-ui.example.com;
    ssl_certificate /etc/nginx/dae-ui/fullchain.pem;
    ssl_certificate_key /etc/nginx/dae-ui/key.pem;
    root /srv/dae-web;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }
    location /api/ {
        proxy_pass https://192.168.1.1:9080;
        proxy_ssl_trusted_certificate /etc/nginx/dae-ca.pem;
        proxy_ssl_verify on;
        proxy_ssl_name 192.168.1.1;
        proxy_set_header Host 192.168.1.1:9080;
        proxy_set_header Origin $http_origin;
        proxy_set_header X-Dae-Proxy 1;
    }
}
```

不改写 API 路径，不改写或移除 Cookie 属性、Origin 或 Fetch Metadata，`X-Dae-Proxy` 必须无条件覆盖客户端同名头。上游 Host 必须匹配 dae 实际 IP:port；保留的页面 Origin 因此仍须加入 `web_origins`。两段均使用 TLS，不能换成 HTTP 或 Unix 上游，也不能关闭上游证书校验。

反代请求只获得 key/Cookie 授予的权限，不借用代理机器的 LAN/MAC 身份。允许管理、显式 MAC 操作与 CA 下载；匿名 LAN、自身设备及浏览器 CA/MITM 验证均不可用，页面显示 unavailable 而不是声称代理握手证明客户端信任。`X-Dae-Proxy`、`Forwarded`、`X-Forwarded-*`、`X-Real-IP` 的存在（包括空值）仅会减权，不能授予身份；未标记代理无法仅从普通 TCP 连接可靠识别，正确覆盖标记是部署契约。Cookie 不按端口隔离，建议专用管理主机名，不与不受信任的 HTTPS 服务共享主机。

`make` 和 `make test` 会通过 `make web-assets` 构建前端，并以产物替换 `internal/webui/assets/`，随后编译 Go。构建产物由 Git 忽略，只编辑 `web/src/`。直接执行 `go build` 或 `internal/webui`、`cmd` 的测试时，除了守护进程原有的构建前置步骤，还需先运行 `make web-assets`。仅构建或测试独立客户端时无需此步骤。

`dae plugins status`、`dae plugins <类型> status` 与独立客户端共用 API 连接配置和状态展示。可用 `--api`、`--timeout`、`DAE_API_ENDPOINT` 与 `DAE_API_KEY` 选择连接，`--instance` 按实例过滤。独立客户端提供 `plugins status` 和 `plugins surge status`，不加载运行时插件；前者可查看任意插件报告。`status` 和 `status --recent` 展示本体状态；脚本运行时和进程池统计通过 `plugins surge status` 或 `plugins status --verbose` 查看。报告命令的 `--json` 输出包含进程级 `buffer_memory` 和筛选后 `plugins` 实例数组的对象，`status --json` 输出完整 daemon 快照。

`dae plugins surge list` 按有效执行域平铺 cron/generic：每个定义有本机行，隔离脚本另有设备行；文本明确显示 local/device MAC/unknown，不凭空 MAC 猜本机。计数和名称消歧按实例/模块/名称，不按行数。`dae plugins surge run demo.tool --instance surge --module tools` 恒在本机执行，不自动选择唯一设备；开启隔离时可加 `--mac 02:00:00:00:00:50` 选择当前 MITM 启用设备。关闭隔离却指定 MAC 返回 400 并要求省略；设备发现不可用返回 503，禁用设备或同执行域任务忙碌返回 409。受理快照 `status.scope` 标识有效域，仅 device 有 `status.mac`。本机无需 LAN 发现、MITM 或 CA，status/list 只读快照不做发现 I/O。通知按实例、scope、MAC、模块、脚本及类型分组，默认每组 3 条；终端文本转义，JSON 保留原值。详细隔离配置、共享风险与执行语义见 [Surge 配置](surge-module.md#手动触发)。

两个命令入口均支持设备存储迁移：

```sh
dae plugins surge store migrate 02:00:00:00:00:11 02:00:00:00:00:22 --instance surge
dae-client plugins surge store migrate 02:00:00:00:00:11 02:00:00:00:00:22 --instance surge --json
```

位置参数依次为旧 MAC、新 MAC。省略 `--instance` 时，scoped status 中恰好一个 Surge 实例才自动选择；零个或多个均在变更前报错。不按模块/任务猜实例，也不查询设备资格。命令校验并规范化两个不同的非零单播六字节 MAC，只发一次变更请求。`--json` 输出 `instance`、`from_mac`、`to_mac`、`keys_moved`，文本会转义终端控制字符。daemon 移动整个设备分区，不按脚本筛选，目标分区即使为空也拒绝覆盖或合并。

先停用旧 MAC 的流量及后台资格，停止其他进程对同一存储的脚本写入，核对新 MAC 和目标无数据，再执行迁移。设备授权须单独调整；两个设备均不要求在线或启用 MITM。本机数据、通知、计数及隔离配置不变，内存模式仅移动当前 Runtime 数据，不因此启用持久化或跨重载保留；没有活动存储 Runtime 为 `503`。目标存在或源/目标脚本执行中为 `409`；旧 MAC 后续执行仍可能新建分区。提示已发布但持久性未确认的 `500` 表示迁移已经生效，超时或断线也不证明数据未变，均不得自动重试。详见 [API 存储语义](api.md#api) 及跨进程限制。

所有 TCP API、metrics、pprof 共用 `api.listen` 与鉴权。可选静态页面在剩余路径提供；Unix socket 只提供 API。页面使用构建时固定目标，登录 key 仅从 HTTPS 页面发往 HTTPS API；HTTPS 管理页的 API 请求和 CA 下载携带 HttpOnly Cookie；HTTP 安装页的 API 请求和所有挑战证明请求均省略凭据。

## 代码边界

```text
client/cli、client/status、未来 TUI
                  │
                  ▼
             api/client ─── HTTP / Unix socket ─── internal/apiserver
                  │                                    │
                  └────────── api 数据契约 ◄────────────┘

web/src ─── 直接 HTTP(S) API ─── internal/apiserver

web 构建产物 ─── internal/webui（嵌入与托管）─── cmd（挂载到 api.listen）
```

- `api`：公开数据契约、已验证入口身份、业务错误及网络数组顺序，只依赖 Go 标准库；不包含运行时聚合或展示逻辑。
- `api/client`：可并发复用的 Go 客户端，封装传输、鉴权、JSON 和错误，不导入 `control`、`common`、`config` 或 `component`。
- `client/status`：本体状态快照和通用插件摘要的展示实现，不访问运行时；终端输出可写入任意 `io.Writer`。
- `client/cli`：两种程序与插件共用的连接参数、实例筛选和命令注册接口；`cmd/dae-client` 是独立入口。
- `plugins/surge/api`、`plugins/surge/client`：插件自己的报告类型、Schema、解析和展示；独立客户端入口显式注册其轻量命令包，不导入脚本运行时。
- `web`：前端源码、浏览器请求层与独立构建入口，不读取父目录中的代码或文件。
- `internal/webui`：只嵌入和托管前端构建产物；`internal/daemon` 负责将静态资源与 API 挂载到现有端口，`control` 不导入 Web 或终端展示代码。
- `internal/daemon`：按已接受配置组装 API handler、鉴权、证书与监控依赖，协调发布和重载。
- `internal/apiserver`：TCP/Unix 监听、HTTP 路由、鉴权、请求校验与重载等待；使用公开契约，通过存储接口访问运行时。
- `control`：读取运行状态、校验 LAN 身份、应用设置并持久化；Unix 与 TCP 使用同一套 API handler。重载先等待旧 handler 的请求结束，再释放旧控制平面。

运行时与客户端直接使用 `api` 类型。`internal/apiserver` 统一管理服务端协议与传输，不导入控制面、客户端或前端。`handler.go` 为每条路由声明访问策略，`access.go` 统一执行 Unix、LAN、设备及密钥/会话门禁，`auth.go` 校验 Bearer 凭据，`session.go` 处理原始 key 登录、Cookie 清除及带绝对到期时间的签名会话；`request.go`、`device.go` 与 `selectors.go` 校验和处理请求，`server.go` 与 `unix.go` 管理监听器生命周期；控制面实现 `state.go` 中的存储接口，通过 `api` 共享入口身份和业务错误，不导入 `internal/apiserver`；HTTP 状态映射由服务端负责。展示所需的汇总、排序、交互状态、键位与刷新策略属于客户端。只有新增的运行时数据或操作才需要扩展守护进程 API。

前端与 dae 的边界是公开构建产物和 HTTP API 契约。`web/` 在同一仓库内保留独立构建，嵌入、静态托管与端口分发由 Go 宿主负责。API 契约、客户端和前端类型在同一个变更中更新并验证。

`make client-test` 在关闭 CGO 的环境运行客户端测试，检查 OpenAPI 是否与契约一致，并检查传递依赖，阻止客户端引入守护进程实现。CI 在安装 clang 和构建 eBPF 之前执行此目标。

## API 参考

规则解释、设备成员管理与影响预览见 [规则解释与设备管理](explain.md)。这些命令同样通过独立 API 客户端提供。

完整字段与操作定义见 [OpenAPI 3.1 文档](../../api/openapi.json)，可导入支持 OpenAPI 的工具。直接编辑 OpenAPI 文档；`make client-test` 检查其字段、必填项、类型和数组长度与 Go 契约是否一致。配置与持久化语义见 [页面与运行时 API](api.md)。

| 方法与路径 | 响应 | 权限与请求 |
| --- | --- | --- |
| `GET /api/status` | `StatusSnapshot` | TCP 使用普通或管理员 key/会话，或显式开启的 LAN 免 key 权限；Unix 使用 socket 权限 |
| `GET /api/selectors` | `SelectorsResponse` | 普通权限；`admin_enabled` 标记管理员操作，`auth_mode` 为 `user_key`、`admin_key`、`lan` 或 `unix` |
| `PUT` / `DELETE /api/session` | 登录：`200` JSON `{role, expires_at}` 和 `__Host-dae-session` Cookie；退出：`204` 清 Cookie，不吊销复制件 | 登录仅接受 HTTPS 原始 key；写请求要求 `X-Dae-API: 1` |
| `PUT /api/selectors/{group}` | `SelectorState` | 管理权限；`{"node_id":"..."}` |
| `DELETE /api/selectors/{group}` | `SelectorState` | 管理权限；空正文，恢复显式 `selector(n)`；没有默认时 `409` |
| `POST /api/probes` | `202` + `ProbeResponse` | 管理权限；`{"outbound":"group","node_id":"..."}` 探测单路径；省略或留空 `node_id` 探测整个出站 |
| `POST /api/resources/refresh` | `202` + `Operation` | 管理权限；空正文，刷新当前配置的资源，等待/运行中返回 `409` |
| `GET /api/resources` | `ResourceRefreshStatus` | 管理权限；查询最近一次 API/自动刷新结果和下次检查时间 |
| `POST /api/operations` | `202` + `Operation` | 管理权限；提交 reload、suspend 或 refresh，立即返回唯一 ID |
| `GET /api/operations/{id}` | `Operation` | 管理权限；按 ID 查询，未知或过期 ID 返回 `404` |
| `POST /api/plugins/{instance}/store/migrate` | `200` + `ScriptStoreMigrateResponse` | 管理权限；`ScriptStoreMigrateRequest` 含 `from_mac`、`to_mac`；同步移动，不返回存储值 |
| `GET /api/device` | `DeviceState` | 仅 TCP，需识别直连 LAN 设备 |
| `GET /api/device/status` | `DeviceStatus` | 当前设备设置、用户态上游流量与连接、按网络/出站汇总；仅直连 LAN |
| `POST /api/device/mitm-tests` | `201` + `MITMTest` | 空正文；创建当前浏览器的短期透明 MITM 挑战 |
| `GET /api/device/mitm-tests/{id}` | `MITMTest` | 查询本设备的测试观测；过期或配置更新后 `404` |
| `PUT` / `DELETE /api/device/sets/{name}` | `DeviceState` | 加入 / 退出集合，空正文 |
| `PUT /api/device/mitm` | `DeviceState` | `{"enabled":true}` 或 `{"enabled":false}` |
| `DELETE /api/device/mitm` | `DeviceState` | 空正文，恢复配置 |
| `POST /api/certificate/tests` | `CertificateTest` | 创建 CA 信任挑战，签发内存临时证书；不修改管理证书，只支持 TCP API |
| `GET /api/certificate/tests/{id}` | `CertificateTest` | 临时证书的 HTTPS 握手证明，成功后消费挑战；管理证书或旧挑战连接 `409` 后关闭并重试 |
| `GET /api/certificate` | `Certificate` | 公开 CA 名称、指纹、可选 `mitm_test_generation` 和 `mitm_test_origins`；未启用时 `404` |
| `GET /api/certificate/ca.pem`、`/api/certificate/ca.cer`、`/api/certificate/ca.mobileconfig` | 证书文件 | 普通权限；不可用时 `404` |

资源刷新 SDK 为 `RefreshResources(ctx)`，返回 `Operation`，通过 `Operation(ctx, id)` 查询该次请求的完成情况。`ResourceRefreshStatus(ctx)` 返回最近一次刷新的 `operation` 和 `next_check`。通用提交方法为 `SubmitOperation(ctx, api.OperationRequest{Kind: "reload"})`；`Abort` 仅用于 reload/suspend。刷新只使用已接受配置中的资源，配置文件修改使用 `dae reload`；详见[资源刷新](api.md#资源刷新)。

设备运行状态 SDK 为 `DeviceStatus(ctx)`，统计按 MAC 归属，`scope` 为 `userspace_upstream`。设备空闲且最近一分钟历史过期后回收；再次出现时累计值重新开始，`started_at` 表示本次观察周期起点，无观察记录时为零时间。MITM 测试 SDK 为 `StartMITMTest(ctx)` 和 `MITMTest(ctx, id)`；这两个方法创建/查询挑战；`VerifyMITM(ctx)` 在当前客户端执行完整验证，浏览器验证则由对应浏览器发起 HTTPS 请求。挑战响应为 `MITMTestProof`，校验 `id`、`ca_fingerprint`，同时确认经授权的 API 查询返回的服务端观测。`mitm_test_generation` 变化时只清除 MITM 结果。

CA 信任独立通过已授权的 `POST /api/certificate/tests` 创建挑战，再以同一 API 端口的 HTTPS GET `/api/certificate/tests/{id}` 校验 ID 和 CA 指纹。POST 签发仅存内存的临时证书和新密钥，不修改持久化管理证书。GET 要求该源 IP 与路由器 IP 使用本次或更新挑战证书的握手，管理证书或更早挑战的连接返回 `409` 后关闭；重试仍须由被测浏览器执行。证明成功后消费挑战，已消费或过期的 ID 返回 `404`。挑战一分钟过期；该地址对没有剩余挑战后，新连接恢复管理证书。共享源 IP 的连接会临时使用同一组挑战证书。不要求设备身份，仅 CA 指纹变化时清除结果。浏览器成功和服务端观测都不能证明整个设备信任 CA。

迁移 SDK 为 `MigrateScriptStore(ctx, "surge", api.ScriptStoreMigrateRequest{FromMAC: "02:00:00:00:00:11", ToMAC: "02:00:00:00:00:22"})`，同步返回 `*api.ScriptStoreMigrateResponse`，含规范化 MAC 和 `KeysMoved`，不返回存储值。非法/相同 MAC 为 `400`，实例/源不存在为 `404`，目标存在或源/目标执行中为 `409`，存储不可用或锁等待取消/超时为 `503`。服务端使用固定五秒可取消锁等待预算；文件 I/O 不保证被硬中断。已发布但持久性未确认返回 `500`，不能自动重试；超时或连接中断亦不能作为未发生变更的证明。

统一探测接口使用 `ProbeRequest`，SDK 为 `Probe(ctx, api.ProbeRequest{Outbound: "group", NodeID: "..."})`。响应 `ProbeResponse` 包含 `outbound`、`node_ids`，`202` 表示已受理；排队或进行中的重复请求会合并。使用出站配置的 DNS 探测、超时和并发限制，支持所有已实例化的受检测出站，不接受任意 URL 或请求级配置覆盖。selector 的结果继续从 `/api/selectors` 获取，其他出站从 `/api/status` 查看健康与延迟。

`SelectorState.track_all` 是 group 配置的只读值，开启时前端用持续检测状态替代 Test 按钮；没有对应的修改 API。`default_node_id` 仅在显式 `selector(n)` 时存在，省略时隐藏所有默认标记和重置操作。候选的 `tested` 区分未测试与失败，`checking` 表示排队/检测中，`tracking` 表示持续监测，`checked_at` 是最近完成测试时间（RFC 3339，首次完成前省略）。未追踪节点的结果是历史结果，不代表持续健康保证。

JSON 修改请求要求 `X-Dae-API: 1`，SDK 自动携带；MITM 修改还要求当前 CA 的 `X-Dae-MITM` 指纹。Go SDK 的 `client.Options.APIKey` 接受普通或管理员 key，`RootCAs` 指定信任根。TCP key 必须使用 HTTPS；Unix 免 key；开启的 LAN 免 key 仅授予普通权限。具体角色见 [API 访问模型](api.md#权限与连接)。

门禁在读取请求正文、检查功能状态及查询资源之前执行，并将本次请求验证出的身份传给处理函数。管理员凭据不替代设备身份；当前设备上下文和当前设备规则解释要求已验证 LAN 入口，成员管理、MITM 和 MITM 测试还要求非零单播以太网 MAC。缺失或错误的密钥/会话返回 `401` 并携带 `WWW-Authenticate: Bearer realm="dae"`；LAN 或设备身份不满足要求返回 `403`。已通过门禁的请求才会得到资源不存在的 `404`；其他设备的 MITM 测试也返回 `404`，避免透露其存在。未知路由仍为 `404`，CA 下载及元数据要求普通权限，无需设备 MAC。

名称按 URL 路径段编码；正文默认限制为 1 KiB，规则解释和成员影响预览为 64 KiB。有 JSON 时需 `Content-Type: application/json`，其余请求正文必须为空。`/api/*` 不接受查询参数，浏览器来源遵循普通／管理员权限模型，TCP 的 Host 必须是实际连接到的路由器 IP 和端口。GET 路由也支持 HEAD。

状态操作成功返回 `200`；探测受理返回 `202`；原始 key 登录返回 `200`、`{role, expires_at}` 与 HttpOnly 会话 Cookie，退出清 Cookie 并返回 `204`。POST 同样需要 `X-Dae-API: 1`，SDK 自动携带。业务错误为 `{"error":"说明"}`；未知路由、错误方法和部分证书下载错误可能为纯文本。客户端应按 HTTP 状态码处理，不能依赖英文错误文案：

| 状态码 | 含义 |
| --- | --- |
| `400` | 正文、字段、节点 ID 或连接地址等不合法 |
| `401` | 密钥/会话缺失或无效，携带 Bearer 认证挑战 |
| `403` | LAN/设备身份无法确认、自助接口非直连、浏览器来源/Fetch Metadata 不获许可、HTTP 凭据或缺少变更标记 |
| `404` / `405` | 资源不存在 / 方法不支持 |
| `409` | CA 已变化、selector 没有可重置的默认节点，或目标出站不支持探测 |
| `413` / `415` | 正文过大 / Content-Type 不正确 |
| `500` | 应用或持久化失败，检查守护进程日志 |
| `503` | 正在启动或重载，稍后重试 |

写入成功直接返回更新后的状态。写入超时并不证明操作未执行，应重新查询当前状态；客户端库不会自动重试写请求。

## 状态字段

当前 `StatusSnapshot.schema` 为 `15`。顶层 `direct_fallback_connections` 是单一的 direct fallback 计数；`PathStats` 只包含活动/累计连接、流量总量及历史，不包含 fallback 字段。Prometheus 的 `dae_fallback_connections_total` 是一条无标签的进程级计数。`tables` 覆盖内核表和用户态资源池，提供 `scope`、`on_full` 和可选 `error`；`limit: 0` 表示无容量上限，非空 `error` 表示 `used` 不可用。域名表 `breakdown.gc` 是按时间回收的 pair 数量；内核 `candidates` 表示容量选择前的候选 IP 数量。顶层 `buffer_memory` 提供进程级 body buffer 内存预算，没有活动插件时仍提供。插件报告位于 `plugins[].details`；Surge 报告提供 `enabled` 与 `modules`，独立 Surge 命令按实例汇总这些报告。客户端忽略新增响应字段，拒绝不支持的 schema、null 响应、重复 JSON 键与类型错误；请求中的未知字段仍被拒绝。不兼容的状态结构调整必须增加 schema。状态端点为 `/api/status`。

节点延迟统计只包含成功探测。自动组的 `selection` 提供本组角色（选中、监测、备用）、有效优先级、有符号评分、已验证的恢复时长和测量时间。CLI 在故障期间显示 `[degraded]`，首次恢复成功后显示 `[recover 5s/30s verified]`，进度仅在成功探测后推进。状态列同时显示正在验证、排队或恢复观察期间下次 recheck 的实际倒计时。节点 `dormant` 为真才表示物理休眠，最近一次观测未失败时在状态列显示一次，历史延迟附带样本年龄；故障节点改为显示 `unavailable` 和重试时间；备用路径仍可共享其他组的监测，`recovery` 报告实际检查与重试。详见[自动节点选择](outbound-selection.md)。

Registry 的 `used` 是域名–IP 配对数，`breakdown.domains`、`ips`、`ipv4`、`ipv6` 分别表示保留的域名数、去重 IP 数及地址类型分布。同一 IP 被多个域名引用仍只计一次，`ips = ipv4 + ipv6`。CLI 明确区分这些数量与内核驻留、容量遗漏数量。

`groups[].nodes[].revision` 标识节点状态版本，`observed_session_seq` 与可选的 `session_detail` 描述已观察到的会话及其资源身份。`recovery` 提供恢复执行方、阶段、验证结果和尝试次数；`retry_at` 仅在确有退避定时器时出现，客户端不能为库自行管理的恢复推测倒计时。可选的 `failure` 记录故障来源及对应资源，便于 TUI 区分当前恢复状态和最近故障。

状态是观察快照，不是所有子系统在同一时刻的事务快照。连通性探测与节点选择可先后更新，客户端不因短暂的健康状态差异拒绝整个响应；字段约束由服务端测试检查。

| 字段 | 语义 |
| --- | --- |
| `version`、`started_at`、`last_reload_at` | 守护进程版本、启动时间、上次完成重载时间 |
| `uptime` | 服务端从与 `started_at` 同源的进程统计起点计算的运行时长，整数纳秒，重载不清零；展示时直接使用，不与客户端时钟相减 |
| `stats` | 进程生命周期内连接数、流量总计，以及近期吞吐历史 |
| `networks` | 各网络的统计，顺序固定为 `tcp4`、`tcp6`、`udp4`、`udp6` |
| `tables` | DNS / 域名表占用；`breakdown` 区分 live、retained 和容量回收数量 |
| `groups` | 可见目标的策略、关键性、连通状态、统计、节点与当前选择 |
| `groups[].selected_node_ids` | 同样的四项网络顺序；空字符串表示该网络当前没有已选择的节点 |
| `groups[].nodes[].support` | 四项网络能力：`unknown`、`confirmed`、`unsupported`；能力与当前健康不同 |
| `plugins` | 插件实例状态、数量与可选的 `details` 报告，不包含插件配置对象 |

时间戳采用 RFC 3339；Go 零时间 `0001-01-01T00:00:00Z` 表示尚未发生。状态内所有 duration 为整数纳秒；selector 的 `latency_ms` 单独采用毫秒。`up_ratio` 范围为 `0..1`，依据可观测时间加权；`seen=false` 表示尚无有效观察。

流量总计为字节，`history.upload_bytes_per_second` / `download_bytes_per_second` 是每 5 秒完成一次的平均字节速率，按从旧到新排列，最多 12 项。启动不足一分钟时长度较短；两方向长度相同。计数器在守护进程重启后重置，重载保留。64 位计数在 JavaScript 中超过 `2^53-1` 时可能丢失精度；需要精确总量的客户端应使用支持大整数的 JSON 解析器。

启用连通检查的组，其 `availability.recent.states` 为过去一小时的 10 个桶，每桶 6 分钟，旧到新；桶内出现不可用则记为 `unavailable`，否则有可用观察为 `available`，没有观察为 `unknown`。未检查的组不展示这段历史。节点 ID 是 API 的不透明标识，不能用名称、数组索引或客户端自行计算的哈希代替。

## TUI / Go 客户端示例

```go
package main

import (
    "context"
    "fmt"
    "os"
    "time"

    "github.com/daeuniverse/dae/api/client"
)

func main() {
    c, err := client.New(client.Options{
        Endpoint: os.Getenv("DAE_API_ENDPOINT"),
        APIKey:   os.Getenv("DAE_API_KEY"),
        Timeout:  5 * time.Second,
    })
    if err != nil {
        panic(err)
    }
    defer c.Close()

    snapshot, err := c.Status(context.Background())
    if err != nil {
        panic(err)
    }
    fmt.Println(snapshot.Version, snapshot.Stats.ActiveConnections)
}
```

TUI 可长期复用 `Client`，用带取消的 context 控制刷新，并用 `var apiErr *client.Error` 和 `errors.As(err, &apiErr)` 取得 `StatusCode`。根据展示需要轮询，例如 2 秒一次；收到 `503` 时保留最后快照并退避，恢复后刷新。当前 API 不提供推送流或跨请求事务，多次查询不是同一原子快照。

修改 selector 使用 `Selectors`、`SelectNode`、`ResetSelector`；设备自助使用 `Device`、`SetMembership`、`SetMITM`、`ResetMITM`。`SetMITM(ctx, false, fingerprint)` 显式关闭，`ResetMITM(ctx, fingerprint)` 恢复配置。客户端只维护交互状态，运行时设置的应用与持久化由守护进程负责。

## 证书、远程操作与性能采集

```sh
# Export via the local socket, then transfer through a trusted channel.
sudo dae-client certificate download --format pem -o dae-ca.pem
# On the remote client:
export DAE_API_ENDPOINT=https://192.168.1.1:9080
export DAE_API_CA=/etc/dae/dae-ca.pem
export DAE_API_KEY_FILE=/etc/dae/user.key
dae-client status --recent
dae-client certificate info
dae-client certificate verify
dae-client certificate verify-mitm
# Administrator key required for these remote calls:
export DAE_API_KEY_FILE=/etc/dae/admin.key
dae-client operation reload
dae-client operation get OPERATION_ID
dae-client operation resources
dae-client pprof profile --seconds 30 --output cpu.pprof
go tool pprof cpu.pprof
```

证书验证需要 TCP 直连，并证明当前 CLI 配置的信任库；不会替另一个浏览器完成信任验证。MITM 验证还要求当前连接有可验证的设备 MAC 和已启用的 MITM。`operation` 返回异步任务，可用 `get ID` 查询；刷新使用 `operation refresh`。pprof 需 `api.pprof: true`，默认请求超时为一分钟，可用 `--timeout` 延长。Unix 上仍无需 key。

pprof 也接受 HTTPS Basic Auth，用户名 `dae`、密码为 `admin_key`，供外部工具使用。`go tool pprof` 可读取 Basic URL，但 URL 中的密钥可能出现在历史、进程参数和工具输出中；优先使用上述 key 文件下载方式。不要把 key 放在 query 参数中。Prometheus 配置见 [metrics](metrics.md)。

`make WEBUI=n` 构建不包含 Web 的 daemon，并跳过前端构建；`api { web: false }` 可运行时关闭页面。所有证书和管理能力仍由 API/CLI 提供。开发时 `pnpm --dir web dev` 只提供静态页面，使用与生产构建相同的固定 `DAE_API_URL`。登录开发环境同样需要 HTTPS 页面、同站直连或同源 HTTPS 反代及精确 `web_origins`；普通 HTTP localhost 开发页不是远程 key 登录入口，不能以扩大白名单绕过跨站限制。
