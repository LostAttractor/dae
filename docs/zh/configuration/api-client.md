# API 与独立客户端开发

`dae status`、`dae status --verbose`、`dae status --recent` 和 `dae plugins surge status` 通过 HTTP API 读取运行状态，Web 通过 API 获取状态和修改设置。独立客户端无需加载配置、读取运行时状态文件、链接 QuickJS 或生成 eBPF。

## 构建与使用

需要 Go 1.27+；可在 `nix-shell` 中运行：

```sh
make client
sudo ./dae-client status
./dae-client status --api http://192.168.1.1:9080 --recent
./dae-client plugins status --api http://192.168.1.1:9080 --json
./dae-client plugins status --api http://192.168.1.1:9080 --verbose
./dae-client plugins surge status --api http://192.168.1.1:9080 --instance personal
./dae-client status --api unix:///var/run/dae.sock --json
```

`make client` 等价于 `CGO_ENABLED=0 go build -trimpath -o dae-client ./cmd/dae-client`，不执行 `make ebpf`，不需要 clang、内核头文件或初始化守护进程所用的 submodule。Go 模块下载仍需要网络或已有缓存。独立客户端也可交叉编译，例如 `GOOS=darwin GOARCH=arm64 make client`。

连接参数对两种命令入口相同：

| 参数 | 默认值与含义 |
| --- | --- |
| `--api` | `DAE_API_ENDPOINT`，未设置时为 `unix:///var/run/dae.sock` |
| `--timeout` | `10s`，单次请求超时；取消命令上下文也会取消请求 |
| `DAE_API_KEY` | TCP 管理接口配置的 API key，以 Bearer 凭据发送；daemon 未配置密钥时，已验证的直连 LAN 客户端无需设置 |
| `--json` | `status` 输出完整 API 快照，与 `--verbose`、`--recent` 互斥；MITM 报告命令输出筛选后的实例数组 |
| `--color` | `status` 文本输出的颜色模式：`auto`（默认）、`always` 或 `never` |

`status --color always`（也可写成 `--color=always`）在管道或重定向输出中仍保留 ANSI 颜色，`--color never` 强制禁用颜色；两者均覆盖环境变量。默认的 `auto` 沿用终端检测及 `FORCE_COLOR`、`NO_COLOR`、`TERM` 设置。该选项适用于普通、`--verbose` 和 `--recent` 文本视图，`--json` 始终输出无颜色的 JSON。使用 `watch` 时还需加上它的 `--color`（`-c`）选项来显示颜色：

```sh
watch --color -n 2 'dae status --recent --color always'
```

独立客户端同样支持，例如 `watch --color -n 2 'dae-client status --recent --color always'`。

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

本地 socket 权限仍为 `0600`，不依赖 `global.api_port`。两种命令入口均不自动提权；访问默认 socket 时使用 `sudo` 或已有的文件系统权限。

TCP 需要启用 [API 配置](api.md)。daemon 配置密钥时需设置 `DAE_API_KEY`；未配置时，已验证的直连 LAN 客户端可以无凭据查询状态，WAN 或无法识别的客户端会被拒绝。客户端忽略环境中的 HTTP 代理，不跟随重定向，避免改变设备身份或把密钥发往其他地址。守护进程直接提供 HTTP；客户端支持 HTTPS 传输，但这不会给守护进程增加 TLS 或反向代理支持。

Go SDK 自建 transport，不依赖应用对 `http.DefaultTransport` 的修改。成功响应上限为 32 MiB，错误正文上限为 8 KiB；错误正文过长时仍可通过 `client.Error.StatusCode` 判断 HTTP 状态。

状态表中的 `UP/24H` 和流量的 `AVG/MAX` 使用复合表头，与数据共用各子字段的宽度：标题与数值都从各自字段左侧开始，`/` 在各行中的位置固定。显示宽度计算支持中文和 ANSI 颜色。

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
proxy_hk  UP     100.00%  [......++++]  香港标准 IEPL 专线 2  0
proxy_jp  UP     100.00%  [......++++]  lightsail             108
proxy_tw  UP     100.00%  [......++++]  台湾标准 IEPL 专线 3  0
proxy_us  UP     100.00%  [......++++]  美国高级 IEPL 专线 1  0
tor       UP     100.00%  [......++++]  tor                   0
```

- `ACTIVE` 显示组的活动连接数。fallback 是进程级的单一 direct 计数，不按节点、组或网络分别维护。它累计因无可用节点而回退到 direct 且成功建立的连接，跨 reload 保留，重启清零，不表示当前正在 fallback 的连接数。
- `SELECTED` 按 `selected_node_ids` 显示当前选中的节点。紧凑视图只列出已确认支持或已经有选择的网络；没有当前选择的 `unknown` 和 `unsupported` IP 家族、协议均省略。所有显示的网络选中同一节点时只写节点名。只有选择不同才用 `ipv4:`、`ipv6:`、`tcp:`、`udp:` 或具体网络名区分，并用分号连接。已确认支持但没有当前选择时显示 `-`；所有网络都没有选择时也显示 `-`。`random` 表示逐连接随机选择，没有稳定的组级节点。已有连接可能仍使用先前选择的节点。
- `STATE`、`24H`、`1H` 分列显示当前状态、时间加权可用率和十个六分钟连通性桶。表头和数据统一左对齐，百分比与历史图也保持各自固定的左侧起点。无颜色时 `+` / `x` / `.` 分别表示可用、不可用、未观察；彩色终端使用绿点、红点和灰色空心点。无连通性检查的组显示 `N/A`，可用率和历史显示 `-`。
- 组名最多占 18 个显示列，每个节点选择最多占 32 个显示列，超长部分以 `…` 省略，支持中文和 ANSI 颜色。表头、组行和全局摘要超过终端宽度时直接截断右侧，不生成续行，右侧的部分节点或计数可能因此不可见。无法获取终端宽度时不做整行截断。

## Web 独立更新

```sh
make web
# 或直接在前端目录构建
make -C web
```

`web/` 包含前端源码与自己的构建入口。`make web` 输出到 `build/web/`（可通过 `WEB_OUTPUT` 修改）；`make -C web` 输出到 `web/dist/`。两者只需要 Make 和常规文件工具，不需要 Go 或 Node.js。`dae-client` 只包含终端命令，不再携带 Web 资源。

产物包含 `index.html`、`style.css`、`app.js`、`api.js`。内嵌页面使用原生表单，提供设备集合、节点选择、HTTPS 开关和证书下载；复杂展示和交互可通过外部前端扩展。要独立更新页面，将产物部署到目录，并给 dae 进程设置环境变量：

```sh
DAE_WEB_ROOT=/opt/dae-web dae run -c /etc/dae/config.dae
```

也可在服务管理器中设置 `DAE_WEB_ROOT`。该目录替代内嵌静态资源；资源按请求读取，替换完整目录即可更新前端，无需重新编译 dae。目录中的文件及子目录均为公开静态资源，只应存放前端产物；缺失资源返回 `404`。新增 JS、CSS 或嵌套资源无需修改 dae 路由。`/api/` 与证书下载路径由 API handler 优先处理。

页面仍通过 `http://路由器IP:<api_port>/` 访问，由 dae 的 API 端口提供，浏览器直接连接路由器，因此现有的同源校验与设备 MAC 识别继续有效。独立构建不意味着可通过 `file://`、任意跨源静态站点或普通反向代理访问设备接口。`X-Forwarded-For` 等头不会改变设备身份。

`make` 和 `make test` 会通过 `make web-assets` 构建前端，并以产物替换 `internal/webui/assets/`，随后编译 Go。构建产物由 Git 忽略，只编辑 `web/src/`。直接执行 `go build` 或 `internal/webui`、`cmd` 的测试时，除了守护进程原有的构建前置步骤，还需先运行 `make web-assets`。仅构建或测试独立客户端时无需此步骤。

`dae plugins status`、`dae plugins <类型> status` 与独立客户端共用 API 连接配置和状态展示。可用 `--api`、`--timeout`、`DAE_API_ENDPOINT` 与 `DAE_API_KEY` 选择连接，`--instance` 按实例过滤。独立客户端提供 `plugins status` 和 `plugins surge status`，不加载运行时插件；前者可查看任意插件报告。报告命令的 `--json` 输出筛选后的完整实例数组，`status --json` 输出完整 daemon 快照。

端口只监听一次：`internal/apiserver` 创建一个 TCP listener 和 `http.Server`，`cmd/api_server.go` 用 `http.ServeMux` 按路径分发请求。`/api/` 进入 internal/apiserver 的 handler，三个证书下载路径也由 API 处理，其余路径进入静态文件 handler。浏览器的 `fetch("/api/...")` 自动沿用页面的协议、地址和端口，无需另起 Web 服务。Unix socket 只挂载 API handler，不提供页面。

## 代码边界

```text
client/cli、client/status、未来 TUI
                  │
                  ▼
             api/client ─── HTTP / Unix socket ─── internal/apiserver
                  │                                    │
                  └────────── api 数据契约 ◄────────────┘

web/src ─── 同源 HTTP API ─── internal/apiserver

web 构建产物 ─── internal/webui（嵌入与托管）─── cmd（挂载到 api_port）
```

- `api`：普通 Go 数据结构与网络数组顺序，只依赖 Go 标准库；不包含运行时聚合或展示逻辑。
- `api/client`：可并发复用的 Go 客户端，封装传输、鉴权、JSON 和错误，不导入 `control`、`common`、`config` 或 `component`。
- `client/status`：状态快照、MITM 摘要与 Surge 报告的唯一解析/展示实现，不访问运行时；终端输出可写入任意 `io.Writer`。
- `client/cli`：两种程序与插件共用的连接参数、实例筛选和状态命令实现；`cmd/dae-client` 是独立入口。
- `web`：前端源码、浏览器请求层与独立构建入口，不读取父目录中的代码或文件。
- `internal/webui`：只嵌入和托管前端构建产物；`cmd` 负责将静态资源与 API 挂载到现有端口，`control` 不导入 Web 或终端展示代码。
- `internal/apiserver`：TCP/Unix 监听、HTTP 路由、鉴权、请求校验与重载等待；使用公开契约，通过存储接口访问运行时。
- `control`：读取运行状态、校验 LAN 身份、应用设置并持久化；Unix 与 TCP 使用同一套 API handler。重载先等待旧 handler 的请求结束，再释放旧控制平面。

运行时与客户端直接使用 `api` 类型。`internal/apiserver` 统一管理服务端协议与传输，不导入控制面、客户端或前端。`handler.go` 注册路由，`auth.go` 统一处理 Unix、LAN 和密钥/会话授权，`session.go` 处理登录、退出及签名 Cookie；`request.go`、`device.go` 与 `selectors.go` 校验和处理请求，`server.go` 与 `unix.go` 管理监听器生命周期；控制面实现 `state.go` 中的存储接口。展示所需的汇总、排序、交互状态、键位与刷新策略属于客户端。只有新增的运行时数据或操作才需要扩展守护进程 API。

前端与 dae 的边界是公开构建产物和 HTTP API 契约。以后可将整个 `web/` 迁移为独立仓库或 submodule，嵌入、静态托管与端口分发代码继续留在 dae。

`make client-test` 在关闭 CGO 的环境运行客户端测试，检查 OpenAPI 是否与契约一致，并检查传递依赖，阻止客户端引入守护进程实现。CI 在安装 clang 和构建 eBPF 之前执行此目标。

## API 参考

完整字段与操作定义见 [OpenAPI 3.1 文档](../../api/openapi.json)，可导入支持 OpenAPI 的工具。直接编辑 OpenAPI 文档；`make client-test` 检查其字段、必填项、类型和数组长度与 Go 契约是否一致。配置与持久化语义见 [页面与运行时 API](api.md)。

| 方法与路径 | 响应 | 权限与请求 |
| --- | --- | --- |
| `GET /api/status` | `StatusSnapshot` | TCP 配置密钥时需要 API key/会话，未配置时校验直连 LAN 身份；Unix 使用 socket 权限 |
| `GET /api/selectors` | `SelectorsResponse` | 管理权限；授权成功后 `admin_enabled` 为 true，`auth_mode` 为 `api_key`、`lan` 或 `unix` |
| `PUT` / `DELETE /api/session` | `204`，无响应正文 | 浏览器登录 / 清除 Cookie；空请求正文。无密钥时验证 LAN/Unix 权限并清除旧 Cookie，不签发会话 |
| `PUT /api/selectors/{group}` | `SelectorState` | 管理权限；`{"node_id":"..."}` |
| `DELETE /api/selectors/{group}` | `SelectorState` | 管理权限；空正文，恢复显式 `selector(n)`；没有默认时 `409` |
| `POST /api/probes` | `202` + `ProbeResponse` | 管理权限；`{"outbound":"group","node_id":"..."}` 探测单路径；省略或留空 `node_id` 探测整个出站 |
| `POST /api/resources/refresh` | `202` + `ResourceRefreshStatus` | 管理权限；空正文，刷新当前配置的资源，等待/运行中返回 `409` |
| `GET /api/resources` | `ResourceRefreshStatus` | 管理权限；查询最近一次 API/自动刷新结果和下次检查时间 |
| `GET /api/device` | `DeviceState` | 仅 TCP，需识别直连 LAN 设备 |
| `PUT` / `DELETE /api/device/sets/{name}` | `DeviceState` | 加入 / 退出集合，空正文 |
| `PUT /api/device/mitm` | `DeviceState` | `{"enabled":true}` 或 `{"enabled":false}` |
| `DELETE /api/device/mitm` | `DeviceState` | 空正文，恢复配置 |
| `GET /api/certificate` | `Certificate` | 公开 CA 名称与指纹；未启用时 `404` |
| `GET /ca.pem`、`/ca.cer`、`/ca.mobileconfig` | 证书文件 | 公开；未启用时 `404` |

资源刷新 SDK 为 `RefreshResources(ctx)`，通过 `ResourceRefreshStatus(ctx)` 查询完成情况。只刷新已接受配置中的资源，配置文件修改使用 `dae reload`；详见[资源刷新](api.md#资源刷新)。

统一探测接口使用 `ProbeRequest`，SDK 为 `Probe(ctx, api.ProbeRequest{Outbound: "group", NodeID: "..."})`。响应 `ProbeResponse` 包含 `outbound`、`node_ids`，`202` 表示已受理；排队或进行中的重复请求会合并。使用出站配置的 DNS 探测、超时和并发限制，支持所有已实例化的受检测出站，不接受任意 URL 或请求级配置覆盖。selector 的结果继续从 `/api/selectors` 获取，其他出站从 `/api/status` 查看健康与延迟。

`SelectorState.track_all` 是 group 配置的只读值，开启时前端用持续检测状态替代 Test 按钮；没有对应的修改 API。`default_node_id` 仅在显式 `selector(n)` 时存在，省略时隐藏所有默认标记和重置操作。候选的 `tested` 区分未测试与失败，`checking` 表示排队/检测中，`tracking` 表示持续监测，`checked_at` 是最近完成测试时间（RFC 3339，首次完成前省略）。未追踪节点的结果是历史结果，不代表持续健康保证。

所有 PUT 和 DELETE 请求需 `X-Dae-API: 1`，SDK 会自动携带。MITM 修改需 `X-Dae-MITM: <当前 CA SHA-256 指纹>`。配置 `global.api_key` 时，TCP 管理请求（包括 LAN 上的 selector 查询）需 `Authorization: Bearer <api_key>` 或有效会话，缺失/错误凭据返回 `401`。Go SDK 使用 `client.Options.APIKey`。未配置密钥时，每个 TCP 管理请求均须通过直连 LAN 入口和邻居校验，否则返回 `403`；无需提供凭据。密钥模式下浏览器可使用 `PUT /api/session` 签发的七天会话 Cookie，`DELETE /api/session` 清除 Cookie；两个会话接口均使用空正文，成功返回 `204`，无密钥访问不签发会话。Unix 上能连接 socket 的进程拥有本地管理权限，但无法通过 socket 操作“当前 LAN 设备”。

名称按 URL 路径段编码；正文限制为 1 KiB，有 JSON 时需 `Content-Type: application/json`，其余请求正文必须为空。`/api/*` 不接受查询参数，浏览器必须同源，TCP 的 Host 必须是实际连接到的路由器 IP 和端口。GET 路由也支持 HEAD。

状态操作成功返回 `200`；探测受理返回 `202`；会话操作成功返回 `204`，无响应正文。POST 同样需要 `X-Dae-API: 1`，SDK 自动携带。业务错误为 `{"error":"说明"}`；未知路由、错误方法和部分证书下载错误可能为纯文本。客户端应按 HTTP 状态码处理，不能依赖英文错误文案：

| 状态码 | 含义 |
| --- | --- |
| `400` | 正文、字段、节点 ID 等不合法；Unix 无法识别设备地址 |
| `401` / `403` | 密钥/会话鉴权失败、无密钥模式下 LAN 身份校验失败、跨源或设备身份无法确认 |
| `404` / `405` | 资源不存在 / 方法不支持 |
| `409` | CA 已变化、selector 没有可重置的默认节点，或目标出站不支持探测 |
| `413` / `415` | 正文过大 / Content-Type 不正确 |
| `500` | 应用或持久化失败，检查守护进程日志 |
| `503` | 正在启动或重载，稍后重试 |

写入成功直接返回更新后的状态。写入超时并不证明操作未执行，应重新查询当前状态；客户端库不会自动重试写请求。

## 状态字段与版本兼容

当前 `StatusSnapshot.schema` 为 `12`。顶层 `direct_fallback_connections` 是单一的 direct fallback 计数；`PathStats` 只包含活动/累计连接、流量总量及历史，不包含 fallback 字段。Prometheus 的 `dae_fallback_connections_total` 是一条无标签的进程级计数。域名表的 `limit: 0` 表示用户态无容量上限，`breakdown.gc` 是按时间回收的 pair 数量；内核 `candidates` 表示容量选择前的候选 IP 数量。插件报告位于 `plugins[].details`；Surge 报告提供 `enabled` 与 `modules`，独立 Surge 命令按实例汇总这些报告。状态顶层不再包含 `surge` 字段。客户端忽略新增响应字段，拒绝不支持的 schema、null 响应、重复 JSON 键与类型错误；请求中的未知字段仍被拒绝。不兼容的状态结构调整必须增加 schema。状态端点为 `/api/status`。

节点延迟统计只包含成功探测。自动组的 `selection` 提供本组角色（选中、监测、备用）、有效优先级、有符号评分、已验证的恢复时长和测量时间。CLI 在故障期间显示 `[degraded]`，首次恢复成功后显示 `[recover 5s/30s]`。节点 `dormant` 为真才表示物理休眠，在状态列显示一次，历史延迟附带样本年龄；备用路径仍可共享其他组的监测，`recovery` 报告实际检查与重试。详见[自动节点选择](outbound-selection.md)。

Registry 的 `used` 是域名–IP 配对数，`breakdown.domains`、`ips`、`ipv4`、`ipv6` 分别表示保留的域名数、去重 IP 数及地址类型分布。同一 IP 被多个域名引用仍只计一次，`ips = ipv4 + ipv6`。CLI 明确区分这些数量与内核驻留、容量遗漏数量。

Schema 10 将这些 Registry 计数作为必需字段。daemon 与 CLI 需一起升级；缺少计数的 schema 9 响应会被拒绝，避免显示假零值。

`groups[].nodes[].revision` 标识节点状态版本，`observed_session_seq` 与可选的 `session_detail` 描述已观察到的会话及其资源身份。`recovery` 提供恢复执行方、阶段、验证结果和尝试次数；`retry_at` 仅在确有退避定时器时出现，客户端不能为库自行管理的恢复推测倒计时。可选的 `failure` 记录故障来源及对应资源，便于 TUI 区分当前恢复状态和最近故障。

状态是观察快照，不是所有子系统在同一时刻的事务快照。连通性探测与节点选择可先后更新，客户端不因短暂的健康状态差异拒绝整个响应；字段约束由服务端测试检查。

| 字段 | 语义 |
| --- | --- |
| `version`、`started_at`、`last_reload_at` | 守护进程版本、启动时间、上次完成重载时间 |
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
