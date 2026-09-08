# API 与独立客户端开发

`dae status`、`dae status --verbose`、`dae status --recent` 和 `dae mitm surge status` 通过 HTTP API 读取运行状态，Web 通过 API 获取状态和修改设置。独立客户端无需加载配置、读取运行时状态文件、链接 QuickJS 或生成 eBPF。

## 构建与使用

需要 Go 1.27+；可在 `nix-shell` 中运行：

```sh
make client
sudo ./dae-client status
./dae-client status --api http://192.168.1.1:9080 --recent
./dae-client mitm status --api http://192.168.1.1:9080 --json
./dae-client mitm status --api http://192.168.1.1:9080 --verbose
./dae-client mitm surge status --api http://192.168.1.1:9080 --instance personal
./dae-client status --api unix:///var/run/dae.sock --json
```

`make client` 等价于 `CGO_ENABLED=0 go build -trimpath -o dae-client ./cmd/dae-client`，不执行 `make ebpf`，不需要 clang、内核头文件或初始化守护进程所用的 submodule。Go 模块下载仍需要网络或已有缓存。独立客户端也可交叉编译，例如 `GOOS=darwin GOARCH=arm64 make client`。

连接参数对两种命令入口相同：

| 参数 | 默认值与含义 |
| --- | --- |
| `--api` | `DAE_API_ENDPOINT`，未设置时为 `unix:///var/run/dae.sock` |
| `--timeout` | `10s`，单次请求超时；取消命令上下文也会取消请求 |
| `DAE_API_TOKEN` | TCP 管理接口的 Bearer token，不写入 URL 或命令行参数 |
| `--json` | `status` 输出完整 API 快照，与 `--verbose`、`--recent` 互斥；MITM 报告命令输出筛选后的实例数组 |

本地 socket 权限仍为 `0600`，不依赖 `global.api_port`。两种命令入口均不自动提权；访问默认 socket 时使用 `sudo` 或已有的文件系统权限。

TCP 需要启用 [API 配置](api.md)。设置 `DAE_API_TOKEN` 后再执行远程状态命令。客户端忽略环境中的 HTTP 代理，不跟随重定向，避免改变设备身份或把 token 发往其他地址。守护进程直接提供 HTTP；客户端支持 HTTPS 传输，但这不会给守护进程增加 TLS 或反向代理支持。

Go SDK 自建 transport，不依赖应用对 `http.DefaultTransport` 的修改。成功响应上限为 32 MiB，错误正文上限为 8 KiB；错误正文过长时仍可通过 `client.Error.StatusCode` 判断 HTTP 状态。

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

`dae mitm status`、`dae mitm <类型> status` 与独立客户端共用 API 连接配置和状态展示。可用 `--api`、`--timeout`、`DAE_API_ENDPOINT` 与 `DAE_API_TOKEN` 选择连接，`--instance` 按实例过滤。独立客户端提供 `mitm status` 和 `mitm surge status`，不加载运行时插件；前者可查看任意插件报告。报告命令的 `--json` 输出筛选后的完整实例数组，`status --json` 输出完整 daemon 快照。

端口只监听一次：`internal/apiserver` 创建一个 TCP listener 和 `http.Server`，`cmd/api_server.go` 用 `http.ServeMux` 按路径分发请求。`/api/` 进入 component/api 的 handler，三个证书下载路径也由 API 处理，其余路径进入静态文件 handler。浏览器的 `fetch("/api/...")` 自动沿用页面的协议、地址和端口，无需另起 Web 服务。Unix socket 只挂载 API handler，不提供页面。

## 代码边界

```text
client/cli、client/status、未来 TUI
                  │
                  ▼
             api/client ─── HTTP / Unix socket ─── component/api
                  │                                    │
                  └────────── api 数据契约 ◄────────────┘

web/src ─── 同源 HTTP API ─── component/api

web 构建产物 ─── internal/webui（嵌入与托管）─── cmd（挂载到 api_port）
```

- `api`：普通 Go 数据结构与网络数组顺序，只依赖 Go 标准库；不包含运行时聚合或展示逻辑。
- `api/client`：可并发复用的 Go 客户端，封装传输、鉴权、JSON 和错误，不导入 `control`、`common`、`config` 或 `component`。
- `client/status`：状态快照、MITM 摘要与 Surge 报告的唯一解析/展示实现，不访问运行时；终端输出可写入任意 `io.Writer`。
- `client/cli`：两种程序与插件共用的连接参数、实例筛选和状态命令实现；`cmd/dae-client` 是独立入口。
- `web`：前端源码、浏览器请求层与独立构建入口，不读取父目录中的代码或文件。
- `internal/webui`：只嵌入和托管前端构建产物；`cmd` 负责将静态资源与 API 挂载到现有端口，`control` 不导入 Web 或终端展示代码。
- `component/api`：HTTP 路由、鉴权与请求校验，使用公开数据契约。
- `control`：读取运行状态、校验 LAN 身份、应用设置并持久化；Unix 与 TCP 使用同一套 API handler。重载先等待旧 handler 的请求结束，再释放旧控制平面。

运行时与客户端直接使用 `api` 类型。`internal/apiserver` 统一管理两种监听器与重载时的请求等待，不依赖控制平面或前端。展示所需的汇总、排序、交互状态、键位与刷新策略属于客户端。只有新增的运行时数据或操作才需要扩展守护进程 API。

前端与 dae 的边界是公开构建产物和 HTTP API 契约。以后可将整个 `web/` 迁移为独立仓库或 submodule，嵌入、静态托管与端口分发代码继续留在 dae。

`make client-test` 在关闭 CGO 的环境运行客户端测试，检查 OpenAPI 是否与契约一致，并检查传递依赖，阻止客户端引入守护进程实现。CI 在安装 clang 和构建 eBPF 之前执行此目标。

## API 参考

完整字段与操作定义见 [OpenAPI 3.1 文档](../../api/openapi.json)，可导入支持 OpenAPI 的工具。直接编辑 OpenAPI 文档；`make client-test` 检查其字段、必填项、类型和数组长度与 Go 契约是否一致。配置与持久化语义见 [页面与运行时 API](api.md)。

| 方法与路径 | 响应 | 权限与请求 |
| --- | --- | --- |
| `GET /api/status` | `StatusSnapshot` | TCP 需要管理 token；Unix 使用 socket 权限 |
| `GET /api/selectors` | `SelectorsResponse` | 公开；`admin_enabled` 表示此传输上的管理功能是否启用 |
| `PUT /api/selectors/{group}` | `SelectorState` | 管理权限；`{"node_id":"..."}` |
| `DELETE /api/selectors/{group}` | `SelectorState` | 管理权限；空正文，恢复配置 |
| `GET /api/device` | `DeviceState` | 仅 TCP，需识别直连 LAN 设备 |
| `PUT` / `DELETE /api/device/sets/{name}` | `DeviceState` | 加入 / 退出集合，空正文 |
| `PUT /api/device/mitm` | `DeviceState` | `{"enabled":true}` 或 `{"enabled":false}` |
| `DELETE /api/device/mitm` | `DeviceState` | 空正文，恢复配置 |
| `GET /api/certificate` | `Certificate` | 公开 CA 名称与指纹；未启用时 `404` |
| `GET /ca.pem`、`/ca.cer`、`/ca.mobileconfig` | 证书文件 | 公开；未启用时 `404` |

所有 PUT 和 DELETE 请求需 `X-Dae-API: 1`，SDK 会自动携带。MITM 修改需 `X-Dae-MITM: <当前 CA SHA-256 指纹>`。TCP 管理请求带 `Authorization: Bearer <api_token>`；未配置 token 返回 `403`，已配置但请求 token 缺失或错误返回 `401`。Unix 上能连接 socket 的进程拥有本地管理权限，但无法通过 socket 操作“当前 LAN 设备”。

名称按 URL 路径段编码；正文限制为 1 KiB，有 JSON 时需 `Content-Type: application/json`，其余请求正文必须为空。`/api/*` 不接受查询参数，浏览器必须同源，TCP 的 Host 必须是实际连接到的路由器 IP 和端口。GET 路由也支持 HEAD。

成功返回 `200`。业务错误为 `{"error":"说明"}`；未知路由、错误方法和部分证书下载错误可能为纯文本。客户端应按 HTTP 状态码处理，不能依赖英文错误文案：

| 状态码 | 含义 |
| --- | --- |
| `400` | 正文、字段、节点 ID 等不合法；Unix 无法识别设备地址 |
| `401` / `403` | 鉴权失败、管理 token 未配置、跨源或设备身份无法确认 |
| `404` / `405` | 资源不存在 / 方法不支持 |
| `409` | CA 已变化，应重新获取并核验当前证书 |
| `413` / `415` | 正文过大 / Content-Type 不正确 |
| `500` | 应用或持久化失败，检查守护进程日志 |
| `503` | 正在启动或重载，稍后重试 |

写入成功直接返回更新后的状态。写入超时并不证明操作未执行，应重新查询当前状态；客户端库不会自动重试写请求。

## 状态字段与版本兼容

当前 `StatusSnapshot.schema` 为 `7`。插件报告位于 `mitm_plugins[].details`；Surge 报告提供 `enabled` 与 `modules`，独立 Surge 命令按实例汇总这些报告。状态顶层不再包含 `surge` 字段。客户端忽略新增响应字段，拒绝不支持的 schema、null 响应、重复 JSON 键与类型错误；请求中的未知字段仍被拒绝。不兼容的状态结构调整必须增加 schema。状态端点为 `/api/status`。

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
| `mitm_plugins` | 插件实例状态、数量与可选的 `details` 报告，不包含插件配置对象 |

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
        Token:    os.Getenv("DAE_API_TOKEN"),
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
