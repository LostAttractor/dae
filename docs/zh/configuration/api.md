# 页面与运行时 API

独立构建、连接参数、TUI 开发与完整字段说明见 [API 与独立客户端开发](api-client.md)，机器可读定义见 [OpenAPI 文档](../../api/openapi.json)。

只读路由/子系统分析、设备集合影响预览和管理员 MAC 管理见 [规则解释与设备管理](explain.md)。

```text
global {
  lan_interface: br-lan
  api_port: 9080
  api_key: '替换为私密密钥'
}
group {
  manual {
    filter: subtag(my_sub)
    policy: selector
    # track_all: true  # 持续检测所有候选；修改后执行 dae reload
  }
}
client {
  work {
    description: '加入后通过所选节点访问工作服务'
  }
}
routing {
  client(work) && domain(suffix: example.com) -> manual
  fallback: direct
}
```

`global.api_port` 默认 `0`，不监听；非零时在所有路由器地址提供 HTTP 页面与 API，独立于 MITM 插件。用实际局域网 IP 访问，例如 `http://192.168.1.1:9080/`。不支持域名、反向代理或跨源浏览器请求；改变端口或路由器地址后需重载。

## 使用与持久化

`selector` 默认只持续检测当前选中的节点，启动屏障也只等待该节点。切换后立即检测新节点，旧节点停止周期检测，正在进行的检测可完成。自动策略的检测范围见[自动节点选择](outbound-selection.md)。

选择器页面使用可搜索的下拉框，收起时只展示当前节点，展开后在限定高度内滚动候选列表，支持大量节点与长名称。默认提供当前节点或候选旁的 **Test** 和整组 **Test All**；测试只触发一轮组配置的 DNS 连通性探测，不改变选择或持续检测范围。已授权且可见的页面每两秒更新结果，未检测节点显示 **Not tested**。

在 selector 的 group 块中设置 `track_all: true` 并重载，即可持续检测全部候选；默认是 `false`。这是配置文件功能，不提供修改它的 API，也不保存在运行时状态中。开启后，页面显示 **Monitoring all nodes**，替代所有 **Test / Test All** 按钮。检测间隔沿用组的 `check_interval` 等配置，启动屏障仍只等待选中节点。此项仅适用于 `selector`，不通过 `group(name)` 继承。

`dae status`（包括 verbose/JSON）中，selector 只列出选中、持续追踪、正在检测或仍有活动连接的节点。已测试但空闲且未追踪的候选只在 `/api/selectors` 和页面中保留最后结果；组及全局累计流量仍包含这些路径。

- **Selectors**：配置 `api_key` 后，在页面顶部输入密钥并点击 **Login** 即可查看状态、切换节点；未配置密钥时，通过直连 LAN 身份校验的客户端可直接使用，顶部显示 **LAN access**。裸 `selector` 没有默认节点概念：优先恢复保存的选择，否则以首个候选作为初始选择，页面不显示默认标记或重置按钮。只有显式 `selector(n)`（包括 `selector(0)`）才声明默认路径索引。选择影响使用该组的所有设备。选择按独立的逻辑路径引用保存；候选重排、priority、TLS、multiplex、全局 mark 和探测参数变化不改变保存的选择。
- **This Device**：设备可自行加入多个 `client(name)` MAC 集合，仍按路由顺序匹配。API 连接必须经过 `global.lan_interface` 的入口，且入口源 MAC 与直连 ARP/NDP 邻居一致；接口名支持通配符，更换 MAC 后需重新加入。未通过身份检查时返回 `403`，登录后的节点列表和公开证书下载仍可用。
- **This Device Status**：当前访问设备的活动/累计连接、上下行流量、最近一分钟速率和实际使用的出站。按入口 MAC 汇总 IPv4/IPv6；无需管理员登录。统计口径为用户态上游连接，包含 splice 加速连接，不包含内核直通、本地 HTTP/DNS 响应和 daemon 自身的后台请求。累计值跨 reload 保留，进程重启归零。
- **Global Status**：版本、运行时间、全局连接与流量、出站/节点状态、域名表和插件状态，沿用管理权限。配置密钥时登录后可见，退出或会话失效时清除展示的数据。
- **HTTPS Modules**：设备开关覆盖 `mitm.client_source_address`，包括显式关闭。开启前须[安装并信任 CA](mitm-certificate.md)。**Test Certificate** 分别测试当前浏览器接受 CA 和透明 MITM 链路，结果只代表该浏览器。

设备与已授权的全局状态在页面可见时每两秒刷新，速率沿用五秒采样、最多一分钟的历史。后台标签页暂停轮询；请求失败会显示更新时间和重试状态。

登录后使用 `HttpOnly`、`SameSite=Strict` Cookie 保存有效期为 7 天的签名会话，Cookie 不包含 API key 原文。刷新页面或重载 daemon 后保留登录状态；**Logout** 清除浏览器 Cookie，修改 `api_key` 会使已有会话失效。**Refresh** 更新状态和刷新时间。设备自助设置无需管理员登录。

`global.api_key` 为可选项。未配置或留空时，状态查询和 selector 管理沿用设备自助接口的直连 LAN 校验：连接必须有 `global.lan_interface` 的有效 eBPF 入口记录，源 MAC 与直连 ARP/NDP 邻居一致。每个请求都会校验，私网源 IP、转发头或旧会话 Cookie 均不能代替此身份；WAN、经路由转发或无法识别的客户端返回 `403`。此模式无需登录，也不签发会话 Cookie。配置密钥后，TCP 管理请求（包括 LAN 客户端）必须通过密钥/会话认证。两种模式下 Unix socket 均使用文件系统权限。

配置项已由 `global.api_token` 更名为 `global.api_key`，升级时需同步修改已有配置；CLI 环境变量使用 `DAE_API_KEY`，Go SDK 使用 `client.Options.APIKey`。

设备识别使用 eBPF 在 LAN 入口记录的 TCP 连接信息，不要求路由或邻居表中的接口名匹配 `lan_interface`。例如 `enp1s0f0np0 → lan（VLAN）→ br-lan` 可保留 `lan_interface: lan`；bond 或其他分层以太网接口使用相同的识别流程。每个请求更新入口 MAC 和时间戳，配置重载时清除记录。无入口记录、记录超过 30 秒、回程路由非直连，或入口 MAC 与该路由接口上的 ARP/NDP 邻居不一致时拒绝设备操作；其他接口上的同名 IP 不影响识别。

`client` 块的纯文本简介用作页面显示名称：配置了简介时只显示简介，未配置时显示集合名称。按钮的无障碍标签和操作提示也使用同一显示名称；API 请求仍以配置中的集合名称标识目标。展示路由引用或配置了内核导出的集合，重复定义报错。简介随 `dae reload` 更新，不影响成员。

**Reset Default** 仅在 selector 显式配置了 `selector(n)` 时提供；它清除保存的选择并恢复该路径。选择器和 HTTPS 模块的设置来源统一显示为 **Default** 或 **Custom**。MITM 的重置仍清除设备覆盖。设置保存在 `$DAE_LOCATION_CACHE/runtime-state.json`（默认 `/var/lib/dae/runtime-state.json`，权限 `0600`），重载、重启或关闭 API 后保留，不改写主配置。已有连接和 UDP 会话保持原路径。

保存引用包含完整代理链、各跳的来源和名称，以及入口地址族、显式 interface/mark；未显式配置 mark 时保存继承关系。本地节点按配置名称识别；订阅节点按订阅标签与名称识别，未命名订阅使用订阅地址指纹区分来源。唯一同名节点可跟随地址或凭据更新。链接指纹用于重名消歧，不保存链接或凭据原文；选择时同源重名的节点必须继续匹配指纹，不会因另一节点消失而误认剩余的同名节点。

保存路径被 filter 排除、入口地址族暂时缺失或无法唯一匹配时，保留引用并临时使用显式默认／首个候选，页面显示 **Temporary fallback**。后续 reload 中路径重新出现会自动恢复。临时回退期间重新选择节点（包括当前正在使用的节点）会替换保存的偏好。健康检查失败本身不会清除选择或改选其他节点。

也可直接编辑该文件，文件系统事件触发热重载，支持原子替换。无效内容、应用失败或文件暂时缺失时保留当前状态。例如：

```json
{
  "selectors": {},
  "clients": {"work": ["02:00:00:00:00:50"]},
  "mitm": {"02:00:00:00:00:50": true}
}
```

保留三个对象，删除对象内条目可清除覆盖或成员。`selectors` 的值是包含 `nodes`、`ipversion`、`interface` 和可选 `mark` 的路径对象，不是 API 的运行时节点 ID；建议通过页面或 `dae selector set` 保存。MAC 使用小写冒号格式。避免同时编辑文件和操作 API。

`track_all` 在主配置的 group 块中设置，运行时状态文件不能覆盖该配置。状态文件中的未知字段会被拒绝。

## 证书与 MITM 测试

启用页面及带 CA 的 MITM 后，CA 测试复用 `global.api_port`：HTTP 提供页面/API，TLS 分支只提供 CA 挑战。透明 MITM 测试使用虚拟目标的 443 端口，由 `global.api_mitm_test_ipv4`（默认 `203.0.113.254`）和 `global.api_mitm_test_ipv6`（默认 `2001:db8:ffff::254`）指定。两项测试均不增加监听端口，也不依赖上游服务。

点击 **Test Certificate** 后：

1. 浏览器访问精确直通的 CA 测试端点，以当前 CA 签发的路由器 IP 证书完成 TLS 并读取随机挑战响应。设备 MITM 尚未开启时也可测试。
2. 设备已开启 MITM 且第一步通过时，请求与页面地址同族的虚拟 IP，经正常透明捕获、设备开关判断和 TLS 解密，由内置 `dae-certificate-test` 插件校验入口 MAC 并直接响应，不拨号上游。同一设备访问路由器和虚拟目标时选择不同源 IP 也可验证。

虚拟地址须未被占用、流量能够到达 dae，且位于本地子网和其他软件的 Fake IP 池之外；与本地子网重叠的配置会被拒绝。不要将虚拟地址配置到路由器网卡上。如果网络在流量到达 dae 前丢弃默认文档保留地址段，须调整目标地址或路由。捕获严格限定为两个 IP 的 443 端口，API 流量仍由内核直通，无关流量沿用普通路由语义。

测试不修改设备开关。挑战一分钟过期，配置发布后旧挑战失效；页面在 CA、测试代次、设备身份或开关变化时清除旧结果。结果附有测试时间和 CA 指纹，不代表设备所有应用的信任状态。浏览器不能区分证书拒绝、网络不通和部分浏览器策略限制时显示 **Verification incomplete**。

请通过路由器的 IPv4 或非链路本地 IPv6 字面地址访问页面，无需外部网站或 DNS 映射。测试端点只接受发起页面的精确 Origin；普通 `/api/` 继续要求同源。浏览器根据 `/api/certificate` 的 `test_mitm_origins` 校验虚拟目标。新挑战使用新的 TLS 连接，不能由缓存响应或普通 HTTPS 可达性替代 MITM 验证。虚拟目标没有上游服务，因此 MITM 验证未完成时不能区分绕过和网络不通。

## 导出 MAC 集合

`ipset`、`nftset` 可单独或同时配置；导出集合无需路由引用，也会显示在设备页面：

```text
client {
  work {
    description: '加入工作设备集合'
    ipset: dae_work
    nftset: 'inet/filter/dae_work'
  }
}
```

`ipset` 创建 `hash:mac`；`nftset` 使用 `family/table/set`，创建 `ether_addr` set，支持 `inet`、`ip`、`ip6`、`bridge`、`netdev`、`arp`。同步 MAC，不解析 IP 或生成带值 map。需要对应内核支持和 `CAP_NET_ADMIN`，无需命令行工具。

启动、配置重载和成员变更时同步，失败尝试回滚。每个后端独立原子更新，多个后端与 dae 路由之间不构成统一事务。

集合须专供 dae 使用，不能由多个 client 共享。dae 创建缺失的表/集合并替换全部成员，不修改防火墙规则。已有集合须为普通 MAC 集合；不支持 ipset 扩展或 nft constant/interval/timeout/dynamic 标志，nft 元素计数器随成员重建。停止 dae 或移除配置后保留集合；防火墙重建后执行 `dae reload` 重新同步。

检查：`ipset list dae_work`、`nft list set inet filter dae_work`。匹配：iptables 的 `-m set --match-set dae_work src`，或同一 nft 表内的 `ether saddr @dae_work`。

## API

POST、PUT 和 DELETE 请求需 `X-Dae-API: 1`。JSON 正文需 `Content-Type: application/json`，无 JSON 的请求使用空正文。配置密钥时，状态查询及 selector 读写需要 `Authorization: Bearer <api_key>` 或有效的浏览器会话 Cookie；未配置时要求通过直连 LAN 身份校验。MITM 修改需要 `X-Dae-MITM: <当前 CA 的 SHA-256 指纹>`。密钥模式下显式 Authorization 头优先于 Cookie。名称须 URL 编码；命令行可省略 `Origin`。

未配置 `global.api_key` 时，TCP 管理请求未通过 LAN 身份校验返回 `403`；已配置但请求密钥/会话缺失、错误或过期时返回 `401`。设备自助设置始终要求直连 LAN 身份，不需要该密钥。

| 方法与路径 | 行为 |
| --- | --- |
| `PUT /api/session` | 配置密钥时使用 `Authorization: Bearer <api_key>` 登录并设置会话 Cookie；未配置时校验 LAN/Unix 权限并清除旧 Cookie。空正文，成功返回 `204` |
| `DELETE /api/session` | 清除浏览器会话 Cookie；空正文，成功返回 `204` |
| `GET /api/status` | 运行时完整状态；TCP 配置密钥时需要 API key/会话，未配置时校验直连 LAN 身份；Unix socket 使用文件系统权限 |
| `GET /api/device` | 当前设备的 IP、MAC、集合（`name`、`description`、`joined`）和 MITM 状态（`enabled`、`override`、`ca_fingerprint`）；无法识别 MAC 时 `403` |
| `GET /api/device/status` | 当前设备设置及按 MAC 归属的用户态上游运行统计；仅已识别的直连 LAN 设备 |
| `POST /api/device/certificate-tests` | 空正文，创建浏览器证书测试挑战；返回 `201`，不改变 MITM 设置 |
| `GET /api/device/certificate-tests/{id}` | 当前设备的测试观测；过期、配置已更新或其他设备的挑战返回 `404` |
| `PUT` / `DELETE /api/device/sets/{name}` | 加入 / 退出集合 |
| `PUT /api/device/mitm` | `{"enabled":true}` 开启，`false` 关闭 |
| `DELETE /api/device/mitm` | 恢复配置 |
| `GET /api/selectors` | 需要管理权限；各组的默认/当前节点 ID、覆盖状态、候选节点健康与延迟；授权成功后 `admin_enabled` 为 true，`auth_mode` 为 `api_key`、`lan` 或 `unix` |
| `PUT /api/selectors/{name}` | `{"node_id":"状态返回的 ID"}` 选择节点 |
| `DELETE /api/selectors/{name}` | 恢复显式 `selector(n)`；未配置默认时返回 `409` |
| `POST /api/probes` | `{"outbound":"manual","node_id":"节点 ID"}` 探测单节点；省略或留空 `node_id` 探测整个出站；返回 `202` 和接受的节点 ID |
| `POST /api/plugins/{instance}/scripts/run` | 需要管理权限；`{"module":"tools","script":"demo.tool"}` 触发已有 cron/generic 任务；返回 `202`、本任务运行编号及受理状态 |
| `POST /api/resources/refresh` | 需要管理权限；空正文，立即尝试刷新当前配置的订阅、模块与依赖；返回 `202` 和受理状态 |
| `GET /api/resources` | 需要管理权限；最近一次 API/自动刷新状态和下次自动检查时间 |
| `GET /api/certificate` | CA 名称、SHA-256 指纹、`test_available` 和可选 `test_generation`；不可用时 `404` |
| `GET /ca.pem`、`/ca.cer`、`/ca.mobileconfig` | 下载公开证书，无需识别 MAC |

MITM 的 `override` 为 `null` 时继承配置。修改后重新查询对应状态。CA 更换后 MITM 修改返回 `409`，需刷新页面，核对、安装并信任当前证书。

`POST /api/probes` 是统一的主动连通性探测入口，适用于已实例化且启用连通性检测的出站（包括 selector、自动选择组和直接引用的节点）。使用已配置的 DNS 探测、超时和并发限制，不接受任意测试 URL 或请求级配置覆盖。`202` 仅表示已受理，排队或进行中的重复请求会合并；不创建持久化任务，也不改变节点选择或 `track_all`。selector 通过 `GET /api/selectors` 查询 `checking`、`tested`、`checked_at`、`healthy`、`latency_ms`，其他出站通过 `/api/status` 查看运行时健康和延迟。未知出站为 `404`、不属于该出站的节点为 `400`、无需检测的内置出站为 `409`。

`SelectorState.track_all` 是配置的只读值。仅显式 `selector(n)` 返回 `default_node_id`；裸 selector 省略此字段，客户端应据此隐藏默认标记与重置操作。

`node_id` 是当前实际使用的运行时节点 ID。有保存偏好时，`overridden` 为 `true`，并返回 `saved_selection` 的 `name` 和 `status`（`matched`、`missing`、`ambiguous`）。后两种状态表示保留偏好并使用临时初始选择；客户端不能把当前 `node_id` 误当作新的保存偏好。

脚本执行的 `202` 仅表示受理，任务使用 daemon 后台路由客户端，HTTP 响应结束后继续执行。通过 `/api/status` 的 `plugins[].details.modules[].tasks` 查询完成情况，`type` 为 `cron` 或 `generic`，`runs` 标识最新尝试，`last_trigger` 为 `cron` 或 `http-api`。generic 没有定时计划，空闲时为 `ready`。仅保留最近一次尝试，计数与历史随重载重置。手动执行不改变 cron 的下次定时时间。实例/任务不存在 `404`，省略 module 导致同名歧义 `400`，已在等待/运行 `409`，worker 未激活或已停止 `503`。不接受脚本文本或参数覆盖，API 客户端不自动重试执行请求。

先用 `dae plugins surge list` 查看可手动执行的 cron/generic 脚本，可用 `--instance`、`--module` 筛选或 `--json` 获取任务数组。再用 `dae plugins surge run demo.tool --instance surge --module tools` 触发，需要 daemon 已运行。`run --json` 返回受理快照，执行结果通过插件状态查询；CLI/API 手动触发的 `last_trigger` 为 `http-api`。详见[手动触发](surge-module.md#手动触发)。

Surge 的 `plugins[].details.notifications` 包含每个实例按脚本各保留的最近 50 条 `$notification.post` 通知，最新在前，没有通知时省略。脚本身份由 `module`、`script` 和 `script_type` 共同确定。字段为 `id`、`created_at`、`module`、`script`、`script_type`、`title`、`subtitle`、`body`，超长文本带 `truncated: true`。记录独立于日志级别和脚本成功与否，重载后清空。`dae plugins surge status` 默认每脚本显示 3 条；`surge status -v`、`plugins status -v` 和 JSON 返回全部保留记录。详见[近期通知](surge-module.md#近期通知)。

daemon 的状态 schema 为 12，通过 Unix socket `/var/run/dae.sock` 的 `/api/status` 提供，供 `dae status`、`dae plugins status` 和插件命令使用，无需开启 `global.api_port`。顶层 `direct_fallback_connections` 统计进程生命周期内因无可用节点而回退到 direct 且成功建立的连接；路径、组和节点统计不含 fallback 字段。域名表报告时间 GC 和内核候选数量，用户态 `limit: 0` 表示无容量上限。Registry 的 `used` 是域名–IP 配对数；`breakdown` 包含域名数 `domains`、去重地址数 `ips`、地址类型分布 `ipv4` / `ipv6` 和累计回收配对数 `gc`。`plugins` 列出实例 ID、类型、宿主生命周期状态和规则数量。可选 `details` 由插件定义，Surge 提供 `enabled`、`modules`。节点延迟只包含成功样本，自动组通过 `selection` 提供故障降级和选择评分。CLI 与 daemon 应使用同一版本。

`dae plugins status --json` 输出完整 `plugins`；`dae plugins <类型> status --instance <ID>` 查询单个实例。插件自动状态排除配置凭据；通知字段保留脚本显式提交的文本，使用相同的管理访问权限。

通知另受每实例 1 MiB 保守 JSON 编码预算限制，文本按最坏转义长度计费。超限时先从记录最多的脚本删除最旧记录，数量相同时删除最旧的一条，因此每脚本实际保留数量可能少于 50 条。verbose/JSON 返回预算内全部记录。

### 资源刷新

```bash
sudo curl --unix-socket /var/run/dae.sock -X POST -H 'X-Dae-API: 1' http://localhost/api/resources/refresh
sudo curl --unix-socket /var/run/dae.sock http://localhost/api/resources
```

刷新使用已接受的配置；配置文件修改仍需 `dae reload`。`202` 表示受理，任务在 HTTP 响应后继续执行，与 reload 串行发布。等待或运行中重复触发返回 `409`。状态含 `run`、`state`（idle/queued/running/completed/failed）、`trigger`（api/automatic）、开始/完成时间、`next_check`、`result` 或 `error`；只保留最近一次，daemon 重启后重置。`result` 会说明因下载或校验失败而保留旧内容的资源组数量。自动检查间隔和回退规则见[资源缓存](cache-directory.md#全局资源缓存)。
