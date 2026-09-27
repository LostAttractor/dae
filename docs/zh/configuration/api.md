# 页面与运行时 API

独立构建、连接参数、TUI 开发与完整字段说明见 [API 与独立客户端开发](api-client.md)，机器可读定义见 [OpenAPI 文档](../../api/openapi.json)。

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

`selector` 默认只持续检测当前选中的节点，启动屏障也只等待该节点。切换后立即检测新节点，旧节点停止周期检测，正在进行的检测可完成。其他选择策略保持原有检测范围。

选择器页面使用可搜索的下拉框，收起时只展示当前节点，展开后在限定高度内滚动候选列表，支持大量节点与长名称。默认提供当前节点或候选旁的 **Test** 和整组 **Test All**；测试只触发一轮组配置的 DNS 连通性探测，不改变选择或持续检测范围。已授权且可见的页面每两秒更新结果，未检测节点显示 **Not tested**。

在 selector 的 group 块中设置 `track_all: true` 并重载，即可持续检测全部候选；默认是 `false`。这是配置文件功能，不提供修改它的 API，也不保存在运行时状态中。开启后，页面显示 **Monitoring all nodes**，替代所有 **Test / Test All** 按钮。检测间隔沿用组的 `check_interval` 等配置，启动屏障仍只等待选中节点。此项仅适用于 `selector`，不通过 `group(name)` 继承。

`dae status`（包括 verbose/JSON）中，selector 只列出选中、持续追踪、正在检测或仍有活动连接的节点。已测试但空闲且未追踪的候选只在 `/api/selectors` 和页面中保留最后结果；组及全局累计流量仍包含这些路径。

- **Selectors**：配置 `api_key` 后，在页面顶部输入密钥并点击 **Login** 即可查看状态、切换节点；未配置密钥时，通过直连 LAN 身份校验的客户端可直接使用，顶部显示 **LAN access**。裸 `selector` 没有默认节点概念：优先恢复保存的选择，否则以首个候选作为初始选择，页面不显示默认标记或重置按钮。只有显式 `selector(n)`（包括 `selector(0)`）才声明默认路径索引。选择影响使用该组的所有设备。选择按节点 ID 保存，重排不变；保存的节点消失时回到显式默认，未配置默认时使用首个候选。
- **This Device**：设备可自行加入多个 `client(name)` MAC 集合，仍按路由顺序匹配。API 连接必须经过 `global.lan_interface` 的入口，且入口源 MAC 与直连 ARP/NDP 邻居一致；接口名支持通配符，更换 MAC 后需重新加入。未通过身份检查时返回 `403`，登录后的节点列表和公开证书下载仍可用。
- **HTTPS Modules**：设备开关覆盖 `mitm.client_source_address`，包括显式关闭。开启前须[安装并信任 CA](mitm-certificate.md)，页面不会探测信任状态。

登录后使用 `HttpOnly`、`SameSite=Strict` Cookie 保存有效期为 7 天的签名会话，Cookie 不包含 API key 原文。刷新页面或重载 daemon 后保留登录状态；**Logout** 清除浏览器 Cookie，修改 `api_key` 会使已有会话失效。**Refresh** 更新状态和刷新时间。设备自助设置无需管理员登录。

`global.api_key` 为可选项。未配置或留空时，状态查询和 selector 管理沿用设备自助接口的直连 LAN 校验：连接必须有 `global.lan_interface` 的有效 eBPF 入口记录，源 MAC 与直连 ARP/NDP 邻居一致。每个请求都会校验，私网源 IP、转发头或旧会话 Cookie 均不能代替此身份；WAN、经路由转发或无法识别的客户端返回 `403`。此模式无需登录，也不签发会话 Cookie。配置密钥后，TCP 管理请求（包括 LAN 客户端）必须通过密钥/会话认证。两种模式下 Unix socket 均使用文件系统权限。

配置项已由 `global.api_token` 更名为 `global.api_key`，升级时需同步修改已有配置；CLI 环境变量使用 `DAE_API_KEY`，Go SDK 使用 `client.Options.APIKey`。

设备识别使用 eBPF 在 LAN 入口记录的 TCP 连接信息，不要求路由或邻居表中的接口名匹配 `lan_interface`。例如 `enp1s0f0np0 → lan（VLAN）→ br-lan` 可保留 `lan_interface: lan`；bond 或其他分层以太网接口使用相同的识别流程。每个请求更新入口 MAC 和时间戳，配置重载时清除记录。无入口记录、记录超过 30 秒、回程路由非直连，或入口 MAC 与该路由接口上的 ARP/NDP 邻居不一致时拒绝设备操作；其他接口上的同名 IP 不影响识别。

`client` 块的纯文本简介用作页面显示名称：配置了简介时只显示简介，未配置时显示集合名称。按钮的无障碍标签和操作提示也使用同一显示名称；API 请求仍以配置中的集合名称标识目标。展示路由引用或配置了内核导出的集合，重复定义报错。简介随 `dae reload` 更新，不影响成员。

**Reset Default** 仅在 selector 显式配置了 `selector(n)` 时提供；它清除保存的选择并恢复该路径。选择器和 HTTPS 模块的设置来源统一显示为 **Default** 或 **Custom**。MITM 的重置仍清除设备覆盖。设置保存在 `$DAE_LOCATION_CACHE/runtime-state.json`（默认 `/var/lib/dae/runtime-state.json`，权限 `0600`），重载、重启或关闭 API 后保留，不改写主配置。已有连接和 UDP 会话保持原路径。

也可直接编辑该文件，文件系统事件触发热重载，支持原子替换。无效内容、未知节点 ID、应用失败或文件暂时缺失时保留当前状态。例如：

```json
{
  "selectors": {},
  "clients": {"work": ["02:00:00:00:00:50"]},
  "mitm": {"02:00:00:00:00:50": true}
}
```

保留三个对象，删除对象内条目可清除覆盖或成员。`selectors` 使用 `/api/selectors` 返回的节点 ID，MAC 使用小写冒号格式。避免同时编辑文件和操作 API。

旧版本写入的 `selector_tracking` 字段在读取时忽略，后续写入时移除；请在主配置的 group 块中设置 `track_all`。运行时状态文件不能覆盖该配置。

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
| `PUT` / `DELETE /api/device/sets/{name}` | 加入 / 退出集合 |
| `PUT /api/device/mitm` | `{"enabled":true}` 开启，`false` 关闭 |
| `DELETE /api/device/mitm` | 恢复配置 |
| `GET /api/selectors` | 需要管理权限；各组的默认/当前节点 ID、覆盖状态、候选节点健康与延迟；授权成功后 `admin_enabled` 为 true，`auth_mode` 为 `api_key`、`lan` 或 `unix` |
| `PUT /api/selectors/{name}` | `{"node_id":"状态返回的 ID"}` 选择节点 |
| `DELETE /api/selectors/{name}` | 恢复显式 `selector(n)`；未配置默认时返回 `409` |
| `POST /api/probes` | `{"outbound":"manual","node_id":"节点 ID"}` 探测单节点；省略或留空 `node_id` 探测整个出站；返回 `202` 和接受的节点 ID |
| `GET /api/certificate` | CA 名称与 SHA-256 指纹；不可用时 `404` |
| `GET /ca.pem`、`/ca.cer`、`/ca.mobileconfig` | 下载公开证书，无需识别 MAC |

MITM 的 `override` 为 `null` 时继承配置。修改后重新查询对应状态。CA 更换后 MITM 修改返回 `409`，需刷新页面，核对、安装并信任当前证书。

`POST /api/probes` 是统一的主动连通性探测入口，适用于已实例化且启用连通性检测的出站（包括 selector、自动选择组和直接引用的节点）。使用已配置的 DNS 探测、超时和并发限制，不接受任意测试 URL 或请求级配置覆盖。`202` 仅表示已受理，排队或进行中的重复请求会合并；不创建持久化任务，也不改变节点选择或 `track_all`。selector 通过 `GET /api/selectors` 查询 `checking`、`tested`、`checked_at`、`healthy`、`latency_ms`，其他出站通过 `/api/status` 查看运行时健康和延迟。未知出站为 `404`、不属于该出站的节点为 `400`、无需检测的内置出站为 `409`。旧的 `/api/selectors/{name}/test` 和 `/tracking` 已移除。

`SelectorState.track_all` 是配置的只读值。仅显式 `selector(n)` 返回 `default_node_id`；裸 selector 省略此字段，客户端应据此隐藏默认标记与重置操作。

daemon 的状态 schema 为 11，通过 Unix socket `/var/run/dae.sock` 的 `/api/status` 提供，供 `dae status`、`dae plugins status` 和插件命令使用，无需开启 `global.api_port`。顶层 `direct_fallback_connections` 统计进程生命周期内因无可用节点而回退到 direct 且成功建立的连接；路径、组和节点统计不含 fallback 字段。域名表报告时间 GC 和内核候选数量，用户态 `limit: 0` 表示无容量上限。Registry 的 `used` 是域名–IP 配对数；`breakdown` 包含域名数 `domains`、去重地址数 `ips`、地址类型分布 `ipv4` / `ipv6` 和累计回收配对数 `gc`。`plugins` 列出实例 ID、类型、宿主生命周期状态和规则数量。可选 `details` 由插件定义，Surge 提供 `enabled`、`modules`。CLI 与 daemon 应使用同一版本。

`dae plugins status --json` 输出完整 `plugins`；`dae plugins <类型> status --instance <ID>` 查询单个实例。插件的任务详情可能包含视频 BV/CID、标题等上下文，但不得包含 Cookie 或 API 密钥。
