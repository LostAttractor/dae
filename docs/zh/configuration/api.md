# 页面与运行时 API

独立构建、连接参数、TUI 开发与完整字段说明见 [API 与独立客户端开发](api-client.md)，机器可读定义见 [OpenAPI 文档](../../api/openapi.json)。

只读路由/子系统分析、设备集合影响预览和管理员 MAC 管理见 [规则解释与设备管理](explain.md)。信任边界及监听器、会话生命周期见[访问控制设计](../design/api-access-control.md)。

```text
global {
  lan_interface: br-lan
}
api {
  listen: '9080'
  user_key: 'replace-with-a-user-key'
  admin_key: 'replace-with-a-different-admin-key'
  allow_lan_anonymous: true
}
group {
  manual {
    filter: subtag(my_sub)
    policy: selector
    # track_all: true
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

## 权限与连接

`api.listen` 留空时不监听 TCP；Unix socket `/var/run/dae.sock` 始终提供 API，权限为 `0600`，不要求 API key。仅填写端口（如 `'9080'`）绑定 `global.lan_interface` 匹配的入口接口，跟随接口增删；显式 IP 仅在本机持有该地址期间享有旁路。IPv6 链路本地地址须使用裸端口和 `global.lan_interface`；配置不接受显式链路本地 IPv6 地址或带 `%zone` 的地址。`'0.0.0.0:9080'` 和 `'[::]:9080'` 是通配监听，按 Go `tcp` 和系统能力选择地址族，可能同时接受 IPv4/IPv6，不应把 `0.0.0.0` 当作仅 IPv4。TCP 同一端口提供 HTTP 和 HTTPS，HTTPS 使用 daemon 的持久化 CA，与 MITM 是否启用无关。原生直连必须使用实际监听端点的 IP 字面地址；域名入口通过 HTTPS 反向代理提供。

仅填写端口时必须配置 `global.lan_interface`；不接受 bridge、bond 等 master 的从接口，因为本机 TCP 流量交付给 master，而非观测到的入口端口。保留原入口范围时应使用显式 API IP 地址；只有打算将 master 的全部端口作为 LAN 入口时，才改为选择 master。暂时没有匹配接口时等待接口出现，不会回退为监听全部地址。本机地址变化会自动原子更新 API 旁路与设备路由豁免共用的地址集合，不替换控制面或中断管理服务；准备或发布失败时保留原集合并重试。相同 LAN 端点的 pattern 更新保留交集接口上的监听；无法复用的绑定类型切换可能因端口冲突而失败，失败保留原服务，这类变更需要重启。裸端口模式下，内核路由旁路与设备路由豁免均要求目的为本机地址、TCP 端口匹配，且逻辑 LAN 入口上已有实际监听 socket；目的地址不必属于该入口接口。热插拔时若端口临时被占用，监听器会自行退避重试，无需再次触发接口事件。

| 权限 | 授权方式 | 功能 |
| --- | --- | --- |
| 普通用户 | HTTPS `user_key` / `admin_key` 或其会话 Cookie；开启 `allow_lan_anonymous` 后的已验证直连 LAN | 全局 status、metrics、selector 读取、CA 下载与信任验证；已识别设备的自身设置、状态与 MITM 验证 |
| 管理员 | HTTPS `admin_key` 或其会话 Cookie；受文件权限保护的 Unix socket | 包含普通权限；节点切换、探测、脚本、重载、资源刷新、跨设备管理、规则解释、路由影响预览、pprof |

`user_key` 与 `admin_key` 必须不同。没有配置 `admin_key` 时远程管理不可用；LAN 免 key 永远只授予普通权限。两类 key 都不证明设备身份：`/api/device...` 仍校验当前 LAN 连接，涉及 MAC 的操作要求真实以太网身份。远程管理员和 Unix 客户端可以通过显式 MAC 管理接口操作其他设备。

通过 TCP 访问管理接口、metrics 和 pprof 均需 HTTPS，已验证的匿名 LAN 也不例外。开启 `allow_lan_anonymous` 后，已验证的直连 LAN 客户端可通过 HTTP 读取 CA 信息、下载证书和创建信任挑战；挑战证明始终要求 HTTPS。HTTP 安装页不发送凭据，也不加载管理功能。未开启匿名 LAN 时，请从 Unix socket 导出 CA，再通过可信渠道安装。

`web_origins` 是所有浏览器 API 与监控请求的精确来源白名单，包括带 key 或 Cookie 的请求；默认只允许同源。填写不含路径的 HTTP(S) origin，主机大小写和默认端口会规范化。**同源**要求协议、主机、端口均相同；**同站**不要求端口相同，但仍受浏览器的协议与站点判断约束。例如 `https://192.168.1.1:8443` 页面直连 `https://192.168.1.1:9080` 是同站跨源，须把页面源加入白名单。`Sec-Fetch-Site: cross-site` 的管理请求即使来源在白名单内也被拒绝；不同主机的 LAN IP 不因同属局域网就成为同站。CLI、Prometheus 等不带 Origin 的原始 key 调用不受浏览器来源限制，仍须独立鉴权。

仅原始 `user_key` 或 `admin_key` 可以通过 HTTPS 登录，响应 JSON 为 `{role, expires_at}`，会话由 `Set-Cookie` 写入 `__Host-dae-session`：`Secure; HttpOnly; SameSite=Strict; Path=/`，不设置 `Domain`。会话按角色与 API Host/端口签名，七天绝对到期；已有 Cookie、LAN 匿名权限或 Unix 隐式管理员权限不能签发或延长会话。页面以 `credentials: include` 发送管理请求，不保存原始 key 或可供 JavaScript 读取的会话凭据。退出调用 `DELETE /api/session` 清除 Cookie，包括已过期 Cookie；复制件直到到期或相应 key 轮换才失效。

Cookie 不按端口隔离，同一主机名/IP 的其他 HTTPS 服务必须可信；建议使用专用管理主机名。同一 Cookie 作用域内的标签页共享登录状态。显式 Authorization 优先：错误 key 不回退 Cookie，错误 Cookie 不回退匿名 LAN；正确原始 key 可替换过期会话。

独立页面的 API 目标在开发/构建时固定为 `DAE_API_URL`，默认相对 `/api/`，不提供运行时地址切换。支持同站直连或同源 HTTPS 反代。反代两段都必须使用 TLS，上游验证 dae CA、Host 改写为实际 API IP:port、保留页面 Origin 并加入 `web_origins`，无条件设置 `X-Dae-Proxy: 1`。该标记及转发头只会减权，不会赋予代理服务器的 LAN/MAC 身份：匿名访问、所有自身设备接口及浏览器 CA/MITM 验证不可用，key/Cookie 管理、显式 MAC 管理与 CA 下载仍可用。HTTP 或 Unix 反代上游不受支持。最小配置见 [独立部署](api-client.md#同源-https-反向代理)。

`api.web` 默认 `true`，控制 daemon 提供静态页面；`make WEBUI=n` 完全不编入页面。独立部署见 [API 与独立客户端](api-client.md)。`/metrics` 始终作为普通 API 提供，无独立开关；`api.pprof` 默认 `false`，启用后 `/debug/pprof/` 使用管理员权限。

## 使用与持久化

`selector` 默认只持续检测当前选中的节点，启动屏障也只等待该节点。切换后立即检测新节点，旧节点停止周期检测，正在进行的检测可完成。自动策略的检测范围见[自动节点选择](outbound-selection.md)。

选择器页面使用可搜索的下拉框，收起时只展示当前节点，展开后在限定高度内滚动候选列表，支持大量节点与长名称。默认提供当前节点或候选旁的 **Test** 和整组 **Test All**；测试只触发一轮组配置的 DNS 连通性探测，不改变选择或持续检测范围。已授权且可见的页面每两秒更新结果，未检测节点显示 **Not tested**。

在 selector 的 group 块中设置 `track_all: true` 并重载，即可持续检测全部候选；默认是 `false`。这是配置文件功能，不提供修改它的 API，也不保存在运行时状态中。开启后，页面显示 **Monitoring all nodes**，替代所有 **Test / Test All** 按钮。检测间隔沿用组的 `check_interval` 等配置，启动屏障仍只等待选中节点。此项仅适用于 `selector`，不通过 `group(name)` 继承。

`dae status`（包括 verbose/JSON）中，selector 只列出选中、持续追踪、正在检测或仍有活动连接的节点。已测试但空闲且未追踪的候选只在 `/api/selectors` 和页面中保留最后结果；组及全局累计流量仍包含这些路径。

- **Selectors**：普通权限可查看状态；管理员可以切换节点、重置与触发探测。裸 `selector` 没有默认节点概念：优先恢复保存的选择，否则以首个候选作为初始选择，页面不显示默认标记或重置按钮。只有显式 `selector(n)`（包括 `selector(0)`）才声明默认路径索引。选择影响使用该组的所有设备。选择按独立的逻辑路径引用保存；候选重排、priority、TLS、multiplex、全局 mark 和探测参数变化不改变保存的选择。
- **This Device**：设备可自行加入多个 `client(name)` MAC 集合，仍按路由顺序匹配。API 连接必须经过 `global.lan_interface` 的入口，且入口源 MAC 与直连 ARP/NDP 邻居一致；接口名支持通配符，更换 MAC 后需重新加入。未通过身份检查时返回 `403`，普通权限的节点列表和证书下载仍可用。
- **This Device Status**：当前访问设备的活动/累计连接、上下行流量、最近一分钟速率和实际使用的出站。按入口 MAC 汇总 IPv4/IPv6；无需管理员登录。统计口径为用户态上游连接，包含 splice 加速连接，不包含内核直通、本地 HTTP/DNS 响应和 daemon 自身的后台请求。累计值跨 reload 保留；设备无活动连接且最近一分钟历史过期后回收统计，重新出现时开始新的观察周期，`started_at` 表示该周期起点。进程重启会重置所有计数。
- **Global Status**：版本、运行时间、全局连接与流量、出站/节点状态、域名表和插件状态，普通权限即可读取；退出后若没有 LAN 免 key 权限则清除展示的数据。
- **HTTPS Modules**：为当前设备选择 **Router default**、**On** 或 **Off**。**Router default** 跟随 `mitm.client_source_address` 并显示当前取值；**On** / **Off** 覆盖该配置，包括显式关闭。开启前须[安装并信任 CA](certificate.md)，否则该设备的 HTTPS 连接会失败。当前浏览器验证 CA 前，该区域持续显示警告；开启期间页面会自动测试 CA，验证失败时显示红色警告。**Test certificate** 分别测试当前浏览器接受 CA 和透明 MITM 链路，结果只代表该浏览器。

设备与已授权的全局状态在页面可见时每两秒刷新，速率沿用五秒采样、最多一分钟的历史。后台标签页暂停轮询；请求失败会显示更新时间和重试状态。

没有以太网身份时，页面显示当前 IP 连接和入口接口，可读取连接上下文；只读诊断另需管理员权限。设备流量、MAC 集合成员变更与比较、设备 MITM 设置和 MITM 测试仍要求可验证的以太网 MAC；管理员登录不能补充该身份。

入口记录包含 TCP 端点、链路类型、时间戳和接口索引，必须在 30 秒内且对应 LAN 钩子仍已挂载。新的数据路径代次使用空记录表，保留数据路径的重载保留入口记录。IPv6 链路本地端点的 zone 必须沿接收方向经 VLAN、网桥或 bond 对应到观测入口。例如 `enp1s0f0np0 → lan（VLAN）→ br-lan` 可保留 `lan_interface: lan`，同时将 `api.listen` 设为显式 IP:port，而非裸端口。以太网设备身份还要求回程路由直连，且入口 MAC 与该路由接口的 ARP/NDP 邻居一致。

`client` 块的纯文本简介用作页面显示名称：配置了简介时只显示简介，未配置时显示集合名称。按钮的无障碍标签和操作提示也使用同一显示名称；API 请求仍以配置中的集合名称标识目标。展示路由引用或配置了内核导出的集合，重复定义报错。简介随 `dae reload` 更新，不影响成员。

管理员展开成员设置后显示 **Referenced** 关联规则，不计算具体目标的命中结果，也不改变成员关系。折叠行通过小圆点表示 Policy 状态：绿色为 **Applies**（适用）、灰色为 **Does not apply**（不适用）、黄色为 **Unknown**（未知）；悬停提示和辅助技术标签提供策略名称与状态。展开后在独立的详情行显示 **Rules** 和完整的 **Policy** 标签。API 的 `policy_match` 仅表示策略选择，独立于规则的 `match`；策略适用时仍需判断规则条件及执行顺序。存在多个活动策略且缺少入口信息时，不推定默认策略适用。共享片段保留各策略中的引用，系统或插件的全局引用只列一次；DNAT 表达式保留目标 IP 和可选端口。条件详情展示成员变更前后的谓词值。**Compare a target** 才会针对指定流量计算完整条件和规则顺序；其中的 **Uncertain** 表示现有上下文尚不足以确定完整结果。

**Reset Default** 仅在 selector 显式配置了 `selector(n)` 时提供；它清除保存的选择并恢复该路径。选择器和 HTTPS 模块的设置来源统一显示为 **Default** 或 **Custom**。MITM 的重置仍清除设备覆盖。设置保存在 `$DAE_LOCATION_CACHE/runtime-state.json`（默认 `/var/lib/dae/runtime-state.json`，权限 `0600`），重载、重启或关闭 API 后保留，不改写主配置。已有连接和 UDP 会话保持原路径。

保存引用包含完整代理链、各跳的来源和名称，以及入口地址族、显式 interface/mark；未显式配置 mark 时保存继承关系。本地节点按配置名称识别；订阅节点按订阅标签与名称识别，未命名订阅使用订阅地址指纹区分来源。唯一同名节点可跟随地址或凭据更新。链接指纹用于重名消歧，不保存链接或凭据原文；选择时同源重名的节点必须继续匹配指纹，不会因另一节点消失而误认剩余的同名节点。

保存路径被 filter 排除、入口地址族暂时缺失或无法唯一匹配时，保留引用并临时使用显式默认／首个候选，页面显示 **Temporary fallback**。订阅更新后出现同源同名的多个节点时，必须匹配原链接指纹；即使组过滤只留下一个同名节点，也不会将其认作原节点。后续 reload 中路径重新出现会自动恢复。临时回退期间重新选择节点（包括当前正在使用的节点）会替换保存的偏好。健康检查失败本身不会清除选择或改选其他节点。

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

启用页面后，HTTP 和 HTTPS 在 `api.listen` 上共用页面/API。浏览器 CA/MITM 验证仅支持直接连接 dae；反代入口显示验证不可用，不能用代理的 TLS 握手证明浏览器信任 dae CA。CA 信任测试使用新签发的服务器证书和短期挑战，不要求 MITM 或设备 MAC。daemon 和当前设备均开启 MITM 后可进一步验证透明解密。透明 MITM 测试使用虚拟目标的 443 端口，由 `api.mitm_test_ipv4`（默认 `203.0.113.254`）和 `api.mitm_test_ipv6`（默认 `2001:db8:ffff::254`）指定。两项测试均不增加监听端口，也不依赖上游服务。

展开 **Certificate & browser verification** 可使用 **Download** 菜单下载描述文件、DER 和 PEM 格式的证书。点击 **Test certificate** 后执行以下测试；页面发现当前设备已开启 HTTPS Modules、开启 HTTPS Modules，或设备与 CA 变化时，也会自动执行：

1. 浏览器向 API 请求 `POST /api/certificate/tests`，签发仅存于内存的临时证书和新密钥，再通过同一端口的 HTTPS 读取 `/api/certificate/tests/{id}`。服务端只接受发起源 IP 到该路由器 IP 使用本次或更新挑战证书完成的握手；管理证书或更早挑战的连接返回 `409` 并关闭，由浏览器重试。浏览器核对挑战 ID 和 CA 指纹，成功后 **CA trust** 显示 **CA trusted by this browser**。无需先打开 HTTPS 页面或接受证书警告。
2. 设备已开启 MITM 且第一步通过时，请求与页面地址同族的虚拟 IP，经正常透明捕获、设备开关判断和 TLS 解密，由内置 `dae-mitm-test` 插件校验入口 MAC 并直接响应，不拨号上游。同一设备访问路由器和虚拟目标时选择不同源 IP 也可验证。

虚拟地址须未被占用、流量能够到达 dae，且位于本地子网和其他软件的 Fake IP 池之外；与本地子网重叠的配置会被拒绝。不要将虚拟地址配置到路由器网卡上。如果网络在流量到达 dae 前丢弃默认文档保留地址段，须调整目标地址或路由。捕获严格限定为两个 IP 的 443 端口，API 流量仍由内核直通，无关流量沿用普通路由语义。

测试不修改持久化管理证书、CA、MITM 证书缓存或设备开关。同一源 IP 最多有 8 个未完成信任挑战，全局最多 64 个，超额返回 `429`。挑战期限为一分钟，临时证书有效期另留五分钟时钟偏差余量，不超过 CA 到期时间，也不延长挑战期限。信任证明成功后消费挑战，一分钟内未完成则过期；临时证书随挑战移除，该源 IP 与路由器 IP 之间没有剩余挑战后，新连接恢复原管理证书。共享源 IP 的客户端会临时使用同一组挑战证书，其他源 IP 不受影响。透明 MITM 挑战及观测每个已验证 MAC 最多保留 8 条、全局最多 256 条，一分钟后过期，超额创建返回 `503`。CA 更换使信任挑战失效，MITM 配置发布使拦截挑战失效。CA 指纹变化清除两项结果，MITM 测试代次、设备身份或开关变化只清除透明 MITM 结果。结果附有测试时间和 CA 指纹，只代表当前浏览器。先前对管理证书添加的“接受风险”例外不能让挑战证书通过；依赖该例外的用户在挑战有效期内可能无法新建 HTTPS 连接，可回到 HTTP 安装页安装并信任 CA。浏览器不能区分证书拒绝、网络不通和部分浏览器策略限制时显示 **Verification incomplete**。

API 地址使用 IPv4 或非链路本地 IPv6 字面地址。证书和 MITM 挑战绑定发起请求的精确 Origin，允许独立 Web 读取该挑战的证明。浏览器核对 `/api/certificate` 公布的虚拟目标、挑战 ID 和 CA 指纹。CA 身份更换后旧 TLS 连接不能读取新身份元数据；相同 CA 的重载保留连接。验证结果只代表执行验证的浏览器或 CLI 信任库。

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

JSON API 的 POST、PUT、DELETE 要求 `X-Dae-API: 1`，JSON 正文要求 `Content-Type: application/json`。MITM 修改还要求 `X-Dae-MITM: <当前 CA SHA-256 指纹>`。名称须 URL 编码，JSON API 不接受查询参数。无效凭据返回 `401`，权限不足或设备身份不可验证返回 `403`。授权先于读取请求正文与资源。pprof 保留标准工具的请求格式和查询参数。

| 方法与路径 | 行为 |
| --- | --- |
| `PUT /api/session` | HTTPS 原始 Bearer key → `200` JSON `{role, expires_at}` 和 HttpOnly 会话 Cookie；不接受已有会话、匿名 LAN 或 Unix 隐式权限 |
| `DELETE /api/session` | 空正文，`204`，清除会话 Cookie；不吊销已复制会话 |
| `GET /api/status` | 普通权限：全局运行状态 |
| `GET /api/device` | 当前设备的 IP、MAC、集合（`name`、`description`、`joined`）和 MITM 状态（`enabled`、`override`、`default`、`ca_fingerprint`）；无法识别 MAC 时 `403` |
| `GET /api/device/status` | 当前设备设置及按 MAC 归属的用户态上游运行统计；仅已识别的直连 LAN 设备 |
| `POST /api/device/mitm-tests` | 空正文，创建当前设备的透明 MITM 测试挑战；返回 `201`，不改变 MITM 设置 |
| `GET /api/device/mitm-tests/{id}` | 当前设备的测试观测；过期、配置已更新或其他设备的挑战返回 `404` |
| `PUT` / `DELETE /api/device/sets/{name}` | 加入 / 退出集合 |
| `PUT /api/device/mitm` | `{"enabled":true}` 开启，`false` 关闭 |
| `DELETE /api/device/mitm` | 恢复配置 |
| `GET /api/selectors` | 普通权限：selector 状态；`admin_enabled` 表示可执行管理员修改；`auth_mode` 为 `user_key`、`admin_key`、`lan`、`unix` |
| `PUT /api/selectors/{name}` | `{"node_id":"状态返回的 ID"}` 选择节点 |
| `DELETE /api/selectors/{name}` | 恢复显式 `selector(n)`；未配置默认时返回 `409` |
| `POST /api/probes` | `{"outbound":"manual","node_id":"节点 ID"}` 探测单节点；省略或留空 `node_id` 探测整个出站；返回 `202` 和接受的节点 ID |
| `POST /api/plugins/{instance}/scripts/run` | 需要管理权限；`{"module":"tools","script":"demo.tool","mac":"02:00:00:00:00:50"}` 触发已有 cron/generic 任务；返回 `202`、本任务运行编号及受理状态 |
| `POST /api/plugins/{instance}/store/migrate` | 需要管理权限；`{"from_mac":"02:00:00:00:00:11","to_mac":"02:00:00:00:00:22"}` 移动设备存储分区；同步 `200` 返回 `instance`、规范化 MAC 和 `keys_moved`，不返回值 |
| `POST /api/resources/refresh` | 需要管理权限；空正文，立即尝试刷新当前配置的订阅、模块与依赖；返回 `202` 和受理状态 |
| `GET /api/resources` | 需要管理权限；最近一次 API/自动刷新状态和下次自动检查时间 |
| `POST /api/operations` | 需要管理权限；提交 reload、suspend 或 refresh，返回 `202` 和唯一操作 ID |
| `GET /api/operations/{id}` | 需要管理权限；查询操作状态，未知或过期 ID 返回 `404` |
| `POST /api/certificate/tests` | 仅 TCP API；返回 `201` 和一分钟有效的 CA 信任挑战，签发内存临时证书；不修改管理证书，不要求 MAC 或 MITM |
| `GET /api/certificate/tests/{id}` | 仅 HTTPS；挑战证书握手返回 `id`、`ca_fingerprint`、`expires_at` 并消费挑战，管理证书或旧挑战连接 `409` 后关闭，已消费或失效挑战 `404` |
| `GET /api/certificate` | CA 名称、SHA-256 指纹，以及可选 `mitm_test_generation`、`mitm_test_origins`；不可用时 `404` |
| `GET /api/certificate/ca.pem`、`/api/certificate/ca.cer`、`/api/certificate/ca.mobileconfig` | 普通权限下载 CA，无需识别 MAC |

MITM 的 `override` 为 `null` 时继承配置；`default` 是配置对该设备的取值，清除覆盖后重新生效。修改后重新查询对应状态。CA 更换后 MITM 修改返回 `409`，需刷新页面，核对、安装并信任当前证书。

`POST /api/probes` 是统一的主动连通性探测入口，适用于已实例化且启用连通性检测的出站（包括 selector、自动选择组和直接引用的节点）。使用已配置的 DNS 探测、超时和并发限制，不接受任意测试 URL 或请求级配置覆盖。`202` 仅表示已受理，排队或进行中的重复请求会合并；不创建持久化任务，也不改变节点选择或 `track_all`。selector 通过 `GET /api/selectors` 查询 `checking`、`tested`、`checked_at`、`healthy`、`latency_ms`，其他出站通过 `/api/status` 查看运行时健康和延迟。未知出站为 `404`、不属于该出站的节点为 `400`、无需检测的内置出站为 `409`。

节点与 selector 节点的 `health` 由服务端统一计算：`unknown`（未检测或尚无观测）、`healthy`、`confirming`（失败确认中）、`unhealthy`。休眠节点保留最近的健康观测；`healthy` 布尔值仍表示当前运行时可用性。节点的 `support` 按网络给出学到的能力，`failing` 标记最近一次探测失败的已确认网络；失效网络在再次探测成功前不承接流量，能力仍保持已确认。组的 `health` 为 `healthy`、`warning` 或 `degraded`。客户端直接渲染 `health`；`checking` 单独表示探测活动。

`SelectorState.track_all` 是配置的只读值。仅显式 `selector(n)` 返回 `default_node_id`；裸 selector 省略此字段，客户端应据此隐藏默认标记与重置操作。

`node_id` 是当前实际使用的运行时节点 ID。有保存偏好时，`overridden` 为 `true`，并返回 `saved_selection` 的 `name` 和 `status`（`matched`、`missing`、`ambiguous`）。后两种状态表示保留偏好并使用临时初始选择；客户端不能把当前 `node_id` 误当作新的保存偏好。

脚本执行的 `202` 仅表示受理；`status.scope` 为有效执行域，只有 device 有 `status.mac`。省略请求 `mac` 恒为本机，不自动选择唯一 LAN 设备；本机不依赖 LAN 发现、MITM 或 CA。显式 MAC 只可用于开启 LAN 隔离的脚本，并须当前 MITM 启用。cron 每次本机一次，开启隔离时另对启用 LAN 设备每 MAC 一次；共享脚本仅本机一次。显式启用 MAC 不要求在线，all/IP/CIDR 只枚举宿主已知 LAN。后台 HTTP 始终使用 daemon 路由，响应结束后任务继续。

通过 `/api/status` 的 `plugins[].details.modules[].tasks` 查询完成情况。每个定义始终有 `scope: "local"` 行，开启隔离时另有 `scope: "device"` 行并携带 MAC，本机在前、设备按 MAC 排序；unknown 不是执行目标。status/list 只读快照，不触发设备发现。LAN 查询失败只影响设备行或模块 Warnings，不阻断本机、不复用旧 LAN 目标。`type` 为 cron/generic，`runs` 属于本任务本执行域，`last_trigger` 为 `cron`/`http-api`。generic 无计划且空闲时 ready，按实例/模块/名称计数与消歧。只保留最新尝试，重载重置计数，手动执行不改变 cron 计划。不存在为 `404`；名称歧义、非法 MAC 或未隔离脚本指定 MAC 为 `400`（要求省略 MAC）；禁用设备或同域任务忙碌为 `409`；worker 未激活/停止或设备发现不可用为 `503`。不接受源代码或参数覆盖，不自动重试。

Surge 实例 `isolate_lan` 默认 true；dae 模块描述符中的 `isolate_lan` 和 `script { name: '脚本名' isolate_lan: false }` 提供模块级及逐脚本覆盖，优先级为脚本 > 模块 > 实例，不改 sgmodule 语法。本机始终使用本机分区；开启隔离的 LAN 按可信直连 MAC 分区，未知身份 read=null、write/删除=false，DNS 脚本答案不缓存。关闭隔离所有来源共享本机分区及 DNS 脚本缓存，scope 显示 local 而非原始来源。capture 与 cron 须采用一致策略与执行域才能共享 Cookie；关闭隔离会跨客户端共享 Cookie/token，更改设置不自动迁移、合并或删除旧分区。`store` 只控制持久化，单一文件为分区 → keys → strings，实例合计 64 MiB、单值 4 MiB。

显式存储迁移移动所选实例旧 MAC 分区的全部 `$persistentStore` 键值，并删除旧分区。不覆盖或合并：目标分区只要存在（包括空分区）就返回 `409`；当前 daemon 及重载重叠代际中源/目标有脚本执行，也返回 `409`。非法或相同 MAC 为 `400`，实例/源分区不存在为 `404`，能力或 Runtime 不可用、锁等待取消/超时为 `503`。两个地址须为不同的非零单播六字节 MAC，不能选择 local/unknown；不要求设备在线或启用 MITM。固定五秒 context 预算约束可取消的锁等待，不保证硬中断文件 I/O。

迁移前先停用旧 MAC 的流量和后台执行资格，核对目标地址及目标无数据，并停止其他进程对同一文件的脚本写入，再运行 `dae plugins surge store migrate 02:00:00:00:00:11 02:00:00:00:00:22 --instance surge`。设备分区跨脚本共享，因此不按模块/脚本筛选。不移动本机数据、通知、计数或排队任务，不修改设备授权、路由或隔离配置；旧 MAC 再次执行仍可建立新分区。内存模式只移动当前 Runtime 数据，不开启持久化或增加跨重载保留。若 `500` 明确提示 `script store migration was published, but durability is unconfirmed`，表示已迁移，但持久性未确认；超时或连接中断同样不证明数据未变。API/CLI 不自动重试，应先核实结果。跨进程文件锁只串行化提交，不保护其他进程的整段脚本执行。

先用 `dae plugins surge list` 查看可手动执行的 cron/generic 脚本，可用 `--instance`、`--module` 筛选或 `--json` 获取任务数组。再用 `dae plugins surge run demo.tool --instance surge --module tools` 触发，需要 daemon 已运行。`run --json` 返回受理快照，执行结果通过插件状态查询；CLI/API 手动触发的 `last_trigger` 为 `http-api`。详见[手动触发](surge-module.md#手动触发)。

Surge 的 `plugins[].details.notifications` 按 scope、MAC、module、script、script_type 分组，各保留最多 50 条 `$notification.post`，最新在前、为空时省略。每条含 `id`、`created_at`、`scope`（local/device/unknown）、设备专用 `mac`、`module`、`script`、`script_type`、`title`、`subtitle`、`body`，超长文本带 `truncated: true`。本机和 unknown 不混组，共享 LAN 显示 local。记录独立于日志级别和执行成功与否，重载清空；文本默认每组 3 条，`surge status -v`、`plugins status -v` 和 JSON 返回全部保留记录。详见[近期通知](surge-module.md#近期通知)。

daemon 的状态 schema 为 16，通过 Unix socket `/var/run/dae.sock` 的 `/api/status` 提供，供 `dae status`、`dae plugins status` 和插件命令使用，无需开启 `api.listen`。顶层 `direct_fallback_connections` 统计进程生命周期内因无可用节点而回退到 direct 且在用户态成功建立的连接，内核直连转发的 fallback 流与其他内核直通流量一样不计入；路径、组和节点统计不含 fallback 字段。`tables` 报告内核表和用户态资源池，提供 `scope`（`kernel` / `userspace`）、`on_full`（`evict` / `reject` / `omit` / `unlimited`）和可选 `error`。`limit: 0` 表示无容量上限；非空 `error` 表示 `used` 不可用，而不是零。LRU 满载时正常淘汰，与拒绝新增的资源池不同。域名表另报告时间 GC、内核候选数量和等待重试的投影变更。Registry 的 `used` 和 `limit` 分别是保留历史的估算字节数与预算，并非进程 RSS；`breakdown` 包含保留配对数 `pairs`、域名数 `domains`、去重地址数 `ips`、地址类型分布 `ipv4` / `ipv6`、累计回收配对数 `gc`、当前不完整桶 `incomplete_buckets` 和累计配对漏记 `omitted_pairs`。`compiled_plugins` 列出运行进程已注册的插件类型，不含系统 MITM diagnostic。`plugins` 列出已接受配置的实例 ID、类型、`enabled`、宿主生命周期状态和规则数量，并保留系统诊断实例。`declared_scopes` 是实例声明的 HTTP 范围数量，`scopes` 是应用 HTTP 总开关后的有效数量；disabled 实例不求值声明，数量为零且无 `details`。`http_active` 表示 scope 可参与 HTTP 处理，不保证设备截获或 worker 健康；生效时 `http_reason` 为空，否则为 `disabled`、`no_scopes`、`mitm_disabled`、`prepared`、`draining` 或 `unavailable`。仅管理员能看到插件定义的 `details`，Surge 提供 `enabled`、`modules`。节点延迟只包含成功样本，自动组通过 `selection` 提供故障降级和选择评分。CLI 与 daemon 应使用同一版本。

`dae plugins status --json` 输出进程级 `compiled_plugins`、`buffer_memory` 和完整 `plugins`，没有活动实例或按实例筛选时仍保留编入清单和内存统计；`dae plugins <类型> status --instance <ID>` 查询单个实例。普通用户和 LAN 匿名请求保留统计及插件通用状态，但省略所有 `plugins[].details`。完整插件报告及通知要求管理员权限。插件自动状态排除配置凭据；通知字段保留脚本显式提交的文本。

通知另受每实例 1 MiB 保守 JSON 编码预算限制，scope、MAC 及文本按最坏转义长度计费。超限先从最长执行域/脚本历史删除最旧记录，数量相同则删除最旧的一条，每组实际可能少于 50 条。verbose/JSON 返回预算内全部记录；MAC 不加入 Prometheus 标签。

### 资源刷新

```sh
sudo curl --unix-socket /var/run/dae.sock -X POST -H 'X-Dae-API: 1' http://localhost/api/resources/refresh
sudo curl --unix-socket /var/run/dae.sock http://localhost/api/operations/OPERATION_ID
sudo curl --unix-socket /var/run/dae.sock http://localhost/api/resources
```

刷新使用已接受的配置；配置文件修改仍需 `dae reload`。`202` 返回唯一操作 ID，任务在 HTTP 响应后继续执行，与 reload、suspend 串行发布。等待或运行中重复触发刷新返回 `409`。操作包含 `id`、`kind`、`state`（queued/running/completed/failed/canceled）、`trigger`（`api` / `automatic`）、排队/开始/完成时间、`progress`、`result` 和 `error`。`GET /api/resources` 返回最近一次刷新的 `operation` 和下次检查时间 `next_check`；首次刷新前省略 `operation`。`result` 会说明因下载或校验失败而保留旧内容的资源组数量。自动检查间隔和回退规则见[资源缓存](cache-directory.md#全局资源缓存)。

`POST /api/operations` 接受 `{"kind":"reload"}`、`{"kind":"suspend"}` 或 `{"kind":"refresh"}`。reload/suspend 可附加 `"abort":true`。队列最多容纳 16 项等待操作，满时返回 `409`。daemon 保留最近完成的 64 项操作和当前工作；`GET /api/operations/{id}` 对未知、过期或上次 daemon 的 ID 返回 `404`。CLI 超时只停止等待，不取消已受理的操作。本地 Unix 操作接口在控制平面替换期间持续可用。
