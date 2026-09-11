# 页面与运行时 API

独立构建、连接参数、TUI 开发与完整字段说明见 [API 与独立客户端开发](api-client.md)，机器可读定义见 [OpenAPI 文档](../../api/openapi.json)。

```text
global {
  lan_interface: br-lan
  api_port: 9080
  api_token: '替换为私密令牌'
}
group {
  manual {
    filter: subtag(my_sub)
    policy: selector
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

- **Selectors**：`selector` 等价于 `selector(0)`；`selector(n)` 指定默认路径索引。选择影响使用该组的所有设备，需要 `api_token`。选择按节点 ID 保存，重排不变，配置中节点消失时恢复默认。
- **This Device**：设备可自行加入多个 `client(name)` MAC 集合，仍按路由顺序匹配。API 连接必须经过 `global.lan_interface` 的入口，且入口源 MAC 与直连 ARP/NDP 邻居一致；接口名支持通配符，更换 MAC 后需重新加入。未通过身份检查时返回 `403`，节点列表和证书下载仍可用。
- **HTTPS Modules**：设备开关覆盖 `mitm.client_source_address`，包括显式关闭。开启前须[安装并信任 CA](mitm-certificate.md)，页面不会探测信任状态。

设备识别使用 eBPF 在 LAN 入口记录的 TCP 连接信息，不要求路由或邻居表中的接口名匹配 `lan_interface`。例如 `enp1s0f0np0 → lan（VLAN）→ br-lan` 可保留 `lan_interface: lan`；bond 或其他分层以太网接口使用相同的识别流程。每个请求更新入口 MAC 和时间戳，配置重载时清除记录。无入口记录、记录超过 30 秒、回程路由非直连，或入口 MAC 与该路由接口上的 ARP/NDP 邻居不一致时拒绝设备操作；其他接口上的同名 IP 不影响识别。

`client` 块提供名称下方的纯文本简介，留空则隐藏；展示路由引用或配置了内核导出的集合，重复定义报错。简介随 `dae reload` 更新，不影响成员。

**Use Configuration** 清除 selector 或 MITM 覆盖。设置保存在 `$DAE_LOCATION_CACHE/runtime-state.json`（默认 `/var/lib/dae/runtime-state.json`，权限 `0600`），重载、重启或关闭 API 后保留，不改写主配置。已有连接和 UDP 会话保持原路径。

也可直接编辑该文件，文件系统事件触发热重载，支持原子替换。无效内容、未知节点 ID、应用失败或文件暂时缺失时保留当前状态。例如：

```json
{
  "selectors": {},
  "clients": {"work": ["02:00:00:00:00:50"]},
  "mitm": {"02:00:00:00:00:50": true}
}
```

保留三个对象，删除对象内条目可清除覆盖或成员。`selectors` 使用 `/api/selectors` 返回的节点 ID，MAC 使用小写冒号格式。避免同时编辑文件和操作 API。

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

PUT 和 DELETE 请求需 `X-Dae-API: 1`。JSON 正文需 `Content-Type: application/json`，无 JSON 的请求使用空正文。selector 修改需要 `Authorization: Bearer <api_token>`；MITM 修改需要 `X-Dae-MITM: <当前 CA 的 SHA-256 指纹>`。名称须 URL 编码；命令行可省略 `Origin`。

未配置 `global.api_token` 时，selector 修改返回 `403` 并说明未配置；已配置但请求令牌缺失或错误时返回 `401`。设备自助设置不需要该令牌。

| 方法与路径 | 行为 |
| --- | --- |
| `GET /api/status` | 运行时完整状态；TCP 需要管理 token，本地 Unix socket 使用文件系统权限 |
| `GET /api/device` | 当前设备的 IP、MAC、集合（`name`、`description`、`joined`）和 MITM 状态（`enabled`、`override`、`ca_fingerprint`）；无法识别 MAC 时 `403` |
| `PUT` / `DELETE /api/device/sets/{name}` | 加入 / 退出集合 |
| `PUT /api/device/mitm` | `{"enabled":true}` 开启，`false` 关闭 |
| `DELETE /api/device/mitm` | 恢复配置 |
| `GET /api/selectors` | 各组的默认/当前节点 ID、覆盖状态、候选节点健康与延迟；`admin_enabled` 表示该传输上的管理功能已启用 |
| `PUT /api/selectors/{name}` | `{"node_id":"状态返回的 ID"}` 选择节点 |
| `DELETE /api/selectors/{name}` | 恢复配置 |
| `GET /api/certificate` | CA 名称与 SHA-256 指纹；不可用时 `404` |
| `GET /ca.pem`、`/ca.cer`、`/ca.mobileconfig` | 下载公开证书，无需识别 MAC |

MITM 的 `override` 为 `null` 时继承配置。修改后重新查询对应状态。CA 更换后 MITM 修改返回 `409`，需刷新页面，核对、安装并信任当前证书。

daemon 的状态 schema 为 10，通过 Unix socket `/var/run/dae.sock` 的 `/api/status` 提供，供 `dae status`、`dae plugins status` 和插件命令使用，无需开启 `global.api_port`。域名表报告时间 GC 和内核候选数量，用户态 `limit: 0` 表示无容量上限。Registry 的 `used` 是域名–IP 配对数；`breakdown` 包含域名数 `domains`、去重地址数 `ips`、地址类型分布 `ipv4` / `ipv6` 和累计回收配对数 `gc`。`plugins` 列出实例 ID、类型、宿主生命周期状态和规则数量。可选 `details` 由插件定义，Surge 提供 `enabled`、`modules`。CLI 与 daemon 应使用同一版本。

`dae plugins status --json` 输出完整 `plugins`；`dae plugins <类型> status --instance <ID>` 查询单个实例。插件的任务详情可能包含视频 BV/CID、标题等上下文，但不得包含 Cookie 或 API 密钥。
