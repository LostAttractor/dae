# 页面与运行时 API

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
  work: '加入后通过所选节点访问工作服务'
}
routing {
  client(work) && domain(suffix: example.com) -> manual
  fallback: direct
}
```

`global.api_port` 默认 `0`，不监听；非零时在所有路由器地址提供 HTTP 页面与 API，独立于 Surge。用实际局域网 IP 访问，例如 `http://192.168.1.1:9080/`。不支持域名、反向代理或跨源浏览器请求；改变端口或路由器地址后需重载。

## 使用与持久化

- **Selectors**：`selector` 等价于 `selector(0)`；`selector(n)` 指定默认路径索引。选择影响使用该组的所有设备，需要 `api_token`。选择按节点 ID 保存，重排不变，配置中节点消失时恢复默认。
- **This Device**：设备可自行加入多个 `client(name)` MAC 集合，仍按路由顺序匹配。仅限 `global.lan_interface` 上的直连 ARP/NDP 邻居；接口名支持通配符，更换 MAC 后需重新加入。未通过身份检查时返回 `403`，节点列表和证书下载仍可用。
- **HTTPS Modules**：设备开关覆盖 `surge.client_source_address`，包括显式关闭。开启前须[安装并信任 CA](mitm-certificate.md)，页面不会探测信任状态。

`client` 块提供名称下方的纯文本简介，留空则隐藏；只展示路由引用的集合，重复定义报错。简介随 `dae reload` 更新，不影响成员。

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

## API

所有修改请求带 `X-Dae-API: 1`；JSON 正文需 `Content-Type: application/json`，无 JSON 的请求使用空正文。selector 修改需要 `Authorization: Bearer <api_token>`；MITM 修改需要 `X-Dae-MITM: <当前 CA 的 SHA-256 指纹>`。名称须 URL 编码；命令行可省略 `Origin`。

未配置 `global.api_token` 时，selector 修改返回 `403` 并说明未配置；已配置但请求令牌缺失或错误时返回 `401`。设备自助设置不需要该令牌。

| 方法与路径 | 行为 |
| --- | --- |
| `GET /api/device` | 当前设备的 IP、MAC、集合（`name`、`description`、`joined`）和 MITM 状态（`enabled`、`override`、`ca_fingerprint`）；无法识别 MAC 时 `403` |
| `PUT` / `DELETE /api/device/sets/{name}` | 加入 / 退出集合 |
| `PUT /api/device/mitm` | `{"enabled":true}` 开启，`false` 关闭 |
| `DELETE /api/device/mitm` | 恢复配置 |
| `GET /api/selectors` | 各组的默认/当前节点 ID、覆盖状态、候选节点健康与延迟；`admin_enabled` 表示已配置令牌 |
| `PUT /api/selectors/{name}` | `{"node_id":"状态返回的 ID"}` 选择节点 |
| `DELETE /api/selectors/{name}` | 恢复配置 |
| `GET /api/certificate` | CA 名称与 SHA-256 指纹；不可用时 `404` |
| `GET /ca.pem`、`/ca.cer`、`/ca.mobileconfig` | 下载公开证书，无需识别 MAC |

MITM 的 `override` 为 `null` 时继承配置。修改后重新查询对应状态。CA 更换后 MITM 修改返回 `409`，需刷新页面，核对、安装并信任当前证书。
