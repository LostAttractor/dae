# 规则解释与设备管理

`dae explain`、`dae-client explain` 和 Web 的 **Explain Decisions** 使用当前配置和运行时证据解释一个假设的新连接。它们不建立目标连接、不发送 DNS 查询、不执行脚本，也不更新缓存、节点检查或运行时设置。现有连接及 UDP 源关联可能保留先前决定。

## 命令行

两种程序共用命令和连接参数；以下示例也可将 `dae` 换成 `dae-client`：

```sh
dae explain route 198.51.100.10:443 --self --api http://192.168.1.1:9080
dae explain route 198.51.100.10:443 --self --sni example.com --join work \
  --api http://192.168.1.1:9080 --json
dae explain route 198.51.100.10:443 --mac 02:00:00:00:00:10 \
  --source-ip 192.168.1.10 --source-port 40000 --interface br-lan --dscp 0
dae explain domain example.com
dae explain dns example.com --qtype AAAA
dae explain outbound proxy --network tcp4
dae explain plugins https://example.com/path --mac 02:00:00:00:00:10 \
  --source-ip 192.168.1.10
dae explain route --input request.json --json
```

`--input -` 从标准输入读取完整 JSON 请求，替代其他输入字段；`--self` 仍决定使用设备接口。`--join`、`--leave` 只比较假设成员关系。连接参数与 [API 客户端](api-client.md) 相同。`explain` 与需要内核权限的包追踪 `trace` 是独立命令。

`--self` 需要可验证的直连 LAN TCP 请求，不能通过 Unix socket 继承 LAN 设备。管理员可通过 Unix socket 或已授权的 TCP 接口指定 MAC。设备接口继承源 IP、MAC、成员关系、MITM 设置以及观测到的入口和桥物理接口；浏览器连接的临时源端口、DSCP、SNI、HTTP Host 和进程名不用于新连接。

省略的包字段保持未知。仅在未知字段可能改变结果时，`complete` 才为 false，并列出需要补充的字段。`origin` 可为 `lan`、`local` 或 `daemon`；`daemon` 表示用户态显式目标路由。非零输入 mark 需要特定本机钩子语义，当前接口拒绝该输入；规则生成的 mark 和 must 会正常解释。

## 结果与边界

- `decision.verdict` 区分 `kernel_direct`、`userspace`、`drop`、`unknown`、`analysis` 和 `local_response`。出站名称为 `direct` 本身不表示内核直通。
- 每个步骤分别提供谓词结果 `match` 和执行状态 `status`，包括不匹配、短路、前序终止、出站不可用跳过、上下文不足、其他入口策略及未绑定策略。补充计算的谓词标为 `supplementary`，不会改变实际执行决定。
- 原始文件位置和表达式保留在 `sources` 中；合并规则包含多个来源，共享片段的每次使用有独立步骤 ID。展开条件显示在谓词列表中。
- 域名目标、TLS SNI、HTTP URL/Host 和内核域名—IP 映射是不同输入。提供 SNI 不会使内核 `domain()` 命中。缺少映射时按正常内核规则求值，不扩大捕获范围。
- 仅提供域名不会主动解析；结果列出已有映射候选并要求明确目标 IP。DNS 保留时间不代表即时清理，解释使用当前仍保留、实际驻留内核的证据。
- Host/DNAT 展示候选目标和改写后的路由；随机多目标不消耗随机数，下游保持未确定。节点分析展示当前策略、候选、可用性、优先级和评分，不等待恢复检查。
- DNS 路由插件解释请求策略、上游和响应谓词。`dns.answer_ips`、`dns.upstream`、`dns.rcode` 可补充响应上下文。未提供 DNS 服务器 IP 时只做 DNS 策略分析；提供 IP、端口和完整身份后，还可解释内核捕获及精确缓存键。缓存查询不刷新 LRU、计数器或 TTL。
- HTTP 插件解释声明式作用域、请求头、URL、Map Local、Host 和脚本匹配。脚本及需要正文的改写保留未知执行边界；缺少解释能力的插件也明确标记，依赖它们的下游决定保持未确定。
- 配置代次和观测时间随结果返回。比较复用路由、成员关系、域名与节点状态快照；插件对相同键复用只读观测。不同子系统不承诺全局原子采样时刻，后续网络状态变化仍可能影响真实连接。

## 设备集合与 MITM 管理

```sh
dae client list
dae client show work
dae client device --mac 02:00:00:00:00:10
dae client join work --mac 02:00:00:00:00:10
dae client leave work --self --api http://192.168.1.1:9080
dae client impact work --mac 02:00:00:00:00:10 --joined=false \
  --target 198.51.100.10:443 --source-ip 192.168.1.10
dae client mitm enable --mac 02:00:00:00:00:10
dae client mitm disable --mac 02:00:00:00:00:10
dae client mitm reset --mac 02:00:00:00:00:10
```

`client list/show/device --self` 查看当前设备；加入、退出、影响预览和 MITM 操作选择 `--self` 或 `--mac`。管理接口只修改已定义集合的 MAC 成员，不创建配置集合。MITM reset 清除覆盖值，生效默认值可能依赖源 IP。CLI 使用当前 CA 指纹提交 MITM 操作。

`impact` 不修改设置，列出直接、取反及条件引用的成员关系影响；指定目标后返回同一快照的变更前后解释。前序规则和其他条件仍可能覆盖成员变化的效果。结果也说明现有连接的保留/关闭策略，以及 ipset/nftset 导出名称；外部防火墙规则不在求值范围内。

Web 集合行的 **Routing impact** 按需展开，**Compare a target** 将成员变化带入解释表单。管理员可在 **Manage Devices by MAC** 查看任意 MAC、加入/退出集合、设置/重置 MITM。解释表单的 **Administrator context** 支持通过 JSON 指定身份；高级 JSON 覆盖相应顶层字段。

## HTTP API

[诊断 OpenAPI](../../api/diagnostics.json) 被主 [OpenAPI](../../api/openapi.json) 引用。公开 Go 契约位于 `api/diagnostics.go`，SDK 方法位于 `api/client/diagnostics.go`。

| 接口 | 用途 |
| --- | --- |
| `GET /api/device/context` | 当前设备可继承上下文 |
| `POST /api/device/diagnostics/explain` | 当前设备解释 |
| `POST /api/diagnostics/explain` | 管理员指定上下文解释 |
| `POST /api/device/sets/{name}/impact` | 当前设备成员影响预览 |
| `POST /api/clients/{name}/impact` | 指定 MAC 的成员影响预览 |
| `GET /api/clients`、`GET /api/clients/{name}` | 管理员查看集合及成员 |
| `PUT` / `DELETE /api/clients/{name}/members/{mac}` | 管理员加入/退出集合 |
| `GET /api/devices/{mac}` | 管理员读取保存的设备设置 |
| `PUT` / `DELETE /api/devices/{mac}/mitm` | 管理员设置/清除 MITM 覆盖 |

解释和影响预览的请求正文上限为 64 KiB，执行上下文限时五秒。其他设置接口沿用 1 KiB 限制。POST/PUT/DELETE 需要 `X-Dae-API: 1`；MITM 修改另需 `X-Dae-MITM` 为当前 CA 指纹。设备接口拒绝覆盖已验证身份，不信任转发头。

```json
{
  "kind": "flow",
  "context": {"mac": "02:00:00:00:00:10", "source_ip": "192.168.1.10", "dscp": 0},
  "flow": {"protocol": "tcp", "destination": {"ip": "198.51.100.10", "port": 443}, "sni": "example.com"},
  "compare": {"client_sets": {"work": true}, "bindings": [{"ip": "198.51.100.10", "domains": ["example.com"]}]},
  "detail": "predicates"
}
```

`compare` 还支持 `mitm` 和 `outbounds` 可用性假设，所有假设仅应用于私有副本。`complete` 描述已给上下文下的决定完整性，不是连通性保证。
