# MITM 证书与跨域连接复用

## 设计结论

**无显式 URL 目标改写时，保持原连接的接入目标、路由和 TLS 身份。HTTP authority 只用于业务路由和插件匹配。**

```text
手机连接：原目标 IP:443，SNI grpc.biliapi.net
    ↓ dae 签发 grpc.biliapi.net 的单主机证书
手机发送多个 H2/H3 stream：
    :authority = grpc.biliapi.net
    :authority = api.live.bilibili.com
    ↓ 保留各自的 authority
dae 上游连接：原接入目标、原出站/mark，SNI grpc.biliapi.net
    ↓ dae 验证该接入点的证书链、有效期和主机名
原入口按各 stream 的 authority 分发
```

不同 authority 不触发新目标 DNS 解析，不重选原出站，不改用业务域名验证上游证书。
这是一种连接保持型 HTTP 转发：两侧 TLS 分别终止，HTTP transport 可以重连、并发建连或转换协议，
不承诺两侧 socket 物理上一一对应，但原接入计划在下游连接生命周期内保持不变。

| 层次 | 判断依据 | 作用 |
| --- | --- | --- |
| 新连接捕获 | 插件声明的域名/IP、对应端口、DNS 映射和客户端准入 | 决定是否进入 MITM |
| 下游 TLS | 原接入主机与 ClientHello SNI、本地 CA | 签发单主机证书，无上游网络访问 |
| 已解密请求准入 | authority 格式、scheme、协议和端口 | HTTPS/H2/H3 接受同端口不同主机，无 SAN 门槛 |
| 插件处理 | 改写前的 incoming authority、每插件独立 scope | 未匹配的请求/响应跳过插件，保留 Alt-Svc |
| 普通上游转发 | 原连接接入目标及首次选定的计划 | 固定地址、节点、出站、mark、TLS 身份和连接池 |
| 显式 URL 目标改写或插件主动请求 | 改写后/主动请求的 URL | 重新解析和选路，验证新目标 TLS，block 仍有效 |

未命中捕获条件的 direct 仍在内核直通；域名/IP 与端口的完整捕获条件不被 authority 或插件 scope 外转发扩大。

原目标命中 block 时，普通转发仍失败；能够生成本地响应或改写目标的插件先执行，因此这些请求无需连接被阻止的原目标。
连接建立后，普通请求不因客户端集合或路由规则的变化重新选路；新下游连接使用新规则。
现有策略租约的强制终止仍会关闭上游资源。每次连接池复用前还会检查缓存原计划的租约；
即使首次拨号未成功、没有建立上游资源依赖，发现原计划已被撤销也会结束下游连接，让客户端重新建立连接，而不是持续返回 502。

`domain()` 路由在普通转发中匹配接入域名，**不是逐 stream 的业务 authority 过滤器**。
例如连接到允许的 grpc 入口后，业务 authority 为另一个配置了 domain block 的域名，
不会自动按那个域名重选路由或 block；它仍发给 grpc 入口。若插件明确改写 URL 到该域名，则执行新目标的 block 规则。

## 安全与协议语义

dae 作为 TLS 客户端验证的是**实际接入点**。`*.biliapi.net` 可以证明 `grpc.biliapi.net` 的身份，
但不能独立证明 `api.live.bilibili.com` 的 HTTPS 源站身份。入口有权处理哪些业务，需要客户端与服务部署的信任约定；
相同 IP、相同组织或 scope 匹配本身都不构成这项证明。

[RFC 9113 §9.1.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-9.1.1) 的普通 HTTPS 跨源复用要求新源满足证书身份检查，
并不只是浏览器特有规则。[RFC 9110 §4.3.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.3.4) 也讨论专门配置的替代服务身份验证。
当前方案保留客户端选定的入口，不尝试替客户端重建其完整业务授权模型，也不声称 SAN 未覆盖的业务域名已经独立获得认证。

关键实现边界：

- dae 到真实上游继续执行 TLS 名称、有效期和信任链验证；验证失败由 dae 中止并返回上游错误，不能交给源站替客户端检查。
- 任意 authority 不会令 dae 拨号到另一个网络目标；改变网络目标必须来自插件显式 URL 改写或插件主动 HTTP 请求。
- 插件看到的 `Flow.Host` / `Request.Host` 是请求声明的业务主机，不是独立认证证明；`Flow.Source/Destination` 保留捕获元组。
- HTTPS/H2/H3 跨主机仍须同端口；不支持的 HTTP/1 跨主机、scheme 不一致、端口不一致或非法 authority 仍被本地拒绝。
- 单主机证书使遵循 SAN 复用规则的客户端可能多建几条连接；已经自行采用统一接入身份的客户端可继续复用。

## 实现与职责

```text
ServeConn / ServePacketConn
  ├─ interceptionTLSConfig
  │    Authority.TLSConfig：SNI 与原目标一致
  │      → ServerCertificate：主机格式 / CA 有效期 / 缓存 / 签发
  │      → 证书诊断 → 下游握手
  └─ HandlerForFlow / HTTP3 ConnContext
       ├─ connectionTransport：延迟固定本连接的原计划
       ├─ admitRequestAuthority：格式 / scheme / 协议 / 端口
       ├─ chainsForFlow：按 incoming authority 选择插件链
       └─ 插件执行后的 terminal
            ├─ upstreamRequest：未改写的 URL 网络目标绑定回原入口，保留 Host
            └─ plannedTransport：检查计划生命周期 → 池查找 → 拨号 / TLS / HTTP
```

| 文件 | 职责 |
| --- | --- |
| `ca/authority.go` | CA 文件生成、读取与加载 |
| `ca/tls.go` | ClientHello SNI 与接入身份绑定 |
| `ca/certificate.go` | 唯一签发入口、主机校验、CA 有效期、LRU、签名及本地约束验证 |
| `certificate.go` | 组合 CA TLS 配置、禁用下游 ticket、记录选证书诊断；不重复实现签发策略 |
| `http_authority.go` | 请求准入和按 incoming authority 选择插件链 |
| `http_upstream.go` | 业务 authority 与网络目标分离、原计划固定 |
| `planned_transport.go` | 计划边界检查、池复用、响应租用与清理 |
| `request_trailer.go` | trailer 流式同步、转发时的空正文 framing |

上表路径均相对于 `component/mitm/`。控制平面的路由与租约归 `control/http_route_plan.go`、`control/mitm_lifecycle.go` 所有。

### HTTP URL 与连接目标分离

插件执行期间，`Request.URL` 始终是业务 URL。终端转发比较插件执行后的 URL scheme/host/port 与 incoming authority：

- 只改 path/query、正文、普通头或 HTTP Host：保持原网络目标。
- 改 scheme、URL 主机或端口：使用新目标计划；插件可以独立决定 HTTP Host 是否随 URL 一起修改。
- 等价主机格式（大小写、尾点、默认端口）不被视为目标改变。

普通转发在终端创建浅请求副本和独立 URL，将其 URL host 设为原接入主机/端口，
保留请求 Host。标准 HTTP/H3 transport 用 URL 选择池、拨号和验证 TLS，用 Host 编码 HTTP authority。
副本共享正文和 trailer；插件链的 `next` 边界统一将 `Response.Request` 恢复为插件的业务请求，终端不再重复赋值。
没有插件的响应在返回 ReverseProxy 时完成请求关联。
插件主动请求使用独立的 `Exchange.Client`，按自己的 URL 正常解析、路由及验证，不继承 fronting 绑定。

### 原计划与连接池

`connectionTransport` 延迟选择原计划，首次需要真实转发时选路，成功后在本连接内固定。
计划结构只在选路边界校验一次，缓存只接收有效计划；连接池相信这个内部约定，不重复检查结构。
并发原请求共用一次选择；选路失败、结构无效或取消不缓存。显式改写请求独立选路，然后按完整计划键查找连接池。
各下游连接的池独立，计划键含地址、节点、出站、mark 和策略租约；HTTP transport 再按 URL/TLS 目标区分连接。
重连仍使用原计划，不因 authority 改变而漂移到另一个 DNS 结果或出站。

固定计划通过可选的 `UpstreamPlan.Check` 检查生命周期；控制平面为原目标提供租约检查，并在撤销时终止下游。
检查发生在每次池查找之前，不重新解析或选路。实际拨号成功后的资源依赖仍负责实时传播资源/策略终止。

原 authority 插件链常驻；每连接最多再缓存 32 个 authority 的插件链，更多名称按需创建。
上下游正文取消、池退役、HTTP/3 清理与宿主排空仍由各自资源所有者负责。

### 证书

`ca/authority.go` 负责 CA 文件；`ca/tls.go` 校验原目标/SNI；`ca/certificate.go` 负责单主机签发。
签发缓存最多 256 项 LRU，叶证书有效期不超过 24 小时和 CA 到期时间，签发和缓存命中均检查 CA 有效期。
保留 DER 解析和本地 CA 名称约束验证。证书选择与插件 scope、脚本类型和 `PreserveRoute` 无关。

上游预探测、SAN 镜像、路由证书缓存、singleflight 探测任务和请求侧叶证书快照均已删除。
本地响应/改写不再承担原目标 TLS 探测开销。下游 session ticket 和 QUIC 0-RTT 目前仍关闭。

### 零长度正文与 trailer

入口只安装 trailer 同步 reader，不预读正文或改变 framing。插件处理后，`prepareRequestFraming` 统一选择转发 framing；
已声明 trailer 的请求直接使用流式 framing，
即使 `Content-Length: 0` 且结束帧尚未到达，插件和上游仍可先返回响应。
没有预声明 trailer 的空请求，仅在插件决定转发后读取 EOF，以区分普通空正文与晚到的 trailer，
保留普通 HTTP/1 API 所需的 `Content-Length: 0`；本地响应或插件替换正文不承担这次读取。
因此需要在请求流结束前接收上游响应的发送方，应预声明 trailer。
trailer 只在首次 EOF 同步；插件读完空正文后修改 trailer，后续 transport 再读到 EOF 时不会用原值覆盖它。

## 运行日志

按同一 `connection_id` 观察：

- `mitm_certificate certificate_source=single`：正常的本地单主机签发。
- `mitm_authority_coalesced`：记录原 `connection_host` 与业务 `request_authority`；`plugin_scope=false` 表示跳过插件。
- `upstream_dial`：真实接入 `domain`、目的地址、出站和 mark。
- `mitm_request_end`：状态、正文完整性和 gRPC 结果。

421 原因和日志方法见[MITM 插件排查](mitm-plugins.md#排查偶发-http--grpc-失败)。
