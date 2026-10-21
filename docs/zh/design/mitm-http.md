# MITM HTTP 转发与证书身份

## 连接目标与身份边界

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
- HTTPS/H2/H3 跨主机仍须同端口；不支持的 HTTP/1 跨主机、URL scheme 不一致、端口不一致或非法 authority 均被本地拒绝。
- 单主机证书使遵循 SAN 复用规则的客户端可能多建几条连接；已经自行采用统一接入身份的客户端可继续复用。

### 请求 scheme

HTTP/2 入站使用固定版本的 Go 协议实现，适配层将原始 `:scheme` 保留在 `Request.URL.Scheme`。
HTTP/2、HTTP/3 和 HTTP/1 absolute-form 的显式 scheme 都参与准入检查；
与接入连接不一致时，在执行插件或选择上游前返回 421，日志记录 `scheme_mismatch`。
因此 TLS HTTP/2 中的 `:scheme=http` 不会被归一化为 HTTPS。
`Request.TLS` 表示连接状态，不用于推断伪首部。

authority 的默认端口按通过准入的 scheme 解释，HTTPS 为 443；显式端口必须与接入端口一致。
HTTP/1 origin-form 按接入连接判断 scheme。h2c 不受支持。
协议源码来源、维护差异和更新方式见 [HTTP/2 适配说明](../../../internal/http2/README.md)。

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
| `../ca/authority.go` | CA 文件生成、读取与加载 |
| `../ca/tls.go` | ClientHello SNI 与接入身份绑定 |
| `../ca/certificate.go` | 唯一签发入口、主机校验、CA 有效期、LRU、签名及本地约束验证 |
| `certificate.go` | 组合 CA TLS 配置、禁用下游 ticket、记录选证书诊断；不重复实现签发策略 |
| `http_authority.go` | 请求准入和按 incoming authority 选择插件链 |
| `http_upstream.go` | 业务 authority 与网络目标分离、原计划固定 |
| `planned_transport.go` | 计划边界检查、池复用、响应租用与清理 |
| `request_trailer.go` | trailer 流式同步、转发时的空正文 framing |
| `http_failure.go` | 上游未处理请求的拒绝信号和 HTTP/3 建连失败传播 |

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

### 双栈连接选择

显式目标改写、插件主动请求和资源下载共用 `pkg/outbound/happyeyeballs` 的地址发现与连接竞速。
A、AAAA 独立查询，优先 IPv6；A 先返回时短暂等待 AAAA，任一地址族的慢查询不阻塞另一族建连。
后续地址在实际尝试前按地址族交错选取，及时纳入较晚到达的 DNS 答案。
解析等待和连接尝试间隔采用 [RFC 8305](https://www.rfc-editor.org/rfc/rfc8305.html) 的默认建议，不增加配置项。

每个候选地址独立执行路由和租约检查；显式地址族限制和 block 仍有效。
竞速只建立连接，不并发发送 HTTP 请求。候选路由已有连接池时先尝试复用，只有底层 transport 确认无法复用且正文未发送时，
才重新发现候选并建连；本次已确认未命中的池不再被当作可复用结果。取得连接后，仍保留底层 transport 原有的安全重试行为。
TCP 连接或 QUIC 握手成功后，连接由实际所属池保存，共享拨号的所有等待者获得同一个目标池，随后各自发送请求。
交接期间保留该池引用；即使缓存淘汰后出现同键的新池，也继续使用原池，不跨池移交连接。
取消的尝试退出后才释放本次选择，未采用的连接关闭。
原接入目标的固定计划不参与重新解析或跨地址竞速。

底层 direct TCP 域名拨号也复用该调度，保留 socket 的 mark、绑定接口和显式地址族。
普通 UDP 没有连接握手，不用 socket 创建成功判定可达性；DNS 插件在应答层选择成功地址，HTTP/3 在 QUIC 握手层选择。

### 证书

`../ca/authority.go` 负责 CA 文件；`../ca/tls.go` 校验原目标/SNI；`../ca/certificate.go` 负责单主机签发。
签发缓存最多 256 项 LRU，叶证书有效期不超过 24 小时和 CA 到期时间，签发和缓存命中均检查 CA 有效期。
保留 DER 解析和本地 CA 名称约束验证。证书选择与插件 scope、脚本类型和 `PreserveRoute` 无关。

下游签发只依赖本地 CA，不访问原目标；本地响应和目标改写无需原目标 TLS 探测。
下游 session ticket 和 QUIC 0-RTT 关闭。

### 零长度正文与 trailer

入口只安装 trailer 同步 reader，不预读正文或改变 framing。插件处理后，`prepareRequestFraming` 统一选择转发 framing；
已声明 trailer 的请求直接使用流式 framing，
即使 `Content-Length: 0` 且结束帧尚未到达，插件和上游仍可先返回响应。
没有预声明 trailer 的零长度请求，在转发时查询协议层的结束状态或插件的完整内存快照，不等待结束帧：
已确认正常结束且没有 trailer 时保留 `Content-Length: 0`；尚未结束时立即流式转发，允许晚到的 trailer。
转为 HTTP/1 时，后者使用 chunked；只接受固定长度的上游仍可能拒绝这类未结束请求。
HTTP/3 的 FIN 尚未到达时也视为未结束，不通过等待或超时猜测请求是否完成。

HTTP/2 和 HTTP/3 的有效 trailer 会在正常 EOF 交付，包括未预声明的字段。
trailer 只在首次 EOF（读取或非阻塞确认）同步；插件修改后的值不会被后续 EOF 覆盖。
非零固定长度请求如果未声明 trailer，转为 HTTP/1 后无法追加晚到的 trailer；发送方需要在请求头声明这些字段。
上游自身对 trailer 的支持范围仍由其 HTTP 实现决定。

### 网络等待与失败传播

普通 HTTP 转发不额外限制上游响应头等待时长或完整上传时长；请求取消负责结束活动交换。
接入首部、TLS/QUIC 握手、连接空闲和 HTTP/2 存活探测仍有各自边界。
HTTP/1 上传被关闭或请求结束时，中断尚未完成的正文读取，避免清理阶段等待剩余上传而阻塞提前响应。
上游连接关闭也会中断该次尝试正在读取的上传，使响应头读取失败能够及时返回；尚未读取的正文保留给安全重试。
仅收到响应头不会中断双向流式上传；完整上传仍可复用连接。
HTTP Upgrade 的两端保留半关闭能力，一侧 EOF 后仍允许另一侧继续发送尾部数据。
底层出站不支持半关闭时，仍受该出站的能力限制。

下游 QUIC 的 PING 在本地终止；上游独立保活，避免慢响应或暂时无数据的活动流被空闲超时打断。
HTTP/3 连接的所有请求流都结束收发后，空闲 90 秒回收；保活包不延长该回收期限。
已准入但未命中插件 scope 的 HTTP/2 authority 使用相同的流式转发规则。
Surge 的网络正文读取不消耗脚本执行预算，也不占用实例执行名额；
正文读取完成并重新取得名额后，解码、改写和脚本执行才开始计时。
正文大小、共享内存、并发执行和累计正则预算继续限制资源使用。

转发只为流式请求保留最多 64 KiB 的重试副本，已有完整插件快照可以共享。
HTTP/2 或 HTTP/3 transport 确认请求尚未处理且需要重试时，如果副本因超限、内存不足或上传未完成而不可用，
将该决定传给下游：HTTP/2 使用 `REFUSED_STREAM`，HTTP/3 使用 `H3_REQUEST_REJECTED`。
HTTP/3 transport 用尽内部重试后，远端返回的 `H3_REQUEST_REJECTED` 流错误也保留该信号。
客户端能否重发取决于它是否保留正文及自己的重试策略；HTTP/1 没有等价的拒绝码，只能中断连接。
无法确认上游是否已经处理的错误不会被转换为安全重试信号，以免重复提交。

下游 QUIC 握手在本地完成。上游 packet 拨号或 QUIC/TLS 握手失败时，关闭该下游 QUIC 连接，
使客户端收到传输失败，而非一个掩盖上游建连失败的 HTTP 502。
客户端可以据此执行自己的协议回退；dae 不在后台自动把 UDP 路由切换成 TCP。
已建立连接上的普通 HTTP 错误和流级错误仍按各自请求处理，不扩大为连接故障。

## 运行日志

按同一 `connection_id` 观察：

- `mitm_certificate certificate_source=single`：正常的本地单主机签发。
- `mitm_authority_coalesced`：记录原 `connection_host` 与业务 `request_authority`；`plugin_scope=false` 表示跳过插件。
- `upstream_dial`：真实接入 `domain`、目的地址、出站和 mark。
- `mitm_request_end`：状态、正文完整性和 gRPC 结果。

421 原因和日志方法见[MITM 插件排查](../configuration/mitm-plugins.md#排查偶发-http--grpc-失败)。
