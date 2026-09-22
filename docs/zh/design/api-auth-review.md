# API 鉴权与页面状态的 Review / 消融记录

## 范围与方法

本次检查覆盖 `api_key` 认证、Cookie 会话、无密钥 LAN 管理和前端访问状态。

先运行基线测试，再使用 Go `-overlay` 对 review 前的代码逐项取消检查；每个变体只改变一个检查，运行独立测试进程。LAN 记录有效期和邻居校验使用 root 权限下的 `TestAPIClientIdentityIntegration`，在隔离 network namespace 内执行真实 eBPF 程序、路由和 ARP/NDP 查询。

判断依据包括响应状态、受保护数据是否泄露、selector 是否被修改和 Cookie 行为，不仅检查函数调用次数。测试通过的分支还需检查调用前提，不能仅凭覆盖不足认定其无用。

## Review 发现与处理

### 前端提前推断管理员状态

旧登录流程在读取 Selectors 前直接执行 `setAccess("api_key")`。在 Chromium 中令登录返回 `204`、随后 Selectors 返回 `503`，页面仍显示 Administrator、隐藏登录框并解锁空面板。该问题是展示状态错误，后端权限校验仍然有效。

现在仅在受保护的 Selectors 请求成功后，使用响应中的 `auth_mode` 更新页面。移除缺少 `auth_mode` 时默认使用 `api_key` 的兜底。登录后的查询失败必须报告错误；首次访客加载和退出后的查询通过显式 `allowGuest` 允许未登录状态。

同时统一 `401/403` 的访问状态清理，将设备、证书加载及 MITM 渲染拆成具名函数，减少刷新函数内嵌的 Promise 回调和重复状态判断。

### 鉴权重复决策与不可达分支

原实现先计算 `adminAuthMode`，再按模式鉴权，成功响应又计算一次模式。现在 `auth.go` 中的 `requireAdmin` 一次返回模式与授权结果，顺序为 Unix、无 key 的 LAN、配置 key 后的会话/Bearer。

空 key 已在入口选择 LAN 路径，`requireAPIKey` 和 `validSession` 内重复的空 key 拒绝分支不可达，已删除。PUT 登录与 DELETE 退出分别注册独立处理函数，Cookie 公共属性由一个构造函数维护。

### 用无效依赖模拟身份拒绝

原测试使用缺失的 `ResolveClient` 模拟非 LAN 请求，导致生产代码增加逐请求 nil 检查。实际控制面始终提供 resolver；这是必需依赖。

测试改为显式返回身份解析错误，删除 nil 兜底并记录依赖约定。真实请求的端点解析、LAN 证据和邻居校验错误仍正常返回 HTTP 错误。测试另补充了“有效 Cookie 不能自行续签”和“Unix 管理权限不能代替配置的 key 签发浏览器会话”的检查。

## 消融结果

| 取消的检查 | 实测结果 | 处理 |
| --- | --- | --- |
| `requireAPIKey` 的空 key 拒绝 | API 测试通过；调用方已分流 | 删除 |
| `validSession` 的空 key 拒绝 | API 测试通过；仅配置 key 的路径调用 | 删除 |
| `ResolveClient == nil` | 原夹具触发 panic；改用显式拒绝 resolver 后测试通过 | 删除兜底，修正夹具 |
| LAN 鉴权失败后的返回 | 拒绝响应中出现受保护状态，selector 修改继续执行 | 保留授权检查 |
| 会话 HMAC 验证 | 篡改 Cookie、旧 key 会话及其他 listener 会话被接受 | 保留 |
| 会话过期时间 | 过期 Cookie 返回 `200` | 保留 |
| 会话 Host/端口签名绑定 | 其他 listener 的会话返回 `200` | 保留 |
| 显式 Authorization 优先级 | 错误 key 被有效 Cookie 掩盖，返回 `200` | 保留 |
| 同源检查 | 跨源请求读取状态、执行设备修改 | 保留 |
| `X-Dae-API` 修改标记 | 缺少标记仍可签发、清除会话 | 保留 |
| LAN 观察记录 30 秒有效期 | 过期入口记录被接受 | 保留 |
| 直连路由与邻居验证 | LAN 后方经路由转发的客户端获得管理权限 | 保留 |

其中 nil 分支做了两次消融：第一次定位到测试夹具问题，第二次在符合依赖约定的夹具下验证删除结果。其余变体以取消检查后出现的行为差异为依据，没有把编译错误当作有效消融结果。

## 回归验证

- Go API、客户端契约、静态资源测试和 race 检查。
- 真实内核身份测试：VLAN/bridge、bond、IPv4/IPv6、WAN、间接路由、MAC 不匹配、过期记录及重载清理；检查 API 包继续使用内核 direct。
- Chromium：LAN 免登录、密钥登录/退出、Cookie 保持、节点选择/重置、手机布局。
- Chromium 故障注入：登录后 Selectors `503`、恢复刷新、会话失效、登录请求不保存 Cookie；验证错误反馈及页面锁定状态。

主要回归命令：

```sh
go test -race ./internal/apiserver ./api/... ./internal/webui
go test ./control -run 'Test(GlobalAPI|DeviceAPI|PublicClientWithTCPAndUnixAPI|StatusAdministrationBoundary|CertificateAPI|SelectorAPI|HostOnlyAPI)' -count=1
go test -c -o /tmp/opencode/dae-api-reviewed-control.test ./control
sudo /tmp/opencode/dae-api-reviewed-control.test -test.run '^TestAPIClientIdentityIntegration$' -test.v
make web-assets
```
