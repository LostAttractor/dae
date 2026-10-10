# Surge 脚本兼容边界

`surge` 插件以运行 Surge script 为目标，重点是 MITM 中的 `http-request` / `http-response` 脚本。模块解析、重写、存储和 HTTP 客户端为脚本执行提供配套能力。用法见[配置指南](../configuration/surge-module.md)，具体 API 与差异见[支持范围](../configuration/surge-module-support.md)。

## 执行职责

- 插件解析 sgmodule，在匹配的请求/响应上通过编译时选定的 QuickJS 或 Node.js 后端执行脚本，并应用脚本结果。两种后端共享宿主 API 和出站客户端；每个二进制只包含一种后端。
- HTTP/TLS、连接生命周期和实际选路由 dae 宿主负责；脚本 HTTP 请求使用宿主提供的路由客户端。
- DNS 脚本通过 Host 引用执行；cron/generic 通过 daemon 的后台任务执行器运行，与 HTTP 脚本共享实例存储和执行名额。
- 运行时统一处理完成协议、超时、取消、正文预算和通知。脚本正常调用 `$done()` 表示执行完成，不保证业务操作成功。

## MITM 与内核直通

MITM 只捕获模块声明的域名/IP 和对应端口。脚本匹配、Host/DNAT 和重写均受该范围约束；不会为获得 SNI/Host 而扩大捕获。

未命中捕获条件的 direct 流量仍在内核直通。缺少 DNS 域名映射时沿用普通 routing，不增加用户态兜底。已经捕获的请求选择 direct，以及脚本主动发起的 HTTP 直连，均由用户态拨号，不能替代内核直通。

## rule 与 event

当前不支持这两类脚本，解析时警告并忽略：

- **rule** 是 Surge 规则链中的同步条件，以 `$done({matched: boolean})` 决定是否匹配。dae 当前的静态 `[Rule]` 子集转换为原生 routing；任意 JS 无法按同一方式进入内核规则链，也不能用后台任务或全流量捕获代替。
- **event** 依赖宿主的启动、重载、网络变化和通知事件。后台执行器只能提供执行能力，插件激活也不等于 Surge 的启动事件，因此不能直接套用 cron/generic 的触发方式。

参见 Surge 官方的 [rule](https://manual.nssurge.com/scripting/rule.html) 与 [event](https://manual.nssurge.com/scripting/event.html) 契约。

## API 边界

API 兼容以脚本可观察的输入、返回值和副作用为准。新增能力应复用宿主的路由、资源限制和取消机制，保持实例隔离。

`$httpClient.policy` 通过宿主选择已加载的出站组，只作用于脚本主动请求；目的地址规则、客户端身份和 mark 仍保留，不改变捕获规则或原连接路由。脚本专用组用 `http_policies` 声明依赖。基础 fetch 复用同一客户端、资源限制和逐请求取消机制。`policy-descriptor`、`insecure`、`$network`、`$surge`、`$httpAPI`、GeoIP/ASN 和 crypto 等边界见支持范围。

`$environment` 报告 dae 宿主信息；通知写日志并保留在插件状态中。插件不模拟 Surge 的应用界面或平台系统集成，也不以函数同名代替实际语义。
