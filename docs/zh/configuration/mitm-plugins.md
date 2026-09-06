# MITM Go 插件

`mitm` 统一管理证书、客户端开关、HTTP/TLS 转发和插件生命周期。插件静态编译进 dae，通过具名子段创建实例；当前内置 `surge`，负责 sgmodule 与 QuickJS 兼容。

```text
mitm {
  enabled: true
  ca_cert: 'mitm-ca.pem'
  ca_key: 'mitm-ca.key'
  client_source_address: '02:00:00:00:00:50'

  surge {
    module { personal: 'file:modules/personal.sgmodule' }
    store: 'personal-store.json'
    script_timeout: 5s
  }
  work {
    type: surge
    module { work: 'file:modules/work.sgmodule' }
    store: 'work-store.json'
  }
}
```

子段名是实例 ID，也是默认的类型。`type` 用于多个同类实例。空 `store` 为实例独立的内存存储；显式指定相同路径则共享持久数据，读写由同一个存储对象串行执行。实例默认启用，可用 `enabled: false` 关闭；宿主总开关默认关闭。未知的活动类型、重复 ID 或未知插件字段会报错。显式关闭的插件不加载。

`ca_cert`、`ca_key`、`client_source_address` 放在宿主；module、store 和 JS 限制放在 Surge 实例中。仅贡献 Host 或路由的实例无需 CA；HTTP scope 要求 CA。客户端开关只控制 HTTP/MITM，不撤销 Host 拨号覆盖。相对路径继续以 `DAE_LOCATION_CACHE` 为基准；新实例缓存位于 `mitm/<ID>/surge-cache`。

仅支持 `mitm` 下的实例配置；旧顶层 `surge {}` 不再接受。`dae surge configure` 输出的 module 段可放入所选 Surge 实例。

插件按声明顺序执行，请求 A → B → 上游，响应 B → A。每个插件的 scope 独立判断，使用连接最初的主机与端口；URL/Host 改写不会激活另一个 scope。一个 Surge 实例内部仍保持原有模块顺序及“每个方向只运行第一个匹配脚本”的行为。

为获取未经过 dae DNS 的 SNI/Host，活跃 HTTP scope 会保守捕获 TCP。这会增加进入用户态的流量；实际解密仍受 scope 和客户端开关限制。HTTP/3 不解密。

开发 Go 插件时，在编译入口导入插件包并调用 `mitm.Register(type, factory)`。工厂接收原始配置 AST、实例 ID、日志和准备阶段 HTTP 客户端，返回实现以下接口的对象：

```go
type Plugin interface {
    Plan() mitm.Plan
    Wrap(mitm.Flow, mitm.Handler) mitm.Handler
}
// 可选接口
type Worker interface { Run(context.Context, *http.Client) error }
type Closer interface { Close() error }
```

`Plan.Scopes` 声明 HTTP 处理范围，`Plan.Destinations` 声明拨号覆盖，`EarlyRoutes` / `Routes` 声明兼容路由。目的地址规则的 Filter 复用 routing AST；To 是目标 IP 列表，Proxy 表示是否也适用于代理。宿主在 `mitm.Load` 或 `mitm.New` 中一次构造：读取每个实例的计划，聚合后保持只读，调用方不得再修改计划或实例列表。具体类型见 [plugin.go](../../../component/mitm/plugin.go)，现有适配器见 [Surge 插件](../../../component/surgemodule/plugin.go)。

工厂只准备资源；`Run` 在控制面激活后调用。后台任务使用 `Run` 的 HTTP client 参数，请求携带 worker context 和插件自己的超时；该客户端不继承模块下载的 30 秒限制，也不继承被拦截连接的目标。`Services.HTTPClient` 仅用于准备阶段下载，不能留给后台任务。

`Wrap` 返回同步 HTTP 中间件。宿主按连接构造中间件链，插件在请求处理时同步调用 `next`，也可直接返回本地响应。返回响应时把正文所有权交给调用方；取得下游响应后遇到错误，插件必须关闭正文。后台任务应复制所需的 Cookie、文本等数据，不能保留 Exchange、请求正文或 ResponseController。业务插件自行实现有界队列、去重、缓存、并发和 API 重试，不在 HTTP 回调内无限等待。

重载时取消旧 worker，HTTP/1 停止 keep-alive，HTTP/2 发起 GOAWAY，并允许已开始的请求排空。默认预算 5 秒，之后取消请求、关闭连接并报告超时；Go 插件必须响应 context 取消。无法强行终止不合作的 Go goroutine。只有执行退出后才关闭插件资源。普通 TCP 字节中继及 UDP association 使用各自连接资源。

状态 API 增加 `mitm_plugins` 实例列表；原 Surge 模块状态保留，并增加 `instance`。不会将插件配置放进状态接口。当前没有内置 bilijump Go 插件，也没有统一的后台任务队列；这些能力由业务插件通过上述接口实现。

大模型识别插件可在 `Wrap` 中提取已解密请求的 Cookie 和视频标识，将必要数据复制到自己的队列，立即返回当前结果；`Run` 用独立预算调用模型并更新缓存。队列、去重、缓存有效期和首轮策略由业务插件决定。这样一个模型任务不会阻塞全部弹幕请求；需要严格首轮过滤时，也应只让同一视频请求等待一个有上限的任务。实际 bilijump 识别逻辑需由插件实现。
