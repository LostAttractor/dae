# MITM 插件配置

`mitm` 管理证书、客户端开关和插件实例。默认构建包含 `surge`，支持 sgmodule 与 QuickJS；其他插件在独立仓库维护，通过 [mitm_plugins.cfg](../../../mitm_plugins.cfg) 加入 dae 编译。

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

`dae mitm surge configure` 输出的 module 段可放入所选 Surge 实例。

插件按声明顺序执行，请求 A → B → 上游，响应 B → A。每个插件的 scope 独立判断，使用连接最初的主机与端口；URL/Host 改写不会激活另一个 scope。一个 Surge 实例内部仍保持原有模块顺序及“每个方向只运行第一个匹配脚本”的行为。

插件的每个 `Plan.Scopes` 项同时保存捕获范围与路由属性；默认在 HTTP 处理后确定路由，仅保持目标且始终转发的纯检查可声明 `PreserveRoute: true`。重叠范围中的请求处理优先。Surge 自动将含脚本、URL Rewrite 或 Map Local 的模块归入请求路由。请求型连接先通过 scope 与客户端准入，再执行 HTTP 规则，最后按有效目标决定出站、mark、must 和 block。原目标的 block 不会阻止已准入请求改写到允许的目标；新目标的 block 仍拒绝。纯检查保留已有内核路由；未准入连接执行普通路由。转发与脚本子请求共用按目标、节点、出站及 mark 隔离的连接池，流量统计归属实际上游连接。

**eBPF direct 是 dae 的核心行为。** 宿主按 HTTP scope 中的正向域名/IP 和各自端口生成 TCP/UDP 捕获条件，只有候选连接才进入用户态；无关 SSH、HTTPS 等 direct 流量仍在内核直通。不能用全 TCP/UDP 或仅按端口捕获来补偿缺少域名信息。

域名条件复用普通 `domain()` 的 DNS 域名—IP 映射，字面 IP 条件无需 DNS。缺少映射时，原本在内核直连的连接不会仅因后续可能出现匹配的 SNI/Host 而被捕获；已因其他规则进入用户态的连接仍可按实际主机名处理。共享 IP 和正向通配符可能带入额外候选，最终仍按原主机名、端口、scope 排除顺序和客户端开关决定是否执行插件。一个 scope 的排除项不会取消另一个 scope 的允许项。

客户端使用的解析结果与 dae 当前保存的域名—IP 映射可能不同步。例如，应用可能在 DNS TTL 到期后继续使用缓存地址；dae 完整停止后重启会丢失内存中的映射；设备切换网络后也可能沿用原网络的解析结果。这些情况下，若 dae 尚未获得或重新建立连接所用 IP 的有效域名映射，相关的正向域名捕获规则就无法命中。dae 内部重载会继承仍有效的域名映射。

HTTP/3 使用现有 CA、客户端开关与插件 scope，无需新增配置。仅在完整 QUIC ClientHello 声明 `h3` 后解密；客户端请求与上游都使用 HTTP/3，插件主动 HTTP 请求按最终目标重新匹配 TCP 路由并使用 HTTP/1 或 HTTP/2。支持同一源/目标/域名下的多连接和重连，不支持跨地址迁移、跨主机复用或 0-RTT。仅保留上游提供的同主机、同端口 H3 Alt-Svc 广告，跨主机或跨端口广告会移除。

被明确捕获后使用 `direct` 出站的连接依赖 dae 转发，停止 dae 会使它断开；这与未被捕获的 eBPF direct 不同。

重载会取消旧插件的后台任务并排空已开始的 HTTP 请求，默认预算 5 秒，超时后取消请求并关闭连接。后台识别、等待预算、缓存等行为由具体插件定义；宿主没有通用的任务队列，也不能事后补写已返回的响应。

`dae mitm status` 汇总所有已启用实例，`--verbose`（`-v`）进一步聚合各插件的完整 status 输出，包括 Surge 模块表和 Bilijump 任务、模型、云缓存及错误详情。整次命令只查询 daemon 一次，`--instance ID` 可筛选实例。没有自定义 status 的插件展示完整 JSON 报告；某插件的状态渲染失败时保留原始报告并继续显示其他插件，命令最终返回错误。`--json` 直接输出完整插件报告，与 `-v` 同用时仍只输出 JSON。

`dae mitm surge status` 查看 Surge 模块状态；外部插件可注册自己的命令，例如 `dae mitm bilijump status --instance personal`。没有自定义 status 的插件也有通用 status 命令。命令通过 Unix socket 查询 daemon，无需开启 `api_port`；旧的顶层 `dae surge` 命令已移除。状态字段见[页面/API](api.md)。添加单个或多个插件见[构建说明](../../en/user-guide/build-by-yourself.md#external-mitm-plugins)，编写插件见[插件 API](../../../component/mitm/plugin/README.md)。
