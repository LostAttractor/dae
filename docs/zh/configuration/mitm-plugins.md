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

为获取未经过 dae DNS 的 SNI/Host，活跃 HTTP scope 会保守捕获 TCP。这会增加进入用户态的流量；实际解密仍受 scope 和客户端开关限制。HTTP/3 不解密。

重载会取消旧插件的后台任务并排空已开始的 HTTP 请求，默认预算 5 秒，超时后取消请求并关闭连接。后台识别、等待预算、缓存等行为由具体插件定义；宿主没有通用的任务队列，也不能事后补写已返回的响应。

`dae mitm status` 汇总所有已启用实例，`--verbose`（`-v`）进一步聚合各插件的完整 status 输出，包括 Surge 模块表和 Bilijump 任务、模型、云缓存及错误详情。整次命令只查询 daemon 一次，`--instance ID` 可筛选实例。没有自定义 status 的插件展示完整 JSON 报告；某插件的状态渲染失败时保留原始报告并继续显示其他插件，命令最终返回错误。`--json` 直接输出完整插件报告，与 `-v` 同用时仍只输出 JSON。

`dae mitm surge status` 查看 Surge 模块状态；外部插件可注册自己的命令，例如 `dae mitm bilijump status --instance personal`。没有自定义 status 的插件也有通用 status 命令。命令通过 Unix socket 查询 daemon，无需开启 `api_port`；旧的顶层 `dae surge` 命令已移除。状态字段见[页面/API](api.md)。添加单个或多个插件见[构建说明](../../en/user-guide/build-by-yourself.md#external-mitm-plugins)，编写插件见[插件 API](../../../component/mitm/plugin/README.md)。
