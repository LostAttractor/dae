# 项目组织结构

| 目录 | 职责 |
| --- | --- |
| `cmd` | 命令、启动、重载和生成的插件表 |
| `config` | 用户配置解析与校验 |
| `control` | 控制面、TCP/UDP 转发、内核资源交接；eBPF 位于 `kern` |
| `component/routing`、`outbound` | 路由规则、目的地址计划、出站选择 |
| `component/network`、`sniffing` | 接口管理与协议嗅探 |
| `component/mitm` | HTTP/TLS、插件生命周期；`plugin` 是公开 API，`surge` 实现 sgmodule，`ca` 管理证书 |
| `component/api` | 管理 API 和页面，通过接口调用控制面 |
| `component/dns`、`settings`、`clientset` | DNS、设置持久化、客户端集合 |
| `pkg`、`common`、`trace`、`third_party` | 基础代码、追踪工具和固定版本依赖 |

MITM 是可选组件，业务插件的实现、测试和文档在独立仓库维护。
[mitm_plugins.cfg](../../../mitm_plugins.cfg) 经 `make` 生成
`cmd/mitm_plugins_generated.go`，Setup 表随启动和重载传递。
插件依赖[公开 API](../../../component/mitm/plugin/README.md)，宿主持有传输资源。

原生 [rules / DNAT](../configuration/destination-rules.md) 与 Surge `[Host]`
共用拨号目标重写，独立于 DNS 应答处理。
