# MITM 插件实现说明

配置与开发 API 见 [MITM Go 插件](../configuration/mitm-plugins.md)。宿主位于 `component/mitm`，Surge 适配器位于 `component/surgemodule/plugin.go`，静态注册与配置加载位于 `cmd/mitm_plugins.go`。

工厂负责准备，宿主一次构造，控制面激活后才启动可选的 `Worker.Run(ctx, client)`。`Plan` 声明 HTTP 范围、目的地址映射和路由贡献，`Wrap` 实现同步中间件。宿主按连接选择实例并构建调用链，统一管理 HTTP、TLS、出站连接和排空。Surge 的模块仍由一个实例内部处理，以保持每方向首个匹配脚本的语义。

## 消融结果

| 删除的机制 | 当前实现与理由 |
| --- | --- |
| Surge 独立 HTTP/TLS 服务、反向代理和 CA 选项 | 通用宿主提供唯一传输入口；Surge 只负责 HTTP 内容处理 |
| 顶层 `surge` 配置兼容分支、重复的控制面 Surge 指针与加载器包装 | 统一为 `mitm` 下的具名实例；证书和客户端选择属于宿主 |
| `Host.Add`、getter 隐式封存、计划深拷贝 | `Load` / `New` 一次构造，只读计划的所有权契约明确 |
| 每请求重建中间件、跟踪重复或延迟 `next` 的原子状态 | 每连接构造一次，静态 Go 插件遵守普通同步中间件契约 |
| 准备阶段后台客户端的运行时门禁 | 工厂只收到准备客户端，运行客户端在 `Run` 时交付 |
| 重复 store 路径拒绝 | 空路径隔离；相同显式路径复用已有并发安全存储，允许有意共享 |
| 两套 hostname 通配匹配器 | Surge 与宿主共用 `mitm.Scope.Match` |
| 控制面再次翻译 Surge 模块路由 | 由 Surge 的 `Plan` 统一导出 |

保留配置输入校验、正文大小和执行预算、响应正文所有权、CA/authority 检查及有界排空。这些约束针对真实输入与资源生命周期。保留 HTTP/1 listener 关闭与活动连接分离、HTTP/2 GOAWAY，以及 UDP ownership，因为简化它们会破坏正在处理的请求或重载中的连接。

默认排空预算为 5 秒，超时后取消请求并关闭连接。Go 插件必须响应取消；宿主不能强行终止 goroutine。后台队列、缓存、业务预算、并发和重试由插件实现，没有预置任务框架、动态 Go 库加载或 DNS hook。

协议验证覆盖 HTTP/1.1、TLS HTTP/2、SNI 与请求 authority、模块作用域、脚本和正文处理、独立/共享存储，以及在途请求排空。路由验证覆盖普通策略、DNAT 顺序、回退、原始身份和 UDP 回包隔离；内核测试直接验证捕获标志和重载 ownership。

## 规模与验证记录

与本轮消融前的实现快照比较，以下目录的 Go 生产代码由 28,209 行降至 27,430 行，净减少 779 行；统计包含注释和空行，排除测试及 BPF 生成文件。该数字用于描述维护规模，不代表性能提升。

| 目录 | 消融前 | 消融后 |
| --- | ---: | ---: |
| `component/mitm` | 719 | 671 |
| `component/surgemodule` | 4,410 | 4,064 |
| `component/routing` | 1,186 | 1,160 |
| `config` | 2,525 | 2,487 |
| `control` | 14,915 | 14,652 |
| `cmd` | 4,454 | 4,396 |

验证环境为仓库 `nix-shell`、Go 1.27.1。执行 `make test`、`make`、`make ebpf-lint`、隔离 maps 的 root `make ebpf-test`，以及 MITM、Surge、routing、config、control、cmd 包的 `go test -race`。在清理测试夹具和恢复相邻 MAC 匹配分支后完成验证。
