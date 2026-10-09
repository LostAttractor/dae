# AGENTS.md

## 代码与文档

- 文档只描述当前用法、行为和设计，不写工作记录或实验总结。
- 未发布功能直接修改，不做旧版本兼容、迁移设计或迁移文档。
- 不得擅自引入第三方脚本、模块等外部测试 blob；测试使用自编写的最小夹具。
- Surge 模块兼容性文档只记录 API 支持范围、行为差异和限制，不记录外部脚本的测试过程或验证结果。

## 构建

- 当前通过 direnv 加载 Go、Clang/LLVM；直接使用现有工具链即可，不要求 `nix-shell`。
- `make` 编译 Go 和 eBPF，产物为 `./dae`。其他目标及变量见 Makefile；`make ebpf-test` 需要 `sudo`。
- 缺内核头文件时执行 `git submodule update --init --recursive`；`make ebpf` 会自动初始化缺失的 submodule。

## eBPF direct 是核心功能

- 未命中显式捕获条件的 `direct` 流量必须内核直通；用户态 direct 拨号会改变性能、源地址和连接生命周期，不能替代。
- MITM 严格按插件声明的域名/IP 和对应端口捕获，Host/DNAT 保留完整过滤条件；不得为获取 SNI/Host 或补偿 DNS 映射而扩大为全 TCP/UDP 或仅按端口捕获。
- 内核 `domain()` 依赖已有域名—IP 映射；缺失时沿用普通 routing 语义并说明边界，不加全流量用户态兜底。
- 修改捕获或路由时，测试实际内核捕获决定：SSH（如 `10.0.0.1:22`）、无关 HTTPS、缺少 DNS 映射的连接仍须直通；目标捕获、原出站、mark、must 和 API 直通行为须保留。仅检查出站名为 `direct` 不够。
