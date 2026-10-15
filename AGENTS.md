# AGENTS.md

## 开发流程

1. 添加新功能前，查清其与现有功能的关联，分清基础能力与上层功能
2. 基于第一性原理，自顶向下重新设计架构，并遵守下述设计约束
3. 用户输入或架构设计有任何模糊之处时，持续追问用户，直到澄清

- 未发布功能直接修改，不做旧版兼容或迁移设计、文档
- 可配置项务必提供合适的默认值；不提供无实际价值的配置项
- 对尚未 push/merge 的提交，不具有 revert 必要的修正或改进应 amend 到原提交，而不是创建新提交，保持提交历史干净
- metrics 优先复用现有 Prometheus 指标及底层统计；`status`、`--recent` 等展示共用数据源，避免重复计数和口径不一致
- 文档只写当前用法、行为和设计，不写工作记录或实验总结；Surge 模块兼容性文档仅写 API 支持范围、行为差异和限制，不写外部脚本测试过程或结果
- `docs/*/design` 按项目能力和架构组织，记录职责、状态模型、约束与设计取舍，不以 review、修复历史或消融过程命名和组织；测试操作与性能测量方法放在开发文档
- 自有 Go 代码共用根 `go.mod`，修改插件 API 时同时适配 `plugins/` 下全部自有插件；外部插件配置见 `plugins.cfg` / `go.work`
- 测试使用自编写的最小夹具，不得擅自引入第三方脚本、模块等外部测试 blob
- 在提交时使用 `Assisted-By` 标记当前的 Agent 工具名、模型名与思考等级，如 `Codex (OpenAI GPT-6 Astra / xhigh)`

## 构建

- 使用 `direnv` 或 `nix-shell` 获得开发环境
- `make` 编译 Go 和 eBPF，生成 `./dae`；其他目标及变量见 Makefile。`make ebpf-test` 需要 `sudo`。
- 在本地 `plugins.cfg` 中取消示例内可选插件的注释，运行 `make test` 验证全部自有插件的编译选择；`SURGE_RUNTIME=nodejs` 验证无 CGO 的 Node 后端。`make client-test` 检查客户端依赖边界。
- 修改 `pkg/config_parser/grammar/dae_config.g4` 后运行 `make config-parser`，提交生成代码；`make config-parser-check` 校验语法与生成器版本一致性。
- 缺内核头文件时运行 `git submodule update --init --recursive`；`make ebpf` 也会自动初始化缺失的 submodule

## 设计目标

dae 是一个以使用 ebpf 技术，尽量减少用户态处理为目标的代理软件，通过只导入代理流量到用户态以实现高性能，此外还有很多需要用户态处理的特殊流量如 DNS, 以及高级功能如 mitm 需要导入流量到用户态, 此时应该提供明确的规则边界，避免导入无关流量
