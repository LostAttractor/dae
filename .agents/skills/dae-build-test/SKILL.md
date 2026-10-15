---
name: dae-build-test
description: 构建或测试 dae、选择自有插件与 Surge 运行时测试覆盖，或修改配置语法后重新生成解析器时使用。
---

# dae 构建与测试

在仓库根目录使用 `direnv` 或 `nix-shell` 获得开发环境。

## 构建与 eBPF

- `make` 编译 Go 和 eBPF，生成 `./dae`；其他目标及变量见根目录 `Makefile`。
- 缺内核头文件时运行 `git submodule update --init --recursive`；`make ebpf` 也会自动初始化缺失的 submodule。
- `make ebpf-test` 需要 `sudo`。

## 插件与运行时测试

- 在本地 `plugins.cfg` 中取消示例内可选插件的注释，运行 `make test` 验证全部自有插件的编译选择。
- 运行 `make test SURGE_RUNTIME=nodejs` 验证无 CGO 的 Node 后端。
- 运行 `make client-test` 检查客户端依赖边界。

## 配置解析器

修改 `pkg/config_parser/grammar/dae_config.g4` 后运行 `make config-parser`，提交生成代码；运行 `make config-parser-check` 校验语法与生成器版本一致性。
