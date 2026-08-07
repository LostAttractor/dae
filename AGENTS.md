# AGENTS.md

## 构建

- 开发环境：`nix-shell`（提供 go、clang、llvm）
- 编译：`make`，同时编译 eBPF C 代码（经 `go generate`）和 Go 部分，产物为 `./dae`
- 常用目标：`make ebpf`（仅编译 eBPF）、`make clean-ebpf`、`make ebpf-test`、`make ebpf-lint`、`make fmt`
- `make ebpf-test` 需要 `sudo`
- 可调变量见 Makefile：`CLANG`、`TARGET`、`OUTPUT`、`NOSTRIP=y` 等

## 内核头文件缺失

eBPF 代码依赖 submodule 中的内核头文件。编译报缺头文件时先拉取 submodule：

```sh
git submodule update --init --recursive
```

（`make ebpf` 会自动执行该命令）