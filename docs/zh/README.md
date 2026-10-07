# 吃鹅直通手册

从[完整配置示例](../../example.dae)开始，按需配置以下功能：

- [页面/API](configuration/api.md)：设备集合、手动节点选择和 MITM 开关。
- [MITM 插件配置](configuration/mitm-plugins.md)：宿主与具名实例；内置 [Surge Module](configuration/surge-module.md) 的[支持范围](configuration/surge-module-support.md)。
- [CA 与客户端安装](configuration/mitm-certificate.md)、[缓存和持久化目录](configuration/cache-directory.md)。
- [rules / DNAT](configuration/destination-rules.md)：通过连接过滤条件覆盖拨号 IP，无需修改 DNS 应答。

开发者可参阅[当前项目结构](design/project-structure.md)和[外部插件契约](../../component/plugin/README.md)。

## Linux 内核要求

### 内核版本

使用 `uname -r` 来查看内核版本。

> **注意**
> dae 要求 Linux 6.13 或更新版本。如果内核版本较低，可以参考 [**Upgrade Guide**](../en/user-guide/kernel-upgrade.md)。

`绑定到 LAN 接口: >= 6.13`

如果你想作为路由器、网桥等中间设备，为其他设备提供代理服务，需要把 dae 绑定到 LAN 接口上。

该特性要求 Linux 6.13 或更新版本。

如果你只在 `lan_interface` 中填写了接口，而未在 `wan_interface` 中填写内容，那么本地程序将无法被代理。如果你期望代理本地程序，需要在 `wan_interface` 中填写 `auto` 或是手动输入 WAN 接口。

`绑定到 WAN 接口: >= 6.13`

如果你想为本地程序提供代理服务，需要把 dae 绑定到 WAN 接口上。

该特性要求 Linux 6.13 或更新版本。

如果你只在 `wan_interface` 中填写了接口或 `auto`，而未在 `lan_interface` 中填写内容，那么从局域网中传来的流量将无法被代理。如果你想同时代理本机和局域网流量，请同时填写 `wan_interface` 和 `lan_interface`。

守护进程运行于 Linux，目标架构必须是受支持的小端架构。容器使用宿主机内核。
独立 [API 客户端](configuration/api-client.md) 可在其他操作系统运行，不依赖这些内核特性。

## 内核配置选项

`dae run` 会在等待网络、加载规则资源和下载订阅之前自动检查内核能力。
也可以在启动前独立执行（无需配置文件）：

```shell
sudo dae check-kernel
```

检查包括 Linux 版本、BTF、实际 eBPF 程序/映射/helper 加载、bpffs 写入、cgroup v2 hooks、
Netkit/veth、TCX、SK_LOOKUP、进程退出 tracepoint、IPv4/IPv6 策略路由和透明套接字。
网络挂载探测在临时网络命名空间中执行；cgroup 探测程序仅放行，探测结束即释放资源。
缺少必需能力或权限会直接报错；可选 TCP splice 和长进程名 helper 缺失时使用现有降级路径，
IPv6 策略路由不可用时给出警告。
接口状态、sysctl 和具体配置仍会在正式启动时检查。

### 核心内核配置

自定义内核应核对以下配置，其中部分选项由 Kconfig 依赖自动选中。
内核版本号本身不能证明能力完整；即使系统未提供内核配置文件，`check-kernel` 也能实际探测运行中的内核。

```text
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_CGROUPS=y
CONFIG_CGROUP_BPF=y
CONFIG_NAMESPACES=y
CONFIG_NET_NS=y
CONFIG_NET=y
CONFIG_INET=y
CONFIG_IPV6=y
CONFIG_IP_MULTIPLE_TABLES=y
CONFIG_NET_XGRESS=y
CONFIG_NET_INGRESS=y
CONFIG_NET_EGRESS=y
CONFIG_PERF_EVENTS=y
CONFIG_KPROBES=y
CONFIG_KPROBE_EVENTS=y
CONFIG_BPF_EVENTS=y
```

`CONFIG_BPF_SYSCALL` 会选中 `NET_XGRESS`，后者选中 `NET_INGRESS` 和 `NET_EGRESS`。
内部链路需要 `CONFIG_NETKIT=y` 或 `CONFIG_VETH=y`/`m`（模块须可加载）之一。
dae 优先创建 Netkit L2 设备；内核报告不支持 Netkit 时，自动使用 veth，并在两端挂载 TCX ingress 程序。
权限不足、名称冲突和资源不足等错误会直接报告，不会被当成缺少 Netkit 支持。

宿主接口使用 TCX link，内部接口使用 Netkit 原生 hook 或 veth TCX link；dae 不要求 TC classifier/qdisc 的
`CONFIG_NET_CLS_BPF`、`CONFIG_NET_SCH_INGRESS` 或 `CONFIG_NET_CLS_ACT`。
仅使用 SOCKMAP/SOCKHASH 或当前的 stream-verdict relay 也不要求 `CONFIG_BPF_STREAM_PARSER`。

生成 BTF 所需的调试信息选项应遵循所用内核的 `DEBUG_INFO_BTF` Kconfig 依赖。
上面的 KPROBES/KPROBE_EVENTS 是启用 `BPF_EVENTS` 的常用配置路径；守护进程使用 BPF helper
和进程退出 tracepoint，`dae trace` 还会挂载 kprobe。

可以在 POSIX shell 中查看已安装内核的配置：

```sh
zcat /proc/config.gz 2>/dev/null || cat "/boot/config-$(uname -r)" /boot/config 2>/dev/null
```

### 运行环境

- `/sys/fs/bpf` 必须挂载为可读写的 bpffs，并允许 dae 写入。
- 必须挂载 cgroup v2，并允许挂载 BPF 程序。
- 内核 BTF（通常为 `/sys/kernel/btf/vmlinux`）和 tracefs 的 tracepoint 信息必须可访问；
  后者通常位于 `/sys/kernel/tracing` 或 `/sys/kernel/debug/tracing`。
- 进程需要 BPF、网络命名空间/设备创建、网络管理、套接字和 perf event 等操作权限；
  自带服务以 root 运行。容器的 capabilities、挂载和系统调用策略也必须允许这些操作。
- 内部网络命名空间需要内核 IPv4/IPv6 网络支持，但不要求外网具备 IPv6 连通性。
  接口转发及相关 sysctl 见[内核参数](../en/user-guide/kernel-parameters.md)。

### 可选及配置相关能力

| 功能 | 要求与行为 |
| --- | --- |
| IPv6 捕获策略路由 | `CONFIG_IPV6_MULTIPLE_TABLES`；不可用时警告，对应 IPv6 捕获路由/规则无法安装。 |
| 长进程名 | cgroup socket-address 程序支持 `bpf_get_current_task`；否则进程名路由使用截断的 task 名称。 |
| TCP splice 加速 | Linux 6.18+、编译启用 `dae_splice`，并支持 SOCKHASH/stream-verdict link 及所需 fexit 目标；不可用时，已捕获 TCP 使用用户态 relay。`make` 默认包含该构建标签。 |
| `dae trace` | Linux 6.13+、kprobe 及可访问的内核符号/BTF。`make` 在 `amd64`、`arm64`、`riscv64`、`loong64`、`ppc64le` 上包含该命令；其他受支持的守护进程架构不包含。具体追踪目标由 `dae trace` 检查，`check-kernel` 不检查这些目标。 |
| 网桥成员匹配 | 成员信息所需的 `CONFIG_BRIDGE_NETFILTER` 和 bridge netfilter 配置见[路由文档](configuration/routing.md)。 |
| 设备集合导出 | 配置 [ipset/nftset 导出](configuration/api.md) 时，需要相应内核能力和网络管理权限。 |

### Geo 数据文件

仅在规则引用时才需要 `geoip.dat` 或 `geosite.dat`，两个文件分别按需加载。
具名规则片段、策略及插件规则中的引用同样需要对应文件；完全没有引用时无需安装，也不会读取。
`geoip:`、`geosite:`、`ext:` 和 `mmdb:` 的用法见[路由文档](configuration/routing.md#例子)。

## 安装

### Arch Linux / Manjaro

直接从官方仓库安装 dae 即可。

除此之外，针对 AVX2 优化的最新二进制包和最新 Git 版可从 [AUR](https://aur.archlinux.org) 或 [archlinuxcn](https://github.com/archlinuxcn/repo) 获取。

#### 官方仓库

```shell
sudo pacman -S dae
```

#### AUR

使用 `yay` 安装，或将下述命令中的 `yay` 替换为 `paru`。

##### 最新稳定版 (针对 x86-64 v3 / AVX2 优化)

```shell
yay -S dae-avx2-bin
```

##### 最新 Git 版

```shell
yay -S dae-git
```

#### archlinuxcn

##### 最新稳定版 (针对 x86-64 v3 / AVX2 优化)

```shell
sudo pacman -S dae-avx2-bin
```

##### 最新 Git 版

```shell
sudo pacman -S dae-git
```

安装后，使用 systemctl 对服务进行控制：

```shell
# 启动 dae
sudo systemctl start dae

# 开机自动启动 dae
sudo systemctl enable dae
```

### Gentoo Linux

dae 已发布于 [gentoo-zh](https://github.com/microcai/gentoo-zh)，可以使用 `app-eselect/eselect-repository` 启用此 overlay:

```shell
eselect repository enable gentoo-zh
emaint sync -r gentoo-zh
emerge -a net-proxy/dae
```

### Fedora

dae 已发布于 [Fedora Copr](https://copr.fedorainfracloud.org/coprs/zhullyb/v2rayA/package/dae)。

```shell
sudo dnf copr enable zhullyb/v2rayA
sudo dnf install dae
```

### Alpine

详见 [run on alpine](../en/tutorials/run-on-alpine.md)。

### Docker

预编译镜像可相关文档请查阅：<https://hub.docker.com/r/daeuniverse/dae>。

作为替代，你也可以使用 `docker compose`:

```shell
git clone --depth=1 https://github.com/daeuniverse/dae
docker compose up -d --build
```

### 手动安装

> **Note**: 这种方法仅建议高级用户使用。采用这种方法，用户可以灵活地测试各个版本的 dae。请注意，新引入的功能有时可能存在 bug，因此请自行承担风险。

dae 可以以守护进程（systemd）的形式运行，见 [run as daemon](../en/user-guide/run-as-daemon.md)。

### 安装脚本

见 [daeuniverse/dae-installer](https://github.com/daeuniverse/dae-installer)（或使用 [镜像站](https://hubmirror.v2raya.org/daeuniverse/dae-installer)）。

### 手动构建

见 [Build Guide](../en/user-guide/build-by-yourself.md)。

## 最小 dae 配置

最小可启动的配置：

```shell
global{}
routing { fallback: direct }
```

此配置没有绑定接口。以下示例通过已有的 SOCKS5 服务代理本机流量，请将节点 URL 换成自己的服务。
它不依赖 Geo 数据文件或 DNS 插件；使用订阅和出站组的配置见[路由文档](configuration/routing.md)。

```shell
global {
  # 绑定到 LAN 和/或 WAN 接口。将下述接口替换成你自己的接口名。
  #lan_interface: docker0
  wan_interface: auto # 使用 "auto" 自动侦测 WAN 接口。

  log_level: info
  allow_insecure: false
  auto_config_kernel_parameter: true
}

node {
  proxy: 'socks5://127.0.0.1:1080'
}

# 更多的 Routing 样例见 https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/routing.md
routing {
  pname(NetworkManager) -> direct
  dip(224.0.0.0/3, 'ff00::/8') -> direct

  dip(127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, '::1/128', 'fc00::/7') -> direct

  fallback: proxy
}
```

核心按普通路由透明转发捕获到的 TCP/UDP 53 端口 DNS。
高级上游选择和应答缓存通过可选 [DNS 插件](configuration/dns.md) 提供。

通过有序的 `use` 组合 `rule_set` 片段，每个 `policy` 独立声明一个 fallback。`default: 策略名` 和接口绑定可选择同一个策略。完整说明见[路由配置](configuration/routing.md)和[拆分配置文件](configuration/separate-config.md)。

完整样例：[example.dae](https://github.com/daeuniverse/dae/blob/main/example.dae)。

如果你使用 PVE，可以参考 [#37](https://github.com/daeuniverse/dae/discussions/37)。

## PPPoE

如果希望代理 pppoe 接口, 请将 wan/lan_interface 设置为 pppd 生成的接口 (即 ppp0 / pppoe-wan) 而不是物理接口, 对于 wan 接口是 pppoe 的情况, 使用 auto 即可。

## 热重载和暂停

当配置变化时，可以方便使用命令进行配置的热重载，在该过程中不会中断已有连接。当想暂停代理时，可使用命令进行暂停。

详见 [Reload and suspend](../en/user-guide/reload-and-suspend.md)。

## 错误排查

详见 [Troubleshooting](../en/troubleshooting.md)。
