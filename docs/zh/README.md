# 吃鹅直通手册

从[完整配置示例](../../example.dae)开始，按需配置以下功能：

- [页面/API](configuration/api.md)：设备集合、手动节点选择和 MITM 开关。
- [MITM 插件配置](configuration/mitm-plugins.md)：宿主与具名实例；内置 [Surge Module](configuration/surge-module.md) 的[支持范围](configuration/surge-module-support.md)。
- [CA 与客户端安装](configuration/certificate.md)、[缓存和持久化目录](configuration/cache-directory.md)。
- [rules / DNAT](configuration/destination-rules.md)：通过连接过滤条件覆盖拨号 IP，无需修改 DNS 应答。

项目设计见[项目结构](design/project-structure.md)、[出站连通性与故障转移](design/outbound-connectivity.md)、[MITM HTTP 转发与证书身份](design/mitm-http.md)和[API 鉴权与访问控制](design/api-access-control.md)。开发参考包括[测试与性能测量](development/testing-and-performance.md)和[外部插件契约](../../component/plugin/README.md)。

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
Netkit/veth、TCX、SK_LOOKUP、进程退出 tracepoint、IPv4/IPv6 策略路由、透明套接字和宿主 UDP conntrack。
conntrack 探针在实际服务的网络命名空间中交换回环数据报并查询方向，不挂载程序、不改变防火墙规则。
网络挂载探测在临时网络命名空间中执行；cgroup 探测程序仅放行，探测结束即释放资源。
缺少必需能力或权限会直接报错；可选长进程名 helper 缺失时使用截断的进程名，
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
CONFIG_NETFILTER=y
CONFIG_NF_CONNTRACK=y
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

UDP 方向依赖系统 conntrack 及其 `bpf_skb_ct_lookup` / `bpf_ct_release` kfunc。
也支持 `CONFIG_NF_CONNTRACK=m`，但模块必须已经加载，并提供模块 BTF（`CONFIG_DEBUG_INFO_BTF_MODULES=y`）。
实际服务的网络命名空间必须启用 IPv4/IPv6 流量跟踪；仅加载模块不代表跟踪 hooks 已启用。
检查失败会拒绝冷启动或候选准备。探针检查默认 zone 的回环路径，不证明接口专用 NOTRACK 或自定义 zone 的行为；
dae 不会通过修改宿主防火墙来启用跟踪。

宿主接口使用 TCX link，内部接口使用 Netkit 原生 hook 或 veth TCX link；dae 不要求 TC classifier/qdisc 的
`CONFIG_NET_CLS_BPF`、`CONFIG_NET_SCH_INGRESS` 或 `CONFIG_NET_CLS_ACT`。
监听 socket 的 SOCKMAP 与 SK_LOOKUP 入口不要求 `CONFIG_BPF_STREAM_PARSER`。

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
| TCP splice 加速 | 原生 TCP 直连转发使用 Go `io.Copy` 与 Linux `splice(2)`。socket 或内核计数不满足条件时使用缓冲复制；无需额外 BPF 程序或构建标签。 |
| `dae trace` | Linux 6.13+、kprobe 及可访问的内核符号/BTF。`make` 在 `amd64`、`arm64`、`riscv64`、`loong64`、`ppc64le` 上包含该命令；其他受支持的守护进程架构不包含。具体追踪目标由 `dae trace` 检查，`check-kernel` 不检查这些目标。 |
| 网桥成员匹配 | 成员信息所需的 `CONFIG_BRIDGE_NETFILTER` 和 bridge netfilter 配置见[路由文档](configuration/routing.md)。 |
| 设备集合导出 | 配置 [ipset/nftset 导出](configuration/api.md) 时，需要相应内核能力和网络管理权限。 |

### Geo 数据文件

仅在规则引用时才需要 `geoip.dat` 或 `geosite.dat`，两个文件分别按需加载。
具名规则片段、策略及插件规则中的引用同样需要对应文件；完全没有引用时无需安装，也不会读取。
`geoip:`、`geosite:`、`ext:` 和 `mmdb:` 的用法见[路由文档](configuration/routing.md#例子)。

CI 产物、Release 二进制和 Docker 镜像均不附带 Geo 数据文件，需要时单独安装或挂载。

## 安装

### 预编译二进制

从 [Releases](https://github.com/LostAttractor/dae/releases) 下载对应平台的 `dae-<target>` 可执行文件，如 `dae-linux-x86_64`。
以 systemd 服务安装及升级见[服务部署（英文）](../en/user-guide/run-as-daemon.md)；重载、同 PID exec 替换和暂停见[使用指南（英文）](../en/user-guide/reload-and-suspend.md)，交接约束见[进程热替换](design/process-replacement.md)。目标平台、校验文件及 `next` 分支构建见[分发流程](../en/user-guide/build-by-yourself.md#distribution-pipeline)。

### Alpine

详见 [run on alpine](tutorials/run-on-alpine.md)。

### Docker

本分叉将镜像发布到 `ghcr.io/lostattractor/dae`。
主分支使用 `:next`，最新正式版使用 `:latest`，也可使用去掉开头 `v` 的版本号（如 `:1.2.3`）。
预发布不会更新 `latest`。构建与发布规则见[容器构建文档](../en/user-guide/build-by-yourself.md#docker)。

```shell
docker pull ghcr.io/lostattractor/dae:next
```

镜像仅包含程序，不附带配置或 Geo 数据。请从宿主机挂载 `/etc/dae/config.dae`，并按需挂载 Geo 数据。

作为替代，你也可以使用 `docker compose`:

```shell
git clone --depth=1 --recurse-submodules https://github.com/LostAttractor/dae
cd dae
docker compose up -d --build
```

### NixOS

仓库的 flake 以默认插件选择打包当前源码，并提供 `services.dae` NixOS 模块，取代 Nixpkgs 中的同名模块。请使用 `git+https` URL，以便 Nix 拉取固定的子模块：

```nix
{
  inputs.dae.url = "git+https://github.com/LostAttractor/dae";

  outputs = { nixpkgs, dae, ... }: {
    nixosConfigurations.HOSTNAME = nixpkgs.lib.nixosSystem {
      modules = [
        dae.nixosModules.default
        {
          services.dae = {
            enable = true;
            configFile = "/etc/dae/config.dae";
          };
        }
      ];
    };
  };
}
```

`configFile` 与 `config` 必须且只能设置其一。`configFile` 须位于 Nix store 之外，且不允许其他用户访问。`config` 文本会安装为 `/etc/dae/config.dae`，但在 Nix store 中对所有用户可读；修改它会重载服务。模块根据 `assets`（默认 `v2ray-geoip` 和 `v2ray-domain-list-community`）或 `assetsPath` 设置 `DAE_LOCATION_ASSET`，根据 `cachePath` 设置 `DAE_LOCATION_CACHE`，并通过 `openFirewall` 开放 TCP/UDP 12345 端口。全部选项见 [`nix/module.nix`](../../nix/module.nix)。

仅构建软件包可运行 `nix build git+https://github.com/LostAttractor/dae`。

构建选项是软件包参数。`surgeRuntime` 在编译期选择 Surge 后端：`nodejs`（默认）在 Node.js 进程中运行脚本，`quickjs` 内嵌 QuickJS-NG。`plugins` 替换 `plugins.cfg` 的插件选择，`pluginModules` 将外部插件模块的源码加入 Go workspace，`vendorHash` 须与由此得到的 Go 依赖一致。`runtimeInputs` 列出插件运行时在 `PATH` 中查找的程序；模块会把它们，以及 `nodejs` 后端所需的 Node.js，加入服务的 `PATH`：

```nix
services.dae.package = dae.packages.${pkgs.stdenv.hostPlatform.system}.dae.override {
  plugins = ''
    surge:github.com/daeuniverse/dae/plugins/surge
    example:example.com/dae-plugin-example
  '';
  pluginModules = [ dae-plugin-example ]; # 设置了 `flake = false` 的 flake 输入。
  vendorHash = "sha256-..."; # 先设为 ""，再使用构建报告的哈希。
  runtimeInputs = [ pkgs.ffmpeg ];
};
```

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

# 更多的 Routing 样例见 https://github.com/LostAttractor/dae/blob/next/docs/zh/configuration/routing.md
routing {
  pname(NetworkManager) -> direct
  dip(224.0.0.0/3, 'ff00::/8') -> direct

  dip(127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, '::1/128', 'fc00::/7') -> direct

  fallback: proxy
}
```

`wan_interface: auto` 跟随主路由表中的 IPv4 和 IPv6 默认路由接口。
仅在策略路由表中存在的默认路由不会启用自动捕获；需要捕获这些接口时，请显式填写接口名。

核心按普通路由透明转发捕获到的 TCP/UDP 53 端口 DNS。
高级上游选择和应答缓存通过可选 [DNS 插件](configuration/dns.md) 提供。

通过有序的 `use` 组合 `rule_set` 片段，每个 `policy` 独立声明一个 fallback。`default: 策略名` 和接口绑定可选择同一个策略。完整说明见[路由配置](configuration/routing.md)和[拆分配置文件](configuration/separate-config.md)。

完整样例：[example.dae](../../example.dae)。

如果你使用 PVE，可以参考 [#37](https://github.com/daeuniverse/dae/discussions/37)。

## PPPoE

如果希望代理 pppoe 接口，请将 wan/lan_interface 设置为 pppd 生成的接口 (即 ppp0 / pppoe-wan) 而不是物理接口，对于 wan 接口是 pppoe 的情况，使用 auto 即可。

## 热重载和暂停

当配置变化时，可以方便使用命令进行配置的热重载，在该过程中不会中断已有连接。当想暂停代理时，可使用命令进行暂停。

详见 [Reload and suspend](../en/user-guide/reload-and-suspend.md)。

## 错误排查

详见 [Troubleshooting](../en/troubleshooting.md)。
