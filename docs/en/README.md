# Quick Start Guide

[**简体中文**](../zh/README.md) | [**English**](README.md)

The [full configuration example](../../example.dae) includes the [management API](configuration/api.md), optional [plugin instances](../zh/configuration/mitm-plugins.md) with [Surge compatibility](../zh/configuration/surge-module.md), [DNS relay/plugins](configuration/dns.md), and [destination overrides](../zh/configuration/destination-rules.md). External plugins use the [public Go contract](../../component/plugin/README.md).

## Linux Kernel Requirement

### Kernel Version

Use `uname -r` to check the kernel version on your machine.

> **Note**
> Linux 6.13 or newer is required. Follow the [**Upgrade Guide**](user-guide/kernel-upgrade.md) if your kernel is older.

`Bind to LAN: >= 6.13`

You need bind dae to LAN interface, if you want to provide network service for LAN as an intermediate device.

This feature requires Linux 6.13 or newer.

Note that if you bind dae to LAN only, dae only provide network service for traffic from LAN, and not impact local programs.

`Bind to WAN: >= 6.13`

You need bind dae to WAN interface, if you want dae to provide network service for local programs.

This feature requires Linux 6.13 or newer.

Note that if you bind dae to WAN only, dae only provide network service for local programs and not impact traffic coming in from other interfaces.

The daemon runs on Linux with a supported little-endian target architecture.
Containers use the host kernel. The standalone [API client](configuration/api-client.md)
can run on other operating systems without these kernel features.

## Kernel Configurations

`dae run` checks kernel support before waiting for the network, loading rule
resources or downloading subscriptions. To check independently without a config:

```shell
sudo dae check-kernel
```

Checks cover the Linux version, BTF, production eBPF programs/maps/helpers,
writable bpffs, cgroup v2 hooks, Netkit/veth, TCX, SK_LOOKUP, the process-exit tracepoint,
IPv4/IPv6 policy routing and transparent sockets. Network attachment probes use a
temporary network namespace; cgroup probes only allow traffic. Probe resources
are released on completion. Missing required support or privileges stops startup;
optional TCP splice and the long-process-name helper retain their fallback paths,
and unavailable IPv6 policy routing produces a warning.
Interface state, sysctls and configuration-specific requirements are checked during
normal startup.

### Core kernel configuration

For a custom kernel, check the following configuration. Kconfig selects some of
these symbols through dependencies; a version number alone does not establish
support. `check-kernel` probes the running kernel even when its config file is
unavailable.

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

`CONFIG_BPF_SYSCALL` selects `NET_XGRESS`, which selects `NET_INGRESS` and
`NET_EGRESS`. The internal link requires either `CONFIG_NETKIT=y` or
`CONFIG_VETH=y`/`m` with the veth module available. dae prefers a Netkit L2 pair;
when the kernel reports Netkit unsupported, it automatically uses a veth pair
with TCX ingress programs on both ends. Permission, name-conflict and resource
errors are reported rather than interpreted as missing Netkit support.

Host interfaces use TCX links. Internal interfaces use native Netkit hooks or
veth TCX links; dae does not require the TC classifier/qdisc options `CONFIG_NET_CLS_BPF`,
`CONFIG_NET_SCH_INGRESS` or `CONFIG_NET_CLS_ACT`. `CONFIG_BPF_STREAM_PARSER` is not
required merely to use SOCKMAP/SOCKHASH or the current stream-verdict relay.

Enable the debug-info options required by your kernel's `DEBUG_INFO_BTF` Kconfig
dependencies. The KPROBES/KPROBE_EVENTS settings above provide the usual path to
`BPF_EVENTS`; the daemon uses BPF helpers and a process-exit tracepoint, while
`dae trace` also attaches kprobes.

To inspect the installed kernel configuration in a POSIX shell:

```sh
zcat /proc/config.gz 2>/dev/null || cat "/boot/config-$(uname -r)" /boot/config 2>/dev/null
```

### Runtime environment

- Mount bpffs read-write at `/sys/fs/bpf` and make it writable by dae.
- Mount cgroup v2 and permit BPF attachment to it.
- Expose kernel BTF (normally `/sys/kernel/btf/vmlinux`) and tracefs tracepoint
  metadata (normally `/sys/kernel/tracing` or `/sys/kernel/debug/tracing`).
- Run with the privileges needed for BPF, network namespace/device creation,
  network administration, sockets and perf events; the supplied service runs as
  root. Container capabilities, mounts and syscall policy must allow these operations.
- Keep IPv4 and IPv6 kernel networking available for the internal namespace;
  this does not require an IPv6 Internet connection. Interface forwarding and
  related sysctls are described in [kernel parameters](user-guide/kernel-parameters.md).

### Optional and configuration-specific features

| Feature | Requirement and behavior |
| --- | --- |
| IPv6 interception policy routing | `CONFIG_IPV6_MULTIPLE_TABLES`; missing support produces a warning and prevents the corresponding IPv6 interception route/rule from being installed. |
| Long process names | `bpf_get_current_task` in cgroup socket-address programs; otherwise process-name routing uses truncated task names. |
| TCP splice acceleration | Linux 6.18+, a build with `dae_splice`, SOCKHASH/stream-verdict links and the required fexit targets; unavailable support falls back to userspace relay for captured TCP. `make` includes the build tag. |
| `dae trace` | Linux 6.13+, kprobes and accessible kernel symbols/BTF. `make` includes it on `amd64`, `arm64`, `riscv64`, `loong64` and `ppc64le`; other supported daemon targets omit the command. Trace targets are checked by `dae trace`, not by `check-kernel`. |
| Bridge-member matching | [Routing](configuration/routing.md) describes `CONFIG_BRIDGE_NETFILTER` and the bridge netfilter settings needed for member metadata. |
| Client-set export | Configured [ipset/nftset exports](configuration/api.md) require their kernel facilities and network-administration privileges. |

### Geo data files

`geoip.dat` and `geosite.dat` are needed only when rules reference them. They are
loaded independently, including references in rule sets, policies and plugin
rules. With no references, neither file is read or needs to be installed. See
[routing](configuration/routing.md#examples) for `geoip:`, `geosite:`, `ext:` and
`mmdb:` usage.

## Installation

### Arch Linux / Manjaro

You can install dae directly from the official repository.

Alternatively, get the latest AVX2-optimized binary package or the latest Git version from [AUR](https://aur.archlinux.org) or [archlinuxcn](https://github.com/archlinuxcn/repo).

#### Official Repository

```shell
sudo pacman -S dae
```

#### AUR

Install with `yay`, or replace `yay` with `paru` in the commands below.

##### Latest Release (Optimized Binary for x86-64 v3 / AVX2)

```shell
yay -S dae-avx2-bin
```

##### Latest Git Version

```shell
yay -S dae-git
```

#### archlinuxcn

##### Latest Release (Optimized Binary for x86-64 v3 / AVX2)

```shell
sudo pacman -S dae-avx2-bin
```

##### Latest Git Version

```shell
sudo pacman -S dae-git
```

After installation, use systemctl to control it.

```shell
# start dae
sudo systemctl start dae

# auto start dae at boot
sudo systemctl enable dae
```

### Gentoo Linux

dae has been released on [gentoo-zh](https://github.com/microcai/gentoo-zh)

use `app-eselect/eselect-repository` to enable this overlay:

```shell
eselect repository enable gentoo-zh
emaint sync -r gentoo-zh
emerge -a net-proxy/dae
```

### Fedora

dae has been released on [Fedora Copr](https://copr.fedorainfracloud.org/coprs/zhullyb/v2rayA/package/dae).

```shell
sudo dnf copr enable zhullyb/v2rayA
sudo dnf install dae
```

### Alpine

See [run on alpine](tutorials/run-on-alpine.md).

### Docker

Pre-built image and related docs can be found at <https://hub.docker.com/r/daeuniverse/dae>.

Alternatively, you can use `docker compose`:

```shell
git clone --depth=1 https://github.com/daeuniverse/dae
docker compose up -d --build
```

## Manual installation

> **Note**: This approach is **ONLY** recommended for `advanced` users. With this approach, users may have flexibility to test various versions of dae. Noted that newly introduced features are sometimes buggy, do it at your own risk.

dae can run as a daemon (systemd) service. See [run-as-daemon](user-guide/run-as-daemon.md)

### Installation Script

See [daeuniverse/dae-installer](https://github.com/daeuniverse/dae-installer) (or [mirror](https://hubmirror.v2raya.org/daeuniverse/dae-installer)).

### Build from scratch

See [Build Guide](user-guide/build-by-yourself.md).

## Minimal Configuration

For minimal bootable config:

```shell
global{}
routing { fallback: direct }
```

This config binds no interfaces. The following example proxies local traffic
through an existing SOCKS5 server; replace the node URL with your own server.
It needs no Geo data files or DNS plugins. For subscription-backed groups, see
[routing](configuration/routing.md).

```shell
global {
  # Bind to LAN and/or WAN as you want. Replace the interface name to your own.
  #lan_interface: docker0
  wan_interface: auto # Use "auto" to auto detect WAN interface.

  log_level: info
  allow_insecure: false
  auto_config_kernel_parameter: true
}

node {
  proxy: 'socks5://127.0.0.1:1080'
}

# See https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/routing.md for full examples.
routing {
  pname(NetworkManager) -> direct
  dip(224.0.0.0/3, 'ff00::/8') -> direct

  dip(127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, '::1/128', 'fc00::/7') -> direct

  fallback: proxy
}
```

Core transparently relays captured DNS on TCP/UDP port 53 using ordinary routing.
Advanced upstream selection and response caching use optional [DNS plugins](configuration/dns.md).

Compose `rule_set` fragments with ordered `use` statements. Each `policy` declares one fallback; `default: policy_name` and interface bindings can select the same policy. See [routing](configuration/routing.md) and [separate configuration files](configuration/separate-config.md) for complete examples.

See more at [example.dae](https://github.com/daeuniverse/dae/blob/main/example.dae).

If you use PVE, refer to [#37](https://github.com/daeuniverse/dae/discussions/37).

## PPPoE Interface

If you want to proxy PPPoE interface, please set wan/lan_interface to the interface generated by pppd (i.e., ppp0 / pppoe-wan) instead of the physical interface.
If you just using PPPoE interface for wan, simply set wan_interface to "auto".

## Reload and suspend

When the configuration changes, it is convenient to use command to hot reload the configuration, and the existing connection will not be interrupted in the process. When you want to suspend dae, you can use command to pause.

See [Reload and suspend](user-guide/reload-and-suspend.md).

## Troubleshooting

See [Troubleshooting](troubleshooting.md).
