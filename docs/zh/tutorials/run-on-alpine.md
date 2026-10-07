# 在 Alpine Linux 上运行

**注意：**

1. dae 要求 Linux 6.13+，以及守护进程所需的[内核能力和挂载](../README.md#内核配置选项)，包括 BTF、cgroup BPF，以及 Netkit 或 veth；缺少 Netkit 支持时自动使用 veth + TCX。
2. `linux-virt`、`linux-lts`、`linux-edge` 等包名不能证明兼容性。安装后用 `dae check-kernel` 检查实际运行的内核，必要时选择或构建具有所需能力的内核。
3. 本教程使用 OpenRC。Alpine 在容器中运行时，内核由宿主提供，宿主必须允许所需操作。

## 启用 Community Repo

运行 `setup-apkrepos` 命令，然后你会看到这样的菜单列表：

```
 (f)    Find and use fastest mirror
 (s)    Show mirrorlist
 (r)    Use random mirror
 (e)    Edit /etc/apk/repositories with text editor
 (c)    Community repo enable
 (skip) Skip setting up apk repositories
```

然后输入 `c` 启用社区仓库。

## 启用 cgroup v2

在 `/etc/rc.conf` 中设置统一 cgroup 模式：

```sh
rc_cgroup_mode="unified"
```

启用并启动 `cgroups` 服务；如果系统已经使用其他 cgroup 布局启动，需要重启以应用模式变更。

```sh
rc-update add cgroups boot
rc-service cgroups start
```

## 挂载 bpffs

如果 `/sys/fs/bpf` 尚未挂载 bpffs，在 `/etc/fstab` 中添加：

```text
bpffs /sys/fs/bpf bpf defaults 0 0
```

然后以 root 挂载：

```sh
mkdir -p /sys/fs/bpf
mount /sys/fs/bpf
```

该文件系统必须允许 dae 写入。预检查还会检查 BTF 和 tracepoint 信息的访问，
可根据报错补齐挂载或内核能力。

## 安装 dae

安装程序： <https://github.com/daeuniverse/dae-installer/>

此安装程序提供了一个 dae 的 OpenRC 服务脚本，安装后，您需要在 `/usr/local/etc/dae/config.dae` 中添加一个配置文件，然后将其权限设置为 600 或 640：

```sh
chmod 640 /usr/local/etc/dae/config.dae
```

以 root 检查内核支持和配置，然后启动 dae：

```sh
dae check-kernel
dae validate -c /usr/local/etc/dae/config.dae
rc-service dae start
```

## 随系统启动

使用 `rc-update` 启用 dae 服务：

```sh
rc-update add dae
```
