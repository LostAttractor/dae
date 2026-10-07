# Run on Alpine Linux

**Note:**

1. dae requires Linux 6.13+ and the [kernel features and mounts](../README.md#kernel-configurations) used by the daemon, including BTF, cgroup BPF and either Netkit or veth. Missing Netkit support automatically selects veth with TCX.
2. Kernel package names such as `linux-virt`, `linux-lts` and `linux-edge` do not establish compatibility. Check the running kernel with `dae check-kernel` after installation; select or build a kernel with the required features if necessary.
3. This guide uses OpenRC. When running Alpine in a container, the host supplies the kernel and must permit the required operations.

## Enable Community Repo

Run `setup-apkrepos` command, then you'll get a menu list like this:

```
 (f)    Find and use fastest mirror
 (s)    Show mirrorlist
 (r)    Use random mirror
 (e)    Edit /etc/apk/repositories with text editor
 (c)    Community repo enable
 (skip) Skip setting up apk repositories
```

Then input `c` to enable community repo.

## Enable cgroup v2

Set unified cgroup mode in `/etc/rc.conf`:

```sh
rc_cgroup_mode="unified"
```

Enable and start the `cgroups` service. If the system already booted with a
different cgroup layout, reboot to apply the mode change.

```sh
rc-update add cgroups boot
rc-service cgroups start
```

## Mount bpffs

If bpffs is not already mounted at `/sys/fs/bpf`, add this entry to `/etc/fstab`:

```text
bpffs /sys/fs/bpf bpf defaults 0 0
```

Then mount it as root:

```sh
mkdir -p /sys/fs/bpf
mount /sys/fs/bpf
```

It must be writable by dae. The preflight also checks BTF and access to tracepoint
metadata; use the errors to identify missing mounts or kernel features.

## Install dae

Installer: <https://github.com/daeuniverse/dae-installer/>

This installer offered an OpenRC service script of dae, after installation, you should add a config file to `/usr/local/etc/dae/config.dae`, then set its permission to 600 or 640:

```sh
chmod 640 /usr/local/etc/dae/config.dae
```

Validate kernel support and the configuration as root, then start dae:

```sh
dae check-kernel
dae validate -c /usr/local/etc/dae/config.dae
rc-service dae start
```

## Start dae at boot

Use `rc-update` to enable dae service:

```sh
rc-update add dae
```
