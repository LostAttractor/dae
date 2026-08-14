# Kernel Upgrade Guide

dae requires Linux 6.13 or newer with Netkit, BPF, BTF, and the other options listed in the [quick-start requirements](../README.md). Containers use the host kernel and cannot upgrade it from inside the container.

Check the running kernel before changing it:

```shell
uname -r
zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r)
```

Install a distribution-supported kernel that is explicitly version 6.13 or newer. Package names, bootloader steps, and available kernel configurations vary by distribution, so follow its current documentation rather than copying commands for a different release. Embedded distributions may omit `CONFIG_NETKIT` or BTF even when their version is new enough.

Keep the previous kernel as a recovery option, reboot, and verify both the version and configuration again. dae does not publish or maintain third-party kernel packages.
