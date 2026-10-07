# Kernel Upgrade Guide

dae requires Linux 6.13 or newer with BPF, BTF, Netkit or veth, and the other options listed in the [quick-start requirements](../README.md). Netkit is preferred; kernels without Netkit use veth with TCX. Containers use the host kernel and cannot upgrade it from inside the container.

Check the running kernel before changing it:

```shell
uname -r
sudo dae check-kernel
zcat /proc/config.gz 2>/dev/null || cat "/boot/config-$(uname -r)" /boot/config 2>/dev/null
```

Install a distribution-supported kernel that is explicitly version 6.13 or newer. Package names, bootloader steps, and available kernel configurations vary by distribution, so follow its current documentation rather than copying commands for a different release. Check BTF and either `CONFIG_NETKIT` or `CONFIG_VETH` even when the version is new enough.

The check also reports missing permissions and mounts; these need environment
configuration rather than a kernel upgrade. Optional TCP splice acceleration needs
Linux 6.18+ and additional BPF tracing support; its absence does not prevent the
core datapath from running on a supported 6.13+ kernel.

Keep the previous kernel as a recovery option, reboot, and verify both the version and configuration again. dae does not publish or maintain third-party kernel packages.
