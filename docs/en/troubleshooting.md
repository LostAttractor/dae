# Troubleshooting

## No network after `dae suspend`

Do not set dae as the DNS in DHCP setting. For example, you can set `223.5.5.5` as DNS in your DHCP setting.

Because dae will not hijack any DNS request if it was suspended.

## PVE related

- [PVE NIC Hardware passthrough](https://github.com/daeuniverse/dae/issues/43)

## Binding to WAN but no network

### Troubleshoot local DNS service

If you use `adguardhome`, `mosdns` in `dns` section, refer to [external-dns](configuration/external-dns.md).

### Troubleshoot firewall

If you bind to wan, make sure firewall is stopped or mark `0x8000000` is allowed by firewall. Don't worry about the security of this port because this port has its own firewall rule.

Usual firewalls on Linux:

```bash
ufw
firewalld
```

#### ufw

UFW users may need some extra steps to make sure `Binding to LAN` working.

Such as adding as follows to `/etc/ufw/before*.rules`:

```bash
# before.rules
-A ufw-before-input -m mark --mark 0x8000000 -j ACCEPT

# before6.rules
-A ufw6-before-input -m mark --mark 0x8000000 -j ACCEPT
```

#### firewalld

If you use firewalld, it is hard to add mark support. You have to execute following commands every time machine boot and firewall rule changes:

```bash
sudo nft 'insert rule inet firewalld filter_INPUT mark 0x8000000 accept'
```

### Troubleshoot PPPoE

Old version of dae does not support PPPoE, Please use latest version.

## Binding to LAN but bad DNS in other machines

### Troubleshoot config of dae

Make sure you have bind to the correct LAN interfaces.

For example, if your use the same interface eth1 for WAN and LAN, write it as `wan_interface: eth1` and also in `lan_interface: eth1`. If the LAN interfaces you want to proxy are eth1 and docker0, write them both as `lan_interface: eth1,docker0`.

### Troubleshoot DNS

To verify on another machine in LAN:

```bash
curl -i 1.1.1.1
curl -i google.com
```

If the first line has a response and the second line doesn't, check whether port `53` is occupied by others on dae's machine.

```bash
netstat -ulpen|grep 53
# or
# lsof -i:53 -n
```

If does, stop the service process or change its listening port from 53 to others. Do not forget to modify `/etc/resolv.conf` to make DNS accessible (for example, with content `nameserver 223.5.5.5`, but do not use `nameserver 127.0.0.1`).

## Fail to load eBPF objects

> FATA[0022] load eBPF objects: field TproxyWanEgress: program tproxy_wan_egress: load program: argument list too long: 1617: (bf) r2 = r6: 1618: (85) call bpf_map_loo (truncated, 992 line(s) omitted)

If you use `clang-13` to compile dae, you may encounter this problem.

There are ways to resolve it:

1. Method 1: Use `clang-15` or higher versions to compile dae. Or just download dae from [releases](https://github.com/daeuniverse/dae/releases).
2. Method 2: Add CFLAGS `-D__UNROLL_ROUTE_LOOP` while compiling. However, it will increse memory occupation (or swap space) at the eBPF loading stage (about 180MB). For example, compile dae to ARM64 using `GOARCH=arm64 make STATIC=y CC="$PWD/scripts/zig-cc.sh" CFLAGS="-D__UNROLL_ROUTE_LOOP"` (after setting up the cross-compiler as described in the [build guide](user-guide/build-by-yourself.md)).

## Native QuickJS build or executable does not start

- `CGO_ENABLED=0` is unsupported. Use `make`, or enable cgo explicitly for direct Go commands.
- Missing `stdlib.h`, unsupported machine instructions, or incompatible object files during cross-compilation usually indicate that `CC` or its sysroot targets the build host instead of `GOARCH`. eBPF's `CLANG` is a separate host tool.
- An existing executable that reports `No such file or directory` may reference an unavailable ELF interpreter. Check `readelf -lW ./dae` and `readelf -dW ./dae`. A Nix-built dynamic executable can depend on `/nix/store`; a glibc executable cannot be assumed to run on Alpine.

For a portable executable, follow the [static musl build instructions](user-guide/build-by-yourself.md#portable-static-musl-build) and run `scripts/check-static.sh dae`. No separate QuickJS shared library is required.
