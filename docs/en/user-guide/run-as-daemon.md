# Run dae as a Daemon Service

[systemd](https://wiki.debian.org/systemd) allows you to create and manage services in extremely powerful and flexible ways.

> **Note**: (Prerequisites) If your distribution's service manager is provided by systemd.

dae can run as a daemon (systemd) service so that it can run at boot.

## Prerequisites

### Kernel and runtime environment

Use a kernel and mounts that meet the [runtime requirements](../README.md#kernel-configurations).
After installing the binary, run `sudo dae check-kernel`. `dae run` also performs
this check before waiting for the network or preparing external resources.

### Optional Geo Data Files

Rules using `geoip:` require [geoip.dat](https://github.com/v2fly/geoip/releases/latest);
rules using `geosite:` require [geosite.dat](https://github.com/v2fly/domain-list-community/releases/latest).
This includes references in named rule sets, policies and plugin rules. Each file
is loaded independently; install neither when neither is referenced. `ext:` and
`mmdb:` require their referenced data files instead.

For a configuration that uses both standard datasets:

```shell
mkdir -p /usr/local/share/dae/
pushd /usr/local/share/dae/
curl -L -o geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
curl -L -o geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
popd
```

### Configuration File

> **Note**: The config file is recommended to save under `/etc/dae`

Download the sample config file:

```bash
mkdir -p /etc/dae
curl -L -o /etc/dae/config.dae https://github.com/LostAttractor/dae/raw/next/example.dae
chmod 600 /etc/dae/config.dae
```

## Download pre-compiled binaries

Download the `dae-<target>` executable for your platform from
[Releases](https://github.com/LostAttractor/dae/releases), for example
`dae-linux-x86_64`. Each release asset has a matching `dae-<target>.dgst` checksum file.

> **Note**: Builds of the `next` branch are available as artifacts of the
> [Build (Next)](https://github.com/LostAttractor/dae/actions/workflows/build.yml) and
> [Daily Build (Next)](https://github.com/LostAttractor/dae/actions/workflows/daily-build.yml)
> workflows. They contain unreleased changes that may be unstable. See the
> [distribution pipeline](build-by-yourself.md#distribution-pipeline) for target names.

```bash
sudo install -Dm755 dae-linux-x86_64 /usr/bin/dae

# help
dae --help
# check version
dae --version
# check kernel support and configuration
sudo dae check-kernel
dae validate -c /etc/dae/config.dae
```

## Setup

```bash
# download the sample systemd.service
sudo curl -L -o /etc/systemd/system/dae.service https://github.com/LostAttractor/dae/raw/next/install/dae.service

# reload and restart daemon to take effect
sudo systemctl daemon-reload
sudo systemctl enable dae --now
sudo systemctl status dae
```

## Check System Logs

```bash
sudo journalctl -xefu dae
```

## Binary upgrades

If dae is already running, `dae run` exits with an error and suggests `dae reload`
before loading configuration or preparing resources. The existing instance keeps
serving traffic. This also applies while it is starting or being replaced, and
does not depend on a PID file.

Install the new executable, then run `systemctl reload dae`. `ExecReload` must
invoke the newly installed binary. Identical executable contents reload
configuration; changed contents run target preflight and userspace input
preparation while the old dataplane and API continue serving, then close the
old Runtime and exec the new binary in the same business process. There is no
resident supervisor or separate worker. The service's PID and process starttime
remain unchanged; its Go heap and goroutines do not. After captured traffic is
blocked, the new image strictly replays sealed inputs, reads final settings and
rebuilds business BPF and plugin instances, including `Warm`. Missing replay inputs
never trigger live downloads. Replacement still does not preserve sessions or
guarantee an interruption below a fixed threshold. See
[replacement behavior and failure boundaries](reload-and-suspend.md#process-replacement).

Replacement does not require systemd or a `MainPID` transfer: foreground runs and
`Type=simple` units are supported too. The sample `Type=notify` unit uses the default
`NotifyAccess=main`; the single business process sends RELOADING and sends READY
only after the new runtime is ready. Internal replacement does not send STOPPING.
Normal service stop runs cleanup directly in that process. An ELF loader or
package initializer that hangs before startup deadline handling is installed
still requires intervention from an external manager; dae adds no resident watchdog.

For a NixOS unit running this fork directly, the relevant settings are:

```nix
{ config, ... }:
let
  dae = config.services.dae.package;
in {
  systemd.services.dae = {
    reloadIfChanged = true;
    serviceConfig = {
      Type = "notify";
      ExecReload = [ "" "${dae}/bin/dae reload" ];
    };
  };
}
```

Keep the unit's existing `ExecStart` pointing directly at the package's `dae run`.
[`reloadIfChanged`](https://github.com/NixOS/nixpkgs/blob/master/nixos/lib/systemd-unit-options.nix)
selects reload even when the store path changes; no stable executable wrapper is
needed. Configure `run -c` with a runtime configuration path whose contents can
change. A `LoadCredential` snapshot is created at service startup and is not
refreshed by same-PID exec. Preflight and exec retain the running daemon's effective
arguments, environment and working directory, not the reload CLI's environment.
Changes to those settings, credentials or other service startup conditions require
an explicit restart. Allow at least four minutes for the service's reload timeout
when configuration resources may load slowly.
