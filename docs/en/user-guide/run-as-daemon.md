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
