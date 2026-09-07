# Build Guide

## Build dependencies

- Go 1.27 or later, Make, Git, and a C compiler with libc development headers.
- Clang and LLVM for eBPF generation (CI uses version 15).
- A target C compiler and sysroot when cross-compiling.

Go dependencies are pinned as Git submodules under `third_party/`: `outbound`,
`quic-go`, `dae-config-dist`, and `quickjs-go`. `go.mod` resolves these local
copies; the config module lives at `third_party/dae-config-dist/go/dae_config`.

The QuickJS-NG runtime is compiled from C sources in the `third_party/quickjs-go` Git submodule, a fork of [buke/quickjs-go](https://github.com/buke/quickjs-go) containing the binding integration fixes. All daemon builds require `CGO_ENABLED=1`, including builds where Surge is disabled in configuration. `make` enables cgo automatically. `netgo` and `osusergo` keep Go's DNS and user lookup implementations.

```sh
git clone --recurse-submodules https://github.com/daeuniverse/dae.git
cd dae
make
```

After switching revisions, run `git submodule update --init --recursive` to use
the pinned dependencies. `make` initializes missing submodules automatically.
Initialize them before running Go commands directly or building a Docker image;
the Docker build context must contain their source files.

On NixOS, `nix-shell --run make` supplies the development tools. A regular build may link to the host's libc; it is intended for that system or an appropriately packaged Nix closure.

`CC` selects the compiler for QuickJS/cgo. `CLANG` selects the host Clang used for eBPF. The Makefile's `CFLAGS` belong to eBPF; use `CGO_CFLAGS` for additional cgo compiler options. Keep these toolchains separate when cross-compiling.

## Portable static musl build

`STATIC=y` selects external static linking and a 2 MiB thread stack. `CC` must point to a musl compiler and its target sysroot; the flag does not select a libc.

On Debian/Ubuntu, install `musl-tools`, then run:

```sh
make STATIC=y CC=musl-gcc
scripts/check-static.sh dae
```

On NixOS, the provided shell selects the host architecture's Linux musl toolchain:

```sh
nix-shell musl.nix --run 'make && scripts/check-static.sh dae'
```

The static check rejects an ELF interpreter or shared-library dependencies. A verified static executable can be copied without libc or `/nix/store` dependencies. The Dockerfile also builds with musl and verifies the executable before copying it into Alpine.

## Cross-compilation

The release workflows use checksum-pinned [Zig 0.15.2](https://ziglang.org/download/0.15.2) as the C compiler and musl sysroot. The installation helper currently runs on Linux x86_64; on other hosts install the same Zig version and set `DAE_ZIG` to its executable.

```sh
export DAE_ZIG=$(scripts/setup-zig.sh /tmp/dae-zig)
GOARCH=arm64 make STATIC=y CC="$PWD/scripts/zig-cc.sh"
scripts/check-static.sh dae

GOARCH=arm GOARM=7 make STATIC=y CC="$PWD/scripts/zig-cc.sh"
GOARCH=mipsle GOMIPS=hardfloat make STATIC=y CC="$PWD/scripts/zig-cc.sh"
```

The wrapper covers `amd64`, `386`, `arm64`, ARM 5/6/7, `mipsle`, `mips64le`, `riscv64`, `loong64` and `ppc64le`. Set the correct ARM/MIPS floating-point ABI for the target CPU; big-endian targets are unsupported.

ARMv5 also needs `gcc-arm-linux-gnueabi` (Debian/Ubuntu), or a target `libgcc.a` supplied through `DAE_ARM_LIBGCC`, for static atomic support. The wrapper retains musl as libc. Keep `-w` when linking MIPS test executables with LLD to avoid incompatible Go/C DWARF sections.

You can instead pass an existing target musl compiler as `CC`. Setting only `GOARCH` is insufficient for cgo: the compiler, libc, ABI and headers must all target that architecture. The eBPF generators run as host Go tools independently of that compiler.

## Running Go commands directly

The Makefile supplies these settings. When invoking Go yourself, set them explicitly:

```sh
export CGO_ENABLED=1
go test -tags=netgo,osusergo ./component/mitm/surge
```

## External MITM plugins

Add one `type:Go/import/path` line per plugin to
[`mitm_plugins.cfg`](../../../mitm_plugins.cfg), then run `make` in dae.
Each package exports `Plugin` (`plugin.Definition` with `Setup` and optional `Commands`); the output binary is `./dae`. For example:

```text
surge:github.com/daeuniverse/dae/component/mitm/surge
bilijump:example.com/dae-mitm-bilijump
demo:example.com/dae-mitm-demo
```

Blank lines and `#` comments are allowed. Types must be unique CLI names (`[a-z][a-z0-9_-]*`); `ca`, `status` and `help` are reserved. An empty file
selects no types. Runtime instances and order belong to `mitm {}`.

For published plugins, use `go get <module>@<version>` to pin compatible
dependencies. For local examples beside dae, prepare a Go workspace from the dae
directory (use `go work use` instead of `init` if one already exists):

```sh
nix-shell
go work init . ../dae-mitm-bilijump ../dae-mitm-demo
go work edit "-replace=github.com/daeuniverse/dae@v0.0.0=$PWD"
make
```

The examples' `example.com` module paths and dae `v0.0.0` dependency are local
placeholders; replace them with published paths and versions for distribution.
Keep `go.work` local. Test each example using its small test-only Makefile:

```sh
GOWORK="$PWD/go.work" make -C ../dae-mitm-demo test
GOWORK="$PWD/go.work" make -C ../dae-mitm-bilijump test TEST_ARGS=-race
```

`make` and `make test` regenerate `cmd/mitm_plugins_generated.go` automatically.
`make plugins` only refreshes that table; run it before direct `go build` after
editing the cfg. The generated file is kept in source control for direct builds.
See [instance configuration](../../zh/configuration/mitm-plugins.md) and the
[plugin API](../../../component/mitm/plugin/README.md).

## Run

### Runtime Dependencies

For traffic splitting, dae relies on the following data sources, [geoip.dat](https://github.com/v2fly/geoip/releases/latest) and [geosite.dat](https://github.com/v2fly/domain-list-community/releases/latest).

```shell
mkdir -p /usr/local/share/dae/
pushd /usr/local/share/dae/
curl -L -o geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
curl -L -o geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
popd
```

### Run

Download the example config file:

```shell
curl -L -o example.dae https://github.com/daeuniverse/dae/raw/main/example.dae
```

See [example.dae](https://github.com/daeuniverse/dae/blob/main/example.dae).

After fine tuning, run dae:

```shell
./dae run -c example.dae
```

> **Note**: Alternatively, you may run dae as a daemon (systemd) service. Check out more details [HERE](run-as-daemon.md).
