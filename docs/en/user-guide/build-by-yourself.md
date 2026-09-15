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

## Static builds

`STATIC=y` selects external static linking and requests a 2 MiB thread stack.
The libc is selected by `CC`, whose target sysroot must supply static archives.
`STATIC=y` does not switch the compiler or libc.

### glibc

The default Nix development shell supplies the glibc compiler and `glibc.static`.
After reloading direnv when the shell changes, build with:

```sh
make STATIC=y
scripts/check-static.sh dae
```

Without direnv, use `nix-shell --run 'make STATIC=y && scripts/check-static.sh dae'`.
On other glibc-based Linux systems, install the target libc's static development
libraries and use the same make command with a glibc compiler.

glibc's `dlopen` and some NSS modules can still require shared libraries at
runtime. The current daemon uses `netgo,osusergo` and disables QuickJS native
module imports and std/os modules. QuickJS's bundled native module loader still
produces a `dlopen` linker warning, although that path is disabled in dae's VM.

### musl

On Debian/Ubuntu, install `musl-tools`, then run:

```sh
make STATIC=y CC=musl-gcc
scripts/check-static.sh dae
```

On NixOS, `musl.nix` reuses the development shell with the host architecture's
Linux musl compiler and defaults `STATIC=y`:

```sh
nix-shell musl.nix --run 'make && scripts/check-static.sh dae'
```

The static check rejects an ELF interpreter or startup shared-library dependencies;
it does not detect libraries loaded later with `dlopen`. The static musl daemon
can be copied without libc or `/nix/store` dependencies. The Dockerfile also builds
with musl and verifies the executable before copying it into Alpine.

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
go test -tags=netgo,osusergo,grpcnotrace ./component/mitm/surge
```

## Debug builds

`DEBUG_FLAGS` defaults to `n`. Enable it for source-level debugging:

```sh
make STATIC=y DEBUG_FLAGS=y OUTPUT=dae-debug
```

For daemon builds, this retains Go symbols and DWARF by omitting `-s -w`,
disables Go optimization and inlining with `-gcflags="all=-N -l"`, and omits
`-trimpath` so debuggers can find local source files. It also disables stripping
of the embedded eBPF objects. eBPF still compiles with `-O2`; native QuickJS
compilation uses the selected `CGO_CFLAGS` (Go's default is `-O2 -g`).

The Go debugging flags also apply to `make test`, `make ebpf-test`, `make client`
and `make client-test`. `NOSTRIP=y` remains an eBPF-only option; `DEBUG_FLAGS=y`
disables eBPF stripping even if `NOSTRIP=n` is specified.

Use `make STATIC=y` (or explicitly `DEBUG_FLAGS=n`) for a release daemon build.
Debug builds are larger and execute different, unoptimized Go code, so their
size and performance differ from optimized builds that merely retain symbols.

## Binary size

`make` includes gRPC's `grpcnotrace` build tag by default to omit the optional
RPC trace web implementation and its template dependencies. Use
`make GRPC_TRACE=y` to include it. The architecture-specific eBPF `trace` tag is
controlled separately by BPF generation.

Release daemon builds use `-trimpath` and strip Go debug symbols with `-s -w`.
The BPF generators also run `cmd/dae-bpf-pack`: it deterministically compresses
each ELF into an adjacent `.o.gz` and updates the generated Go loader to embed
that file. The original `.o` remains available for ELF/BTF inspection and audits.
Run the complete `go generate` directive sequence, or `make ebpf`, when refreshing
objects; invoking `bpf2go` alone does not perform the compression step.

Objects are decompressed and checksum-checked when their collection specs are
loaded. The ELF, BTF and relocations are restored byte for byte. Decompressed
objects are not kept in a package-global cache. `make clean-ebpf` removes both
the raw and compressed generated objects.

Configuration outlines and VMess share links use the standard library JSON
implementation. VMess parsing retains numeric/string subscription fields and
the existing `allowInsecure` conversions locally, without global JSON decoder
registration.

To inspect a build, use `go version -m dae`, `readelf -SW dae` and `size -A dae`.
Sections of type `NOBITS`, including `.bss` and `.noptrbss`, do not contribute
their reported size to the executable file. Go function and type metadata is
needed at runtime even in a stripped binary. Compare builds with the same Go/C
toolchains, plugins, build tags and static-linking settings.

## BPF map capacities

The following make arguments tune rule scale and traffic-dependent table
capacities in `control/kern/tproxy.c`:

| Parameter | Default | Purpose |
| --- | ---: | --- |
| `MAX_MATCH_SET_LEN` | 1024 | Existing rule-scale setting: routing instruction capacity and domain bitmap width |
| `MAX_DOMAIN_ROUTING_NUM` | 65536 | Complete IP states resident in the kernel domain projection |
| `MAX_DST_MAPPING_NUM` | 262144 | Per-flow routing results in `routing_tuples_map` |
| `MAX_DST_MAPPING_NUM_UDP` | 131072 | UDP flow-direction state in `udp_conn_state_map` |
| `MAX_UDP_ROUTING_CACHE_NUM` | 65536 | Capacity of each UDP source-routing cache and userspace binding map |

```sh
make MAX_DOMAIN_ROUTING_NUM=131072 MAX_UDP_ROUTING_CACHE_NUM=131072
```

Capacities must be positive integers. `MAX_MATCH_SET_LEN` must be a multiple of
32 between 32 and 65536; it changes both domain bitmap width and routing-profile
layout. Generated Go types and the Go routing limit use the same build setting.
Domain capacity is counted in IPs and read from the loaded map; a larger bitmap
also costs more per IP. Adjust the traffic-state capacities for the expected
concurrent flow/source count and available memory.

Interface capacity, the per-trie LPM limit, process metadata and API observation
tables remain internal constants. `MAX_LPM_NUM` is derived from
`MAX_MATCH_SET_LEN + 8`. These are not independent make configuration parameters.

After generating objects with a nondefault `MAX_MATCH_SET_LEN`, direct `go build`
or `go test` commands also need
`-ldflags '-X github.com/daeuniverse/dae/common/consts.MaxMatchSetLen_=2048'`
(replace `2048` with your chosen value). The make targets set this automatically.

`make ebpf`, `make test`, `make ebpf-test` and `make ebpf-audit` propagate the same
settings. Rebuild and restart the daemon to create maps at the new sizes;
configuration reload does not resize maps. Protocol/ABI constants and singleton
scratch-map dimensions are not general-purpose capacity settings.

See [DNS retention](../configuration/dns.md) for the userspace registry, kernel
candidate selection and the effect of omitted IPs on domain capture.

## External plugins

Add one `type:Go/import/path` line per plugin to
[`plugins.cfg`](../../../plugins.cfg), then run `make` in dae.
Each package exports `Plugin` (`plugin.Definition` with `Setup` and optional `Validate`/`Commands`); the output binary is `./dae`. `Validate` enables early static configuration checks before network and resource preparation. For example:

```text
surge:github.com/daeuniverse/dae/component/mitm/surge
bilijump:example.com/dae-mitm-bilijump
demo:example.com/dae-mitm-demo
```

Blank lines and `#` comments are allowed. Types must be unique CLI names (`[a-z][a-z0-9_-]*`); `ca`, `status` and `help` are reserved. An empty file
selects no types. Runtime instances and order belong to `plugins {}`.

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

`make` and `make test` regenerate `cmd/plugins_generated.go` automatically.
`make plugins` only refreshes that table; run it before direct `go build` after
editing the cfg. The generated file is kept in source control for direct builds.
See [instance configuration](../../zh/configuration/mitm-plugins.md) and the
[plugin API](../../../component/plugin/README.md). DNS plugin examples and migration are in [DNS configuration](../configuration/dns.md).

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
