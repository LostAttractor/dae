# Build Guide

## Build dependencies

- Go 1.27.2 or later, Make, and Git. QuickJS builds also need a C compiler with libc development headers.
- Clang with the BPF backend and matching LLVM tools for eBPF generation. Clang 15+ is recommended; older versions emit a warning. CI tests Clang majors 15–23; release builds use Clang 23.
- Node.js 22.13+ and pnpm to bundle the embedded Web interface and Recharts charts.
- A target C compiler and sysroot when cross-compiling with cgo.

The root documentation tools and `web/` share a pnpm workspace and root lockfile.
The Nix shell provides Corepack's pnpm shim. On other systems with Corepack
installed, run `corepack enable pnpm`; it uses the version pinned in the root
`package.json`. Make installs dependencies with `pnpm install --frozen-lockfile`.

Core, CLI, outbound protocols, the config parser and first-party plugins share
the root `go.mod` and `go.sum`. They are developed and released together.
`pkg/outbound` contains protocol and dialer implementations; `plugins/` contains
Surge and the optional DNS cache/router. Normal Go development needs no `go.work`.

Third-party forks remain pinned as Git submodules: `third_party/quic-go`,
`third_party/quickjs-go`, and the eBPF headers in `kern/headers`. The root
`go.mod` resolves the two Go forks to these local copies.

The Surge plugin's default QuickJS-NG backend is compiled from C sources in `third_party/quickjs-go`, a fork of [buke/quickjs-go](https://github.com/buke/quickjs-go) containing the binding integration fixes. This backend requires `CGO_ENABLED=1`, including when Surge is compiled in but disabled in configuration. The Node.js backend builds without cgo. `netgo` and `osusergo` keep Go's DNS and user lookup implementations.

```sh
git clone --recurse-submodules https://github.com/daeuniverse/dae.git
cd dae
make
```

After switching revisions, run `git submodule update --init --recursive` to use
the pinned dependencies. `make` initializes missing submodules automatically.
Initialize them before running Go commands directly or building a Docker image;
the Docker build context must contain their source files.

On NixOS, load the development tools with direnv (`direnv allow`), then run `make`.
Without direnv, `nix-shell --run make` supplies the same environment. A regular
build may link to the host's libc; it is intended for that system or an
appropriately packaged Nix closure.

`CC` selects the compiler for QuickJS/cgo. `CLANG` selects the host Clang used for eBPF. The Makefile's `CFLAGS` belong to eBPF; use `CGO_CFLAGS` for additional cgo compiler options. Keep these toolchains separate when cross-compiling.

## Compiler requirements and CI coverage

The eBPF and cgo compilers have separate version and target requirements:

| Component | Compiler selection | Requirement |
| --- | --- | --- |
| eBPF programs and tracing | `CLANG`, `STRIP`, `LLVM_OBJDUMP` | Host Clang with the BPF backend and matching LLVM tools; 15+ recommended |
| QuickJS/cgo | `CC` | Target C compiler, libc headers and libraries; static builds need target static archives |
| QuickJS/cgo on MIPS64 | `CC` | Clang 23+ when using a Clang-based compiler; older backends can miscompile BigInt atomic operations |
| Node.js backend | `SURGE_RUNTIME=nodejs` | No C compiler for this backend; eBPF still needs host Clang |

The common kernel header warns when eBPF is compiled with Clang older than 15,
including direct `go generate` builds. This warning remains non-fatal under
the default `-Werror`; older compilers may still fail on unsupported code.
The MIPS64 minimum is enforced in the QuickJS binding,
including direct `go build` and `go test` commands. Selecting a newer eBPF
`CLANG` does not update the compiler behind `CC` or `zig cc`.

CI's `setup-llvm` action installs Clang 23 by default and exports matching
`CLANG`, `STRIP` and `LLVM_OBJDUMP` tools. Native Go and AddressSanitizer tests
select that compiler through `CC`; `setup-musl` instead configures the pinned
Zig cross-compiler for static builds.

CI checks these separate scopes:

| Workflow | Execution scope |
| --- | --- |
| Go Test | Native Linux x86_64: `make test` (`go test ./...`) for QuickJS and Node with default and all-plugin selections, package boundaries, standalone API clients, the API server without cgo, backend isolation, pinned QuickJS/QUIC contracts, generated parser consistency and standalone Web tests. |
| BPF Test | Clang 15–23 test executables are built on Ubuntu 24.04 and run natively on one Ubuntu 26.04 x86_64 runner, including BIG TCP and live bridge metadata. This is a compiler matrix, not a target-CPU or kernel-version matrix. |
| eBPF Audit | Clang 23 objects are loaded and inspected in a Linux 6.18 VM; verifier and dump artifacts are retained. |
| Kernel Test | Linux x86_64, Linux 6.18 VM: startup/verifier, netkit/veth and TCX integration, splice, and LAN/WAN IPv4/IPv6 TCP/UDP proxy paths. |
| Musl Static Test | Native x86_64: QuickJS AddressSanitizer tests; musl-linked daemon and full Surge/QuickJS package tests execute in Alpine without host shared libraries. |
| PR/Next/daily/release builds | Each release target: static ELF checks, daemon `--version`, and five QuickJS smoke tests, executed natively or through QEMU user mode. |
| Docker | Build and static-link verification for `arm/v7`, `arm64`, `amd64` and `386`; this does not run the daemon's network integration suite on those architectures. |

The release matrix covers `amd64` v1/v2/v3, `386`, `arm64`, ARM 5/6/7,
`mipsle`, `mips64le`, `ppc64le`, `loong64`, and RISC-V RVA20/RVA22/RVA23.
The five target smoke tests exercise request rewrite,
binary/text conversion, result presence and synthetic responses,
Promises/timers, and 64-bit Atomics (including negative BigInt operands).
QEMU user-mode success does not establish eBPF verifier or network behavior
on a target device's kernel. Full Go tests and kernel integration do not run
on every release architecture, and the compiler matrix does not cover every
Clang patch release or every possible `CC` implementation.

`make ebpf-test-build` generates BPF objects and builds the static test executable
at `build/ebpf-test/kernel.test` without requiring root. `sudo make ebpf-test`
builds and runs it on the local kernel. The full suite needs an SKB test-run
interface that accepts BIG TCP packets and a configurable linear data boundary.
CI runs every compiler's executable sequentially on the Ubuntu 26.04 runner's
kernel, reports each compiler separately, and continues after a test failure
before failing the job. C fixtures load only their programs and dependencies
with fresh maps for each case.

### Distribution pipeline

Preview, Next, daily, release and prerelease builds share `seed-build.yml`.
`install/release-targets.json` defines both the compiler settings and unique
artifact name for each target. RISC-V builds use `linux-riscv64` for `rva20u64`,
`linux-riscv64_rva22u64` for `rva22u64`, and `linux-riscv64_rva23u64` for `rva23u64`.

The workflow resolves the source commit and version once. Each target compiles
the daemon and runs static ELF checks and target smoke tests. Preview, Next and
daily builds upload each `dae-<target>` executable as a directly downloadable
file without a ZIP wrapper; they do not assemble distribution packages or
download runtime data.

To start a binary build manually, open **Actions → Build binaries → Run workflow**
and select a branch, or use the GitHub CLI:

```shell
gh workflow run seed-build.yml --ref next
```

Manual runs build the selected commit for every target with ordinary build
versioning and upload the same executable files. The workflow must be present
on the repository's default branch to enable
[manual runs](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).

Release and prerelease builds upload a separate `dae-<target>.dgst` file for each
executable, containing its MD5, SHA1, SHA256 and SHA512 checksums. Each binary and
checksum file is a separate artifact named after the file, without a ZIP wrapper.
Publishing uploads those files directly as release assets after all target
builds succeed.

Download the binary for your target and make it executable, for example
`chmod +x dae-linux-x86_64`. Provide your own configuration and, if needed,
service definition. Install Geo data separately
[when the configuration references it](#optional-geo-data-files).

## Surge JavaScript runtime

`SURGE_RUNTIME` selects one backend at compile time for all Surge instances:

```sh
make SURGE_RUNTIME=quickjs # Default; CGO_ENABLED defaults to 1
make SURGE_RUNTIME=nodejs  # CGO_ENABLED defaults to 0
```

The Node build adds the `surge_nodejs` Go build tag and excludes the QuickJS
adapter and C sources. It skips initialization of the QuickJS submodule and
requires Node.js 22.13+ on the deployment host. The QuickJS build excludes the
Node adapter and needs no Node.js installation to run scripts. Node.js and pnpm
are still used to bundle the Web interface during either build.

There is no runtime configuration switch. Node builds accept `node_path` to
locate the executable. Scripts can inspect `$environment['dae-runtime']`.
See the [Surge configuration](../../zh/configuration/surge-module.md#nodejs-后端)
for process lifetime, API scope and memory limits.

Root `go.mod` records dependencies for both build variants; the selected build
only compiles its own dependency graph. The daemon core has no QuickJS import
and does not impose a cgo requirement when plugins do not use it. Other external
plugins may impose their own native dependencies.

## Static builds

With cgo enabled, `STATIC=y` selects external static linking and requests a 2 MiB thread stack.
The libc is selected by `CC`, whose target sysroot must supply static archives.
`STATIC=y` does not switch the compiler or libc.

With `CGO_ENABLED=0`, including the default Node build, Go links the daemon
without an external C linker; `STATIC=y` does not add cgo linker flags.

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

Release cgo builds use the Zig development snapshot
`0.18.0-dev.146+35accc06e`, which supplies Clang 23.1.2 and target musl headers,
startup objects and libraries. Its version and archive SHA256 are fixed in
`scripts/setup-zig.sh`. The installer runs on Linux x86_64 and aarch64;
other hosts can install the same snapshot and set `DAE_ZIG` to its executable.
Zig is a build-time tool, not a daemon runtime dependency.

```sh
export DAE_ZIG=$(scripts/setup-zig.sh /tmp/dae-zig)
GOARCH=arm64 make STATIC=y CC="$PWD/scripts/zig-cc.sh"
scripts/check-static.sh dae

GOARCH=arm GOARM=7 make STATIC=y CC="$PWD/scripts/zig-cc.sh"
GOARCH=mipsle GOMIPS=hardfloat make STATIC=y CC="$PWD/scripts/zig-cc.sh"
GOARCH=mips64le make STATIC=y CC="$PWD/scripts/zig-cc.sh"
```

The wrapper covers `amd64`, `386`, `arm64`, ARM 5/6/7, `mipsle`, `mips64le`,
`riscv64`, `loong64` and `ppc64le`. Set the correct ARM/MIPS floating-point ABI
for the target CPU; big-endian targets are unsupported.

ARMv5 also needs `gcc-arm-linux-gnueabi` (Debian/Ubuntu), or a target `libgcc.a`
supplied through `DAE_ARM_LIBGCC`, for static atomic support. The wrapper retains
musl as libc. Keep `-w` when linking MIPS test executables with LLD to avoid
incompatible Go/C DWARF sections.

You can instead pass an existing target musl compiler as `CC`. Setting only
`GOARCH` is insufficient for cgo: the compiler, libc, ABI and headers must all
target that architecture. The eBPF generators run as host Go tools independently
of that compiler.

### Docker

Docker uses a host Ubuntu/Clang 23 build stage and the same Zig cross-compiler
to produce static binaries for its target platforms. Toolchain installation
is cached independently of application sources.
The final Alpine image adds only the daemon executable. Configuration files,
service files and Geo data are not included. CI publishes `linux/amd64`,
`linux/arm64`, `linux/arm/v7` and `linux/386` variants under the same image tags.
The Docker context excludes local `go.work` and `plugins.cfg` files, so it uses
the repository's default plugin selection. Pass `--build-arg VERSION=...` to
`docker build` to set the binary version; CI supplies the release tag or a
commit build version containing the commit date and SHA.

The Docker workflow publishes to `ghcr.io/<owner>/<repository>`, using the
lowercase repository name. For this fork the image is `ghcr.io/lostattractor/dae`.
It authenticates with the workflow's `GITHUB_TOKEN` and `packages: write`
permission. OCI labels identify the source repository, commit and binary version.

The workflow resolves the source commit, version and tags once, then builds each
platform in a separate matrix job with its own cache scope. All jobs check out
the same commit and push their images by digest without updating public tags.
After every build succeeds, the publication job combines those immutable
digests, verifies that all four platforms are present, and publishes the shared
multi-platform tags. A failed platform build prevents tag publication; successful
jobs retain their digest artifacts so failed jobs can be rerun independently.

The default command is `dae run -c /etc/dae/config.dae`. Create your configuration
on the host and mount it into the container; the repository's Compose file mounts
the host `/etc/dae` directory. For rules that need Geo data, you can additionally
mount the host data directory read-only:

```yaml
volumes:
  - /etc/dae:/etc/dae
  - /usr/local/share/dae:/usr/local/share/dae:ro
```

Omit the data mount when your rules do not need external data files. Arguments
after the image name are passed to `dae`; for example,
`docker run --rm ghcr.io/lostattractor/dae:next --version` prints the version.

| Build | Image tags |
| --- | --- |
| Push to the main branch `next`, or manual build of `next` | `next`, `sha-<12-character commit>` |
| Stable release | Version without the leading `v`, `latest`, `sha-<12-character commit>` |
| Prerelease | Version without the leading `v`, `sha-<12-character commit>` |
| Manual build of a `v*` tag | Version without the leading `v`, `sha-<12-character commit>`; does not update `latest` |
| Manual build of another branch | `sha-<12-character commit>` |

Release workflows call the image workflow after publishing their release assets.
The image workflow also handles releases published directly on GitHub. A release
created with `GITHUB_TOKEN` does not trigger another `release` event workflow,
so the explicit call is required. See [GitHub workflow trigger behavior](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).

GHCR package visibility is configured separately from repository visibility.
After the first publication, set the package to **Public** to allow anonymous
pulls; newly published packages are private by default. See [GitHub Container registry permissions](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).

## Running Go commands directly

The Makefile supplies these settings. When invoking Go yourself, set them explicitly:

```sh
export CGO_ENABLED=1
go test -tags=netgo,osusergo,grpcnotrace ./plugins/surge

# Node backend, without QuickJS or cgo:
CGO_ENABLED=0 go test -tags=surge_nodejs,netgo,osusergo,grpcnotrace ./plugins/surge/...
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
| `MAX_DST_MAPPING_NUM` | 262144 | Long-lived TCP forwarding state in `tcp_flow_map` |
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

The setup handoff LRU has 16384 entries, separate from long-lived TCP state.
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

First-party plugins require no additional modules. Copy
[`plugins.cfg.example`](../../../plugins.cfg.example) to `plugins.cfg` to choose
the plugins compiled into the binary. Surge is enabled by default; DNS cache and
router are commented out. Uncomment their entries in your local copy to build
and test all first-party plugins:

```sh
make
make test
make test SURGE_RUNTIME=nodejs
```

For external plugins, add one `type:Go/import/path` line per plugin to
`plugins.cfg`, then run `make` in dae.
Without a local `plugins.cfg`, the build uses the example selection.
`PLUGINS_CONFIG` selects a different file without changing the local selection.
Missing nondefault selection files fail the build. Release and container builds
use `plugins.cfg.example` with `GOWORK=off`.
Each package exports `Plugin` (`plugin.Definition` with `Configure` and optional `Commands`); the output binary is `./dae`. `Configure` parses and validates settings once before network and resource preparation, returning a factory that prepares the runtime instance. For example:

```text
surge:github.com/daeuniverse/dae/plugins/surge
bilijump:example.com/dae-mitm-bilijump
demo:example.com/dae-mitm-demo
```

Blank lines and `#` comments are allowed. Types must be unique CLI names (`[a-z][a-z0-9_-]*`); `ca`, `status` and `help` are reserved. An empty file
selects no types. Runtime instances and order belong to `plugins {}`.

For published plugins, use `go get <module>@<version>` to pin compatible
dependencies. For local examples beside dae, prepare a Go workspace from the dae
directory (use `go work use` instead of `init` if one already exists):

```sh
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

`make` and `make test` regenerate
`internal/compiledplugins/plugins_generated.go` automatically.
`make plugins` only refreshes that registry; run it before direct `go build` or
daemon tests, including on a fresh checkout. The registry belongs to the build
composition package; command and daemon code receive its definitions.
`plugins.cfg` and generated registries are ignored by Git; the example and
all-plugin configurations and generator are tracked. An existing local selection is never
overwritten by generation.
See [instance configuration](../../zh/configuration/mitm-plugins.md) and the
[plugin API](../../../component/plugin/README.md). DNS plugin examples are in [DNS configuration](../configuration/dns.md).

## Config parser generation

The grammar is `pkg/config_parser/grammar/dae_config.g4`; generated Go code and
token metadata live in `pkg/config_parser/internal/dae_config`. Commit grammar
changes and regenerated files together:

```sh
make config-parser
make config-parser-check
```

Generation needs Python 3, Java and Go, supplied by `nix-shell`. The generator
downloads ANTLR 4.13.1 into `build/tools`, verifies its pinned SHA-256 and uses
the matching Go runtime from `go.mod`. The check target generates into a
temporary directory and rejects stale output. Ordinary builds use the committed
parser and require neither Java nor the ANTLR download.

## Run

### Runtime requirements

The runtime kernel and mounts must meet the [kernel requirements](../README.md#kernel-configurations).
Check the newly built executable before starting the daemon:

```sh
sudo ./dae check-kernel
```

### Optional Geo data files

Install [geoip.dat](https://github.com/v2fly/geoip/releases/latest) only for rules
using `geoip:`, and [geosite.dat](https://github.com/v2fly/domain-list-community/releases/latest)
only for rules using `geosite:`. References in named rule sets, policies and plugin
rules also count. Unreferenced files are not loaded; plain IP/CIDR and domain rules
need neither file. `ext:` and `mmdb:` require their referenced data files instead.

If your configuration references both standard datasets, install them with:

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

After fine tuning, validate the configuration and run dae:

```shell
./dae validate -c example.dae
./dae run -c example.dae
```

> **Note**: Alternatively, you may run dae as a daemon (systemd) service. See [Run as a daemon](run-as-daemon.md) for details.
