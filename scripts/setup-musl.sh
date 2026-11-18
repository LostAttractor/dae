#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Install the target selected by Go and print an executable suitable for CC.
set -euo pipefail
die() { echo "ERROR: $*" >&2; exit 1; }
[[ $# == 1 ]] || die "usage: $0 INSTALL_DIRECTORY"
scripts=$(cd "$(dirname "$0")" && pwd)
host=$(uname -sm)
case "$host" in
    'Linux x86_64'|'Linux aarch64') ;;
    *) die "unsupported build host $host; supply your own target musl CC" ;;
esac
arch=${GOARCH:-$(go env GOARCH)}
flags=()
case "$arch" in
    amd64) triple=x86_64-unknown-linux-musl ;;
    386) triple=i686-unknown-linux-musl ;;
    arm64) triple=aarch64-unknown-linux-musl ;;
    loong64) triple=loongarch64-unknown-linux-musl ;;
    ppc64le) triple=powerpc64le-unknown-linux-musl ;;
    riscv64) triple=riscv64-unknown-linux-musl ;;
    arm)
        arm=${GOARM:-7}
        case "$arm" in
            5|[567],softfloat) float=soft; triple='arm-unknown-linux-musleabi' ;;
            [67]|[567],hardfloat) float=hard; triple='arm-unknown-linux-musleabihf' ;;
            *) die "unsupported GOARM=$arm" ;;
        esac
        case "${arm%%,*}" in
            5) flags=(-march=armv5te -mfpu=vfp) ;;
            6) flags=(-march=armv6 -mfpu=vfp) ;;
            7) flags=(-march=armv7-a -mfpu=vfpv3-d16) ;;
        esac
        flags+=("-mfloat-abi=$float")
        ;;
    mipsle)
        case "${GOMIPS:-hardfloat}" in
            hardfloat) triple=mipsel-unknown-linux-musl; flags=(-march=mips32 -mhard-float) ;;
            softfloat) triple=mipsel-unknown-linux-muslsf; flags=(-march=mips32 -msoft-float) ;;
            *) die "unsupported GOMIPS=$GOMIPS" ;;
        esac
        ;;
    mips64le)
        triple=mips64el-unknown-linux-musl
        case "${GOMIPS64:-hardfloat}" in
            hardfloat|softfloat) ;;
            *) die "unsupported GOMIPS64=$GOMIPS64" ;;
        esac
        flags=(-march=mips64 -mabi=64 -mhard-float)
        ;;
    *) die "no release musl toolchain for GOARCH=$arch" ;;
esac

release=20261001
mkdir -p "$1"
directory=$(cd "$1" && pwd)
# Each install is independent, including simultaneous builds for different ARM ABIs.
install=$(mktemp -d "$directory/$triple.XXXXXXXX")
archive=$triple.tar.xz
cleanup() {
    if (( $? == 0 )); then
        rm -f -- "$install/$archive"
    else
        # The upstream archives contain read-only directories.
        chmod -R u+w -- "$install" && rm -rf -- "$install"
    fi
}
trap cleanup EXIT
curl --fail --show-error --location --retry 3 \
    "https://github.com/cross-tools/musl-cross/releases/download/$release/$archive" -o "$install/$archive"
(cd "$install" && awk -v file="$archive" '$2 == file' "$scripts/musl-cross.sha256" | sha256sum -c - >&2)
if [[ $arch == mips64le && ${GOMIPS64:-hardfloat} == softfloat ]]; then
    bash "$scripts/setup-mips64-softfloat.sh" "$install" "$install/$archive"
    exit
fi
tar --no-same-owner -xJf "$install/$archive" -C "$install"
kit=$install/$triple
sysroot=$kit/$triple/sysroot
# GNU ld can otherwise report a mixed MIPS floating-point ABI and still exit 0.
if [[ $arch == mipsle || $arch == mips64le ]]; then flags+=('-Wl,--fatal-warnings'); fi
gcc=$kit/bin/$triple-gcc
if [[ $host == 'Linux x86_64' ]] && "$gcc" -dumpmachine >/dev/null 2>&1; then
    cc=("$gcc")
else
    # Use only target data from the archive; never execute its x86 host tools.
    cc=("${CLANG:-clang-23}" "-Qunused-arguments" "--target=$triple" "--sysroot=$sysroot"
        "--gcc-install-dir=$kit/lib/gcc/$triple/16.2.0" "-fuse-ld=lld")
    if [[ $arch == mipsle || $arch == mips64le ]]; then
        # LLD merges .MIPS.abiflags but concatenates GCC's redundant .gnu.attributes.
        echo 'SECTIONS { /DISCARD/ : { *(.gnu.attributes) } } INSERT AFTER .text;' > "$install/mips.ld"
        flags+=("-Wl,-T,$install/mips.ld")
        [[ $arch != mipsle ]] || flags+=(-latomic)
    fi
fi
{
    printf '#!/usr/bin/env bash\nexec'
    printf ' %q' "${cc[@]}" "${flags[@]}"
    printf ' "$@"\n'
} > "$install/cc"
chmod +x "$install/cc"
"$install/cc" --version >&2
printf '%s\n' "$install/cc"
