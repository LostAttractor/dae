#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

# Internal to setup-musl.sh: a fresh install directory and the verified kit.
install=${1:?missing install directory}
kit=${2:?missing musl-cross archive}
exec 3>&1 1>&2

clang=$(command -v "${CLANG:-clang-23}") || { echo "Set CLANG to host Clang 23 or newer" >&2; exit 1; }
clang_version=$("$clang" -dumpversion)
clang_major=${clang_version%%.*}
(( clang_major >= 23 )) || { echo "MIPS64 QuickJS requires Clang 23 or newer" >&2; exit 1; }
PATH="$(dirname "$(realpath "$clang")"):$PATH"
llvm_tool() {
    command -v "$1-$clang_major" || command -v "$1" || { echo "Missing LLVM tool: $1" >&2; return 1; }
}
lld=$(llvm_tool ld.lld)
ar=$(llvm_tool llvm-ar)
ranlib=$(llvm_tool llvm-ranlib)
jobs=${JOBS:-$(getconf _NPROCESSORS_ONLN)}
unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH

stage=$(mktemp -d "$install/build.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
sysroot=$install/sysroot
resource=$install/clang-resource
mkdir -p "$sysroot/include" "$resource"
# Only Linux UAPI headers are shared; no hard-float object belongs in this sysroot.
triple=mips64el-unknown-linux-musl
tar --no-same-owner -xJf "$kit" -C "$sysroot" --strip-components=4 \
    "$triple/$triple/sysroot/usr/include"/{asm,asm-generic,linux,drm,misc,mtd,rdma,sound,video,xen}

fetch() {
    local url=$1 sha=$2 name=${1##*/}
    archive=$stage/$name
    curl -fsSL --retry 3 "$url" -o "$archive"
    printf '%s  %s\n' "$sha" "$archive" | sha256sum -c -
}

fetch https://musl.libc.org/releases/musl-1.2.6.tar.gz \
    d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a
tar -xzf "$archive" -C "$stage"
fetch https://github.com/llvm/llvm-project/releases/download/llvmorg-23.1.3/llvm-project-23.1.3.src.tar.xz \
    c44186a7762ed28954be72e5ff6df9808e0779d4f1bf014ecc4e7e211d31ee34
llvm='llvm-project-23.1.3.src'
tar -xJf "$archive" -C "$stage" "$llvm/cmake" "$llvm/compiler-rt" "$llvm/third-party"

target=mips64el-unknown-linux-muslabi64
abi='-march=mips64 -mabi=64 -msoft-float'
mkdir "$stage/musl-build"
(
    cd "$stage/musl-build"
    CC="$clang --target=$target --ld-path=$lld" AR="$ar" RANLIB="$ranlib" \
        CFLAGS="$abi -O2 -g0" LIBCC='' "$stage/musl-1.2.6/configure" \
        --target="$target" --prefix= --disable-shared
    make -s DESTDIR="$sysroot" install-headers
)

cmake -G 'Unix Makefiles' -S "$stage/$llvm/compiler-rt/lib/builtins" -B "$stage/builtins" \
    -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=mips64el \
    -DCMAKE_C_COMPILER="$clang" -DCMAKE_CXX_COMPILER="$clang" -DCMAKE_ASM_COMPILER="$clang" \
    -DCMAKE_C_COMPILER_TARGET="$target" -DCMAKE_CXX_COMPILER_TARGET="$target" \
    -DCMAKE_ASM_COMPILER_TARGET="$target" -DCMAKE_SYSROOT="$sysroot" \
    -DCMAKE_C_FLAGS="$abi" -DCMAKE_CXX_FLAGS="$abi" -DCMAKE_ASM_FLAGS="$abi" \
    -DCMAKE_AR="$ar" -DCMAKE_RANLIB="$ranlib" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$resource" \
    -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON -DCOMPILER_RT_CRT_USE_EH_FRAME_REGISTRY=OFF \
    -DLLVM_RUNTIMES_BUILD=ON -DLLVM_ENABLE_PER_TARGET_RUNTIME_DIR=ON
cmake --build "$stage/builtins" --parallel "$jobs"
cmake --install "$stage/builtins"
ln -s "$("$clang" -print-resource-dir)/include" "$resource/include"
make -s -C "$stage/musl-build" -j "$jobs" DESTDIR="$sysroot" install

driver=$install/cc
{
    printf '#!/usr/bin/env bash\n'
    printf 'clang=%q\nlld=%q\ntarget=%q\n' "$clang" "$lld" "$target"
    cat <<'EOF'
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
# Keep DWARF for cgo's compile probes; LLD cannot merge Go and Clang MIPS debug sections.
exec "$clang" "$@" -Qunused-arguments "--target=$target" -march=mips64 -mabi=64 -msoft-float \
    --sysroot="$root/sysroot" --gcc-toolchain="$root/sysroot" --ld-path="$lld" \
    -resource-dir "$root/clang-resource" --rtlib=compiler-rt --unwindlib=none \
    -B"$root/sysroot/lib/" -L"$root/sysroot/lib" -static -Wl,--strip-debug
EOF
} > "$driver"
chmod +x "$driver"

cat <<'EOF' | "$driver" -Wl,--fatal-warnings -x c - -o "$stage/smoke"
#include <asm/unistd.h>
#include <linux/types.h>
#include <stdio.h>
#if !defined(__mips_soft_float) || !defined(__MIPSEL__) || _MIPS_SIM != _ABI64 || __NR_Linux != 5000
#error Unexpected MIPS ABI
#endif
int main(void) {
    volatile double a = 1.5, b = 2.5;
    return printf("%.2f\n", a * b) < 0;
}
EOF
LC_ALL=C readelf -hAl "$stage/smoke" | awk '
    /Class:.*ELF64/ { elf64=1 }
    /Data:.*little endian/ { le=1 }
    /^ISA: MIPS64$/ { isa=1 }
    /^FP ABI: Soft float$/ { soft=1 }
    /INTERP|DYNAMIC/ { dynamic=1 }
    END { exit !(elf64 && le && isa && soft && !dynamic) }
' || { echo "Unexpected ISA, ABI or dynamic linkage in smoke executable" >&2; exit 1; }
printf '%s\n' "$driver" >&3
