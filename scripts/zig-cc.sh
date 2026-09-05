#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Go invokes this as CC; Zig supplies both the target compiler and musl sysroot.
set -eu

arch=${GOARCH:-$(go env GOARCH)}
cpu=baseline
case "$arch" in
    amd64) target=x86_64-linux-musl ;;
    386) target=x86-linux-musl ;;
    arm64) target=aarch64-linux-musl ;;
    arm)
        arm=${GOARM:-7}
        case "${arm%%,*}" in
            5) cpu=generic+v5te; float=softfloat ;;
            6) cpu=generic+v6+vfp2; float=hardfloat ;;
            7) cpu=generic+v7a+vfp3d16; float=hardfloat ;;
            *) echo "ERROR: unsupported GOARM=$arm" >&2; exit 1 ;;
        esac
        case "$arm" in
            *,softfloat) float=softfloat ;;
            *,hardfloat) float=hardfloat ;;
            *,*) echo "ERROR: unsupported GOARM=$arm" >&2; exit 1 ;;
        esac
        if [ "$float" = softfloat ]; then
            target=arm-linux-musleabi
        else
            target=arm-linux-musleabihf
            # ARMv5 hard-float is an explicit opt-in, like GOARM=5,hardfloat.
            [ "${arm%%,*}" != 5 ] || cpu=generic+v5te+vfp2
        fi
        ;;
    mipsle)
        cpu=mips32
        case "${GOMIPS:-hardfloat}" in
            hardfloat) target=mipsel-linux-musleabihf ;;
            softfloat) target=mipsel-linux-musleabi ;;
            *) echo "ERROR: unsupported GOMIPS=$GOMIPS" >&2; exit 1 ;;
        esac
        ;;
    mips64le)
        target=mips64el-linux-muslabi64
        cpu=mips64
        case "${GOMIPS64:-hardfloat}" in
            hardfloat) ;;
            softfloat) cpu=$cpu+soft_float ;;
            *) echo "ERROR: unsupported GOMIPS64=$GOMIPS64" >&2; exit 1 ;;
        esac
        ;;
    riscv64) target=riscv64-linux-musl ;;
    loong64) target=loongarch64-linux-musl ;;
    ppc64le) target=powerpc64le-linux-musl ;;
    *) echo "ERROR: no release musl toolchain mapping for GOARCH=$arch" >&2; exit 1 ;;
esac

# Go supplies GCC's MIPS float switches. Zig 0.15.2 does not accept
# -mhard-float there; the target ABI/CPU above already selects the same mode.
if [ "$arch" = mipsle ] || [ "$arch" = mips64le ]; then
    remaining=$#
    while [ "$remaining" -gt 0 ]; do
        argument=$1
        shift
        case "$argument" in
            -mhard-float|-msoft-float) ;;
            *) set -- "$@" "$argument" ;;
        esac
        remaining=$((remaining - 1))
    done
fi

if [ "$arch" = mips64le ]; then
    # The MIPS N64 ABI requires PIC with abicalls. Make that explicit so the
    # cgo runtime's -Werror does not reject Zig's implicit non-PIC default.
    set -- "$@" -fPIC
fi

if [ "$arch" = arm ] && [ "${arm%%,*}" = 5 ]; then
    linking=yes
    for argument do
        case "$argument" in
            -c|-E|-S|-M|-MM|-fsyntax-only|--version|-dumpversion|-dumpmachine|-print-*) linking=no ;;
        esac
    done
    if [ "$linking" = yes ]; then
        # ARMv5 has no native atomics. Zig's compiler-rt calls Linux __sync
        # helpers supplied by GCC's static support library; this does not link
        # glibc. Newer ARM ISAs do not need this additional archive.
        atomic_runtime=${DAE_ARM_LIBGCC:-}
        if [ -z "$atomic_runtime" ] && command -v arm-linux-gnueabi-gcc >/dev/null 2>&1; then
            atomic_runtime=$(arm-linux-gnueabi-gcc -print-libgcc-file-name)
        fi
        if [ ! -f "$atomic_runtime" ]; then
            echo "ERROR: ARMv5 needs gcc-arm-linux-gnueabi's static libgcc.a; install it or set DAE_ARM_LIBGCC" >&2
            exit 1
        fi
        set -- "$@" "$atomic_runtime"
    fi
fi

exec "${DAE_ZIG:-zig}" cc -target "$target" -mcpu="$cpu" "$@"
