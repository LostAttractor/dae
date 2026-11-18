#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Run a release smoke test natively or with qemu-user. The executable is static.
set -eu

if [ "$#" -eq 0 ]; then
    echo "usage: $0 EXECUTABLE [ARGUMENT...]" >&2
    exit 2
fi
arch=${GOARCH:-$(go env GOARCH)}
if [ "$arch" = arm ]; then
    arm=${GOARM:-7}
    case "$arm" in
        5|5,softfloat|5,hardfloat) cpu=arm926 ;;
        6|6,softfloat|6,hardfloat) cpu=arm1176 ;;
        7|7,softfloat|7,hardfloat) cpu=cortex-a8 ;;
        *) echo "ERROR: unsupported GOARM=$arm" >&2; exit 1 ;;
    esac
fi
if [ "$arch" = "$(go env GOHOSTARCH)" ] && \
    { [ "$arch" != amd64 ] || [ "${GOAMD64:-v1}" = v1 ]; }; then
    exec "$@"
fi
# QEMU user mode can make musl's initial-thread stack-size probe repeatedly
# fail mremap. The test-only harness pins that initial thread and runs tests on
# real pthread workers with known stack bounds. Native runs keep normal startup.
export DAE_QEMU_TEST_WORKER=1
case "$arch" in
    amd64) exec qemu-x86_64 -cpu max "$@" ;;
    386) exec qemu-i386 "$@" ;;
    arm) exec qemu-arm -cpu "$cpu" "$@" ;;
    arm64) exec qemu-aarch64 "$@" ;;
    mipsle) exec qemu-mipsel "$@" ;;
    mips64le)
        if [ "${GOMIPS64:-hardfloat}" = softfloat ]; then
            exec qemu-mips64el -cpu 5Kc "$@"
        fi
        exec qemu-mips64el "$@"
        ;;
    # Go's RVA23 profile uses vector, Zfa, and Zicond instructions. QEMU's
    # default rv64 model does not enable every supported extension.
    riscv64) exec qemu-riscv64 -cpu max "$@" ;;
    loong64) exec qemu-loongarch64 "$@" ;;
    ppc64le) exec qemu-ppc64le "$@" ;;
    *) echo "ERROR: no smoke-test runner for GOARCH=$arch" >&2; exit 1 ;;
esac
