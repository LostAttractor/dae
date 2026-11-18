#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu
export LC_ALL=C

check_abi() {
    case "${GOARCH:-}" in
        mipsle) class=32; float=${GOMIPS:-hardfloat}; abi=o32 ;;
        mips64le) class=64; float=${GOMIPS64:-hardfloat}; abi=n64 ;;
        arm)
            class=32
            arm=${GOARM:-7}
            case "$arm" in
                5|[567],softfloat) float=softfloat ;;
                [67]|[567],hardfloat) float=hardfloat ;;
                *) echo "ERROR: unsupported GOARM=$arm" >&2; return 1 ;;
            esac
            abi=EABIv5
            ;;
        *) return 0 ;;
    esac
    case "$float" in
        softfloat) fp='Soft float'; arm_flags='soft-float ABI' ;;
        hardfloat) fp='Hard float (double precision)'; arm_flags='hard-float ABI' ;;
        *) echo "ERROR: unsupported floating-point mode $float for GOARCH=$GOARCH" >&2; return 1 ;;
    esac

    header=$(readelf -hW "$1") || return 1
    if printf '%s\n' "$header" | grep -Eq "^[[:space:]]*Class:[[:space:]]+ELF$class$" &&
        printf '%s\n' "$header" | grep -Eq '^[[:space:]]*Data:.*little endian$'; then
        case "$GOARCH" in
            arm)
                if printf '%s\n' "$header" | grep -Eq '^[[:space:]]*Machine:[[:space:]]+ARM$' &&
                    printf '%s\n' "$header" | grep -Eq "^[[:space:]]*Flags:.*Version5 EABI, $arm_flags$"; then
                    return 0
                fi
                ;;
            mipsle|mips64le)
                if printf '%s\n' "$header" | grep -Eq '^[[:space:]]*Machine:[[:space:]]+MIPS '; then
                    flags=$(printf '%s\n' "$header" | awk '/^[[:space:]]*Flags:/ {sub(/,$/, "", $2); print $2}')
                    attrs=$(readelf -AW "$1") || return 1
                    # N64 uses ELF64 with no ABI bits; O32 sets EF_MIPS_ABI_O32.
                    # Also exclude ABI2 (N32), ON32, and 32-bit mode on ELF64.
                    case "$abi:$((flags & 0xf160))" in
                        o32:4096|o32:4352|n64:0)
                            if printf '%s\n' "$attrs" | grep -Fx "FP ABI: $fp" >/dev/null; then
                                return 0
                            fi
                            ;;
                    esac
                fi
                ;;
        esac
    fi
    echo "ERROR: $1 does not match GOARCH=$GOARCH (little-endian ELF$class, $abi, $float)" >&2
    return 1
}

if [ "$#" -eq 0 ]; then
    echo "usage: $0 ELF_FILE..." >&2
    exit 2
fi
for artifact in "$@"; do
    # readelf works on every release architecture without executing the file.
    headers=$(readelf -lW "$artifact")
    dynamic=$(readelf -dW "$artifact")
    if printf '%s\n' "$headers" | grep -q 'INTERP'; then
        echo "ERROR: $artifact has a dynamic ELF interpreter" >&2
        exit 1
    fi
    if printf '%s\n' "$dynamic" | grep -q '(NEEDED)'; then
        echo "ERROR: $artifact has shared-library dependencies" >&2
        exit 1
    fi
    check_abi "$artifact"
    printf '%s\n' "$artifact: static ELF verified"
done
