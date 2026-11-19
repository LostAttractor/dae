#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# CI/container installer. Local builds may use an existing host LLVM installation.
set -euo pipefail
if [[ $# != 1 ]]; then
    echo "usage: $0 LLVM_MAJOR" >&2
    exit 2
fi
version=$1
case "$version" in
    15|16|17|18|19|20|21|22|23) ;;
    *) echo "ERROR: supported LLVM majors are 15 through 23" >&2; exit 1 ;;
esac
# shellcheck source=/dev/null
source /etc/os-release
if [[ "$ID:$VERSION_ID" != ubuntu:24.04 || "$EUID" != 0 ]]; then
    echo "ERROR: this installer requires root on Ubuntu 24.04" >&2
    exit 1
fi
packages=("clang-$version" "llvm-$version" "lld-$version")
if ! dpkg-query -W -f='${db:Status-Status}\n' "${packages[@]}" 2>/dev/null | awk '$0 != "installed" { exit 1 }'; then
    apt=(apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20)
    "${apt[@]}" update -y
    "${apt[@]}" install -y ca-certificates curl gnupg
    if (( version >= 17 )); then
        key=$(mktemp)
        trap 'rm -f "$key"' EXIT
        curl --fail --show-error --location --connect-timeout 15 --max-time 30 --retry 3 --retry-max-time 60 \
            https://apt.llvm.org/llvm-snapshot.gpg.key -o "$key"
        fingerprint=$(gpg --show-keys --with-colons "$key" | awk -F: '$1 == "fpr" {print $10; exit}')
        if [[ "$fingerprint" != 6084F3CF814B57C1CF12EFD515CF4D18AF4F7421 ]]; then
            echo "ERROR: unexpected LLVM signing key fingerprint: $fingerprint" >&2
            exit 1
        fi
        install -m 644 "$key" /usr/share/keyrings/dae-llvm.asc
        suite="llvm-toolchain-noble-$version"
        printf 'deb [signed-by=/usr/share/keyrings/dae-llvm.asc] https://apt.llvm.org/noble/ %s main\n' "$suite" \
            > /etc/apt/sources.list.d/dae-llvm.list
        "${apt[@]}" update -y
    fi
    "${apt[@]}" install -y "${packages[@]}"
fi
"clang-$version" --version
"llvm-strip-$version" --version
