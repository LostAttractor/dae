#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Install the release cross-compiler from a checksum-pinned official archive.
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 INSTALL_DIRECTORY" >&2
    exit 2
fi
# This checksum-pinned snapshot supplies Clang 23.1.2 and target musl libraries.
# TODO: Check new stable Zig releases and replace this snapshot once they bundle
# Clang 23 or newer. Update the archive URL, both host checksums and build docs,
# then rerun target smoke tests, including the MIPS64 QuickJS Atomics64 regression.
version=0.18.0-dev.146+35accc06e
case "$(uname -s):$(uname -m)" in
    Linux:x86_64)
        host=x86_64
        sha256=1061dbb921f62b67765810609a80c17fa69eeced9f21e9a7e0d06b4e0d7a3715
        ;;
    Linux:aarch64)
        host=aarch64
        sha256=09251ef727afa183aabb904bf70300614de58963ad70329c9e3ecda03ebdb949
        ;;
    *) echo "ERROR: this installer requires Linux x86_64 or aarch64; install Zig $version for your host and set DAE_ZIG" >&2; exit 1 ;;
esac
name=zig-$host-linux-$version
mkdir -p "$1"
directory=$(cd "$1" && pwd)
archive=$(mktemp "$directory/zig-download.XXXXXX")
trap 'rm -f "$archive"' EXIT HUP INT TERM
curl --fail --show-error --location --retry 3 \
    "https://ziglang.org/builds/$name.tar.xz" -o "$archive"
printf '%s  %s\n' "$sha256" "$archive" | sha256sum -c - >&2
tar -xJf "$archive" -C "$directory"
[ "$("$directory/$name/zig" version)" = "$version" ]
printf '%s\n' "$directory/$name/zig"
