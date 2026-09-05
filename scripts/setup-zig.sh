#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Install the release cross-compiler from a checksum-pinned official archive.
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 INSTALL_DIRECTORY" >&2
    exit 2
fi
if [ "$(uname -s):$(uname -m)" != "Linux:x86_64" ]; then
    echo "ERROR: this installer requires Linux x86_64; install Zig 0.15.2 for your host and set DAE_ZIG to its executable" >&2
    exit 1
fi
version=0.15.2
name=zig-x86_64-linux-$version
sha256=02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239
mkdir -p "$1"
directory=$(cd "$1" && pwd)
archive=$(mktemp "$directory/zig-download.XXXXXX")
trap 'rm -f "$archive"' EXIT HUP INT TERM
curl --fail --show-error --location --retry 3 \
    "https://ziglang.org/download/$version/$name.tar.xz" -o "$archive"
printf '%s  %s\n' "$sha256" "$archive" | sha256sum -c - >&2
tar -xJf "$archive" -C "$directory"
[ "$("$directory/$name/zig" version)" = "$version" ]
printf '%s\n' "$directory/$name/zig"
