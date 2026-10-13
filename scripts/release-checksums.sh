#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
if [[ $# != 1 ]]; then
    echo "usage: $0 BINARY" >&2
    exit 2
fi
file=$(basename -- "$1")
cd -- "$(dirname -- "$1")"
if [[ ! -f "$file" ]]; then
    echo "Binary not found: $file" >&2
    exit 1
fi
{
    printf '%s  md5\n' "$(md5sum "$file")"
    printf '%s  sha1\n' "$(sha1sum "$file")"
    printf '%s  sha256\n' "$(sha256sum "$file")"
    printf '%s  sha512\n' "$(sha512sum "$file")"
} > "$file.dgst"
