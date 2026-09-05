#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

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
    printf '%s\n' "$artifact: static ELF verified"
done
