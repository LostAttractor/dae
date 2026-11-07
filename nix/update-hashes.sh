#!/usr/bin/env bash
# Replace stale fixed-output dependency hashes in nix/package.nix.
set -euo pipefail
cd "$(dirname "$0")/.."

for dep in goModules pnpmDeps; do
	if log=$(nix build --no-link ".#dae.$dep" 2>&1); then
		continue
	fi
	specified=$(sed -n 's/^ *specified: *//p' <<<"$log")
	got=$(sed -n 's/^ *got: *//p' <<<"$log")
	if [ -z "$got" ] || ! grep -qF "\"$specified\"" nix/package.nix; then
		printf '%s\n' "$log" >&2
		exit 1
	fi
	sed -i "s|\"$specified\"|\"$got\"|" nix/package.nix
	echo "$dep: $got"
done
