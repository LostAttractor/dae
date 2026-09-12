# SPDX-License-Identifier: AGPL-3.0-only
# Native-host tools generate eBPF; the C compiler targets static Linux musl.
{ pkgs ? import <nixpkgs> {} }:

import ./shell.nix {
  inherit pkgs;
  useMusl = true;
}
