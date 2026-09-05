# SPDX-License-Identifier: AGPL-3.0-only
# Native-host tools generate eBPF; the C compiler targets static Linux musl.
{ pkgs ? import <nixpkgs> {} }:

let
  musl = pkgs.pkgsMusl;
in pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    go_1_27
    git
    gnumake
    binutils
    llvmPackages_latest.clang-unwrapped
    llvmPackages_latest.llvm
    llvmPackages_latest.bintools
    musl.stdenv.cc
  ];
  CGO_ENABLED = "1";
  CC = "${musl.stdenv.cc}/bin/${musl.stdenv.cc.targetPrefix}cc";
  CLANG = "${pkgs.llvmPackages_latest.clang-unwrapped}/bin/clang";
  STRIP = "${pkgs.llvmPackages_latest.llvm}/bin/llvm-strip";
  STATIC = "y";
  # stdenv's setup hooks may overwrite CC and STRIP after derivation attributes
  # are exported. Select the host eBPF tools and musl compiler after those hooks.
  shellHook = ''
    export CC="${musl.stdenv.cc}/bin/${musl.stdenv.cc.targetPrefix}cc"
    export CLANG="${pkgs.llvmPackages_latest.clang-unwrapped}/bin/clang"
    export STRIP="${pkgs.llvmPackages_latest.llvm}/bin/llvm-strip"
  '';
  hardeningDisable = [ "zerocallusedregs" "stackprotector" "stackclashprotection" ];
}
