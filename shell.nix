{ pkgs ? import <nixpkgs> {}, useMusl ? false }:

let
  cCompiler = (if useMusl then pkgs.pkgsMusl else pkgs).stdenv.cc;
in pkgs.mkShell ({
  CGO_ENABLED = "1";
  # Select the target C compiler and host eBPF tools after stdenv's setup hooks.
  shellHook = ''
    export CC="${cCompiler}/bin/${cCompiler.targetPrefix}cc"
    export CLANG="${pkgs.llvmPackages_latest.clang-unwrapped}/bin/clang"
    export STRIP="${pkgs.llvmPackages_latest.llvm}/bin/llvm-strip"
  '';
  hardeningDisable = [
    "zerocallusedregs"
    "stackprotector"
    "stackclashprotection"
  ];

  nativeBuildInputs = with pkgs; [
    git
    gnumake
    nodejs_22
    binutils
    bpftools
    go_1_27
    llvmPackages_latest.clang-unwrapped
    llvmPackages_latest.llvm
    llvmPackages_latest.bintools
    cCompiler
  ];

  # Search static archives after the wrapper's dynamic libc paths. Adding them
  # to buildInputs would inject -L flags that also override dynamic linking.
  LIBRARY_PATH = pkgs.lib.optionalString (!useMusl) "${pkgs.glibc.static}/lib";
} // pkgs.lib.optionalAttrs useMusl {
  STATIC = "y";
})
