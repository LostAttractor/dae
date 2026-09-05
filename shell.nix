{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  CGO_ENABLED = "1";
  CLANG = "${pkgs.llvmPackages_latest.clang-unwrapped}/bin/clang";
  STRIP = "${pkgs.llvmPackages_latest.llvm}/bin/llvm-strip";
  shellHook = ''
    export CC="${pkgs.stdenv.cc}/bin/cc"
    export CLANG="${pkgs.llvmPackages_latest.clang-unwrapped}/bin/clang"
    export STRIP="${pkgs.llvmPackages_latest.llvm}/bin/llvm-strip"
  '';
  hardeningDisable = [
    "zerocallusedregs"
    "stackprotector"
    "stackclashprotection"
  ];

  nativeBuildInputs = with pkgs; [
    llvmPackages_latest.bintools
    stdenv.cc
  ];

  buildInputs = with pkgs; [
    bpftools
    go_1_27
    llvmPackages_latest.clang-unwrapped
    llvmPackages_latest.llvm
  ];
}
