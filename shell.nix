{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  hardeningDisable = [
    "zerocallusedregs"
    "stackprotector"
    "stackclashprotection"
  ];

  nativeBuildInputs = with pkgs; [
    llvmPackages_latest.bintools
  ];

  buildInputs = with pkgs; [
    bpftools
    go
    llvmPackages_latest.clang-unwrapped
    llvmPackages_latest.llvm
  ];
}
