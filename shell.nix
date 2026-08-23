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
    go_1_27
    llvmPackages_latest.clang-unwrapped
    llvmPackages_latest.llvm
  ];
}
