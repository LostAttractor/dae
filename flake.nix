{
  description = "dae, a Linux high-performance transparent proxy solution based on eBPF";

  inputs = {
    # Kernel headers and the Go forks are pinned as submodules.
    self.submodules = true;
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  };

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
      # Matches the Makefile's unstable-<date>.r<count>.<commit> format.
      version =
        "unstable-${builtins.substring 0 8 self.lastModifiedDate}"
        + lib.optionalString (self ? revCount) ".r${toString self.revCount}"
        + ".${self.shortRev or self.dirtyShortRev or "nogit"}";
    in
    {
      packages = forAllSystems (system: rec {
        dae = nixpkgs.legacyPackages.${system}.callPackage ./nix/package.nix { inherit version; };
        default = dae;
      });

      nixosModules.dae = import ./nix/module.nix self;
      nixosModules.default = self.nixosModules.dae;

      checks = forAllSystems (system: {
        nixos = nixpkgs.legacyPackages.${system}.testers.runNixOSTest (import ./nix/test.nix self);
      });
    };
}
