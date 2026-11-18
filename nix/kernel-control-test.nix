self: kernelPackages: {
  name = "dae-kernel-control-${kernelPackages.kernel.version}";

  nodes.machine =
    { pkgs, ... }:
    let
      dae = self.packages.${pkgs.stdenv.hostPlatform.system}.dae;
      suite = dae.overrideAttrs (old: {
        pname = "dae-kernel-control-suite";
        postBuild = (old.postBuild or "") + ''
          # Use the package's generated plugins, BPF objects and build tags.
          export CGO_ENABLED=0
          tags="netgo,osusergo,surge_nodejs,grpcnotrace,$(cat .build_tags)"
          go test -c -tags="$tags" -o control.test ./control
          go test -c -tags="$tags" -o daemon.test ./internal/daemon
          go test -c -tags="$tags" -o clientset.test ./component/clientset
          go test -c -tags="$tags" -o apiserver.test ./internal/apiserver
        '';
        installPhase = ''
          runHook preInstall
          install -Dm755 control.test daemon.test clientset.test apiserver.test -t "$out/bin"
          runHook postInstall
        '';
      });
      tools = [
        suite
        pkgs.bash
        pkgs.coreutils
        pkgs.gnugrep
        pkgs.iproute2
        pkgs.nftables
        pkgs.util-linux
      ]
      ++ dae.runtimeInputs;
    in
    {
      virtualisation = {
        cores = 2;
        memorySize = 4096;
      };
      boot.kernelPackages = kernelPackages;
      boot.kernelModules = [
        "nf_conntrack"
        "nf_tables"
        "nft_chain_nat"
        "ip_set_hash_mac"
        "veth"
      ];
      environment.etc."dae-kernel-control/run".text = ''
        export PATH=${pkgs.lib.makeBinPath tools}
        source ${./kernel-control/run.sh}
      '';
    };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    print(machine.succeed("bash /etc/dae-kernel-control/run"))
  '';
}
