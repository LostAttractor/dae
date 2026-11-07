self: {
  name = "dae";

  nodes.machine = {
    imports = [ self.nixosModules.dae ];
    services.dae = {
      enable = true;
      config = ''
        global {
          disable_waiting_network: true
        }
        plugins {
          surge {
            module {
              tools: 'file:///etc/dae/tools.sgmodule'
            }
          }
        }
        routing {
          fallback: direct
        }
      '';
    };
    # A generic script runs only on demand and needs neither MITM nor network access.
    environment.etc."dae/tools.sgmodule".text = ''
      [Script]
      runtime.check = type=generic,script-path=runtime.js,timeout=10
    '';
    environment.etc."dae/runtime.js".text = ''
      console.log("surge-check runtime=" + $environment["dae-runtime"]);
      $done();
    '';
  };

  testScript = ''
    machine.wait_for_unit("dae.service")
    machine.succeed("test -e /run/netns/daens")
    machine.succeed("systemctl reload dae.service")
    machine.wait_for_unit("dae.service")
    machine.succeed("dae plugins surge run runtime.check --instance surge --module tools")
    machine.wait_until_succeeds("journalctl -u dae.service | grep -q 'surge-check runtime=nodejs'")
  '';
}
