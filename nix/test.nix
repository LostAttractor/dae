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
        routing {
          fallback: direct
        }
      '';
    };
  };

  testScript = ''
    machine.wait_for_unit("dae.service")
    machine.succeed("test -e /run/netns/daens")
    machine.succeed("systemctl reload dae.service")
    machine.wait_for_unit("dae.service")
  '';
}
