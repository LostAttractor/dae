self:
let
  # NixOS test networking numbers nodes alphabetically: client, gateway, peer.
  lan4 = "192.168.1.2";
  lan6 = "2001:db8:1::2";
  wan4 = "192.168.2.2";
  wan6 = "2001:db8:2::2";
  peer4 = "192.168.2.3";
  peer6 = "2001:db8:2::3";
  echoPort = 18080;
  proxyPort = 18388;

  listener =
    {
      pkgs,
      lib,
      addresses,
      tag,
    }:
    {
      systemd.services.datapath-targets = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig.ExecStart = "${lib.getExe pkgs.python3} /etc/datapath.py serve ${tag} ${lib.concatStringsSep " " addresses}";
      };
    };
in
{
  name = "dae-kernel-proxy";

  defaults = { pkgs, ... }: {
    networking.firewall.enable = false;
    environment.systemPackages = [ pkgs.python3 ];
    environment.etc."datapath.py".source = ./kernel-proxy/datapath.py;
  };

  nodes = {
    client.virtualisation.vlans = [ 1 ];

    gateway = { pkgs, lib, ... }: {
      imports = [
        self.nixosModules.dae
        (listener {
          inherit pkgs lib;
          addresses = [
            lan4
            lan6
          ];
          tag = "2";
        })
      ];
      virtualisation.vlans = [
        1
        2
      ];
      boot.kernelModules = [ "nf_conntrack" ];
      # With no gateway firewall, nothing else registers the conntrack hooks.
      boot.extraModprobeConfig = "options nf_conntrack enable_hooks=1";
      boot.kernel.sysctl = {
        "net.ipv4.ip_forward" = 1;
        "net.ipv6.conf.all.forwarding" = 1;
      };
      systemd.services.dae.wantedBy = lib.mkForce [ ];
      services.dae = {
        enable = true;
        config = ''
          global {
            lan_interface: eth1
            wan_interface: eth2
            auto_config_kernel_parameter: true
            disable_waiting_network: true
            dial_target_override: false
            reroute_mode: none
            udp_check_dns: '${peer4}:53,${peer4},${peer6}'
          }
          node {
            relay: 'ss://YWVzLTEyOC1nY206cGFzcw@${peer4}:${toString proxyPort}'
          }
          routing {
            rules {
              dport(53) -> must
            }
            dip(${peer4}, '${peer6}') -> relay
            fallback: direct
          }
        '';
      };
    };

    peer =
      { pkgs, lib, ... }:
      let
        singBox = pkgs.callPackage ./kernel-sing-box.nix { };
        config = pkgs.writeText "datapath-sing-box.json" (
          builtins.toJSON {
            inbounds = [
              {
                type = "shadowsocks";
                listen = peer4;
                listen_port = proxyPort;
                method = "aes-128-gcm";
                password = "pass";
              }
            ];
            outbounds = [
              {
                type = "direct";
                tag = "direct";
              }
            ];
          }
        );
      in
      {
        imports = [
          (listener {
            inherit pkgs lib;
            addresses = [
              peer4
              peer6
            ];
            tag = "3";
          })
        ];
        virtualisation.vlans = [ 2 ];
        # Direct packets reach this VM but only local sing-box egress can reach the targets.
        networking.nftables = {
          enable = true;
          tables.datapath = {
            family = "inet";
            content = ''
              chain input {
                type filter hook input priority filter; policy accept;
                iifname != "lo" tcp dport { 53, ${toString echoPort} } drop
                iifname != "lo" udp dport { 53, ${toString echoPort} } drop
              }
            '';
          };
        };
        systemd.services.sing-box = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network-online.target" ];
          wants = [ "network-online.target" ];
          serviceConfig.ExecStart = "${lib.getExe' singBox "sing-box"} run -c ${config}";
        };
      };
  };

  testScript = ''
    start_all()
    for machine in (client, gateway, peer):
        machine.wait_for_unit("multi-user.target")
    client.succeed("ip route replace ${peer4}/32 via ${lan4}")
    client.succeed("ip -6 route replace ${peer6}/128 via ${lan6}")
    peer.succeed("ip route replace 192.168.1.0/24 via ${wan4}")
    peer.succeed("ip -6 route replace 2001:db8:1::/64 via ${wan6}")
    for address in ("${peer4}", "${peer6}"):
        client.wait_until_succeeds(f"ping -c 1 -W 1 {address}")
        gateway.wait_until_succeeds(f"ping -c 1 -W 1 {address}")

    peer.wait_for_unit("nftables.service")
    peer.wait_for_unit("sing-box.service")
    peer.wait_for_open_port(${toString proxyPort}, addr="${peer4}")
    for machine in (gateway, peer):
        machine.wait_for_unit("datapath-targets.service")

    def probe(machine, addresses, tag, execute, mode="probe"):
        for address in addresses:
            for protocol, port in (("tcp", ${toString echoPort}), ("udp", ${toString echoPort}), ("udp", 53)):
                with subtest(f"{machine.name} {mode} {protocol} {address}:{port} target {tag}"):
                    execute(f"python3 /etc/datapath.py {mode} {tag} {address} {protocol} {port}")

    targets = ("${peer4}", "${peer6}")
    with subtest("targets alive and direct traffic cannot reach them"):
        probe(peer, targets, 3, peer.wait_until_succeeds)
        for source in (client, gateway):
            probe(source, targets, 3, source.succeed, mode="blocked")

    with subtest("LAN ingress and WAN egress after daemon readiness"):
        gateway.succeed("systemctl start dae.service")
        gateway.wait_for_unit("dae.service")
        probe(client, ("${lan4}", "${lan6}"), 2, client.wait_until_succeeds)
        for source in (client, gateway):
            probe(source, targets, 3, source.succeed)

    with subtest("reload removes IPv6 proxying but preserves IPv4 proxying"):
        pid = gateway.succeed("systemctl show -p MainPID --value dae.service").strip()
        gateway.succeed("sed -i \"s/, '${peer6}'//\" /etc/dae/config.dae")
        gateway.succeed("systemctl reload dae.service")
        gateway.wait_for_unit("dae.service")
        assert gateway.succeed("systemctl show -p MainPID --value dae.service").strip() == pid
        for source in (client, gateway):
            probe(source, ("${peer4}",), 3, source.succeed)
            probe(source, ("${peer6}",), 3, source.succeed, mode="blocked")
        probe(peer, ("${peer6}",), 3, peer.succeed)
  '';
}
