self:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  inherit (lib)
    getExe
    literalExpression
    mkEnableOption
    mkIf
    mkOption
    optional
    types
    ;

  cfg = config.services.dae;
  configPath = if cfg.configFile != null then cfg.configFile else "/etc/dae/config.dae";
in
{
  # Replaces the Nixpkgs module of the same name.
  disabledModules = [ "services/networking/dae.nix" ];

  options.services.dae = {
    enable = mkEnableOption "dae, a Linux high-performance transparent proxy solution based on eBPF";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.dae;
      defaultText = literalExpression "dae.packages.\${pkgs.stdenv.hostPlatform.system}.dae";
      description = "The dae package to use.";
    };

    assets = mkOption {
      type = types.listOf types.path;
      default = with pkgs; [
        v2ray-geoip
        v2ray-domain-list-community
      ];
      defaultText = literalExpression "with pkgs; [ v2ray-geoip v2ray-domain-list-community ]";
      description = "Packages providing Geo data under `share/v2ray`.";
    };

    assetsPath = mkOption {
      type = types.str;
      default = "${
        pkgs.symlinkJoin {
          name = "dae-assets";
          paths = cfg.assets;
        }
      }/share/v2ray";
      defaultText = literalExpression ''"''${pkgs.symlinkJoin { name = "dae-assets"; paths = assets; }}/share/v2ray"'';
      description = ''
        Directory containing Geo data files, exported as `DAE_LOCATION_ASSET`.
        Setting it overrides `assets`.
      '';
    };

    cachePath = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/var/lib/dae";
      description = ''
        Writable state directory for certificates, subscription caches, runtime
        state and Surge resources, exported as `DAE_LOCATION_CACHE`. When unset,
        dae uses `/var/lib/dae`. Relative local subscription paths are resolved
        from the main configuration directory, independently of this option.
      '';
    };

    openFirewall = mkOption {
      type = types.submodule {
        options = {
          enable = mkEnableOption "opening {option}`port` in the firewall";
          port = mkOption {
            type = types.port;
            description = "Port to open; matches `tproxy_port` in the configuration.";
          };
        };
      };
      default = {
        enable = true;
        port = 12345;
      };
      description = "Open the TPROXY port in the firewall.";
    };

    configFile = mkOption {
      type = types.nullOr (
        types.addCheck types.str (x: lib.hasPrefix "/" x && !lib.hasPrefix builtins.storeDir x)
        // {
          description = "absolute path string outside the Nix store";
        }
      );
      default = null;
      example = "/etc/dae/config.dae";
      description = ''
        Absolute path of a configuration file outside the Nix store. dae
        rejects configuration files accessible by others.
        Exactly one of `configFile` and `config` must be set.
      '';
    };

    config = mkOption {
      type = types.nullOr types.lines;
      default = null;
      description = ''
        Configuration text, installed as `/etc/dae/config.dae`. The text is
        world-readable in the Nix store; use `configFile` for secrets.
        See <https://github.com/LostAttractor/dae/blob/next/example.dae>.
      '';
    };

    disableTxChecksumIpGeneric = mkEnableOption "" // {
      description = ''
        Disable `tx-checksum-ip-generic` on the default route interface before
        starting dae. See <https://github.com/daeuniverse/dae/issues/43>.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = (cfg.config == null) != (cfg.configFile == null);
        message = "Exactly one of `services.dae.config` and `services.dae.configFile` must be set.";
      }
    ];

    environment.etc."dae/config.dae" = mkIf (cfg.config != null) {
      mode = "0400";
      text = cfg.config;
    };

    environment.systemPackages = [ cfg.package ];
    systemd.packages = [ cfg.package ];

    networking.firewall = mkIf cfg.openFirewall.enable {
      allowedTCPPorts = [ cfg.openFirewall.port ];
      allowedUDPPorts = [ cfg.openFirewall.port ];
    };

    systemd.services.dae = {
      wantedBy = [ "multi-user.target" ];
      reloadTriggers = optional (cfg.config != null) cfg.config;
      path = cfg.package.runtimeInputs or [ ];
      environment = {
        DAE_LOCATION_ASSET = cfg.assetsPath;
      }
      // lib.optionalAttrs (cfg.cachePath != null) { DAE_LOCATION_CACHE = cfg.cachePath; };
      serviceConfig = {
        ExecStartPre = [
          ""
          "${getExe cfg.package} validate -c ${configPath}"
        ]
        ++ optional cfg.disableTxChecksumIpGeneric (
          getExe (
            pkgs.writeShellApplication {
              name = "disable-tx-checksum-ip-generic";
              runtimeInputs = with pkgs; [
                iproute2
                gawk
                ethtool
              ];
              # Every interface of every default route, with or without a gateway.
              text = ''
                ip route show default |
                  awk '{ for (i = 1; i < NF; i++) if ($i == "dev" && !seen[$(i + 1)]++) print $(i + 1) }' |
                  while read -r iface; do
                    ethtool -K "$iface" tx-checksum-ip-generic off
                  done
              '';
            }
          )
        );
        ExecStart = [
          ""
          "${getExe cfg.package} run --disable-timestamp -c ${configPath}"
        ];
      };
    };
  };
}
