{
  config,
  lib,
  ...
}: let
  cfg = config.nixarr.plex;
  defaultPort = 32400;
  nixarr = config.nixarr;
in
  with lib; {
    options.nixarr.plex = {
      enable = mkOption {
        type = types.bool;
        default = false;
        example = true;
        description = ''
          Whether or not to enable the Plex service.

          **Required options:** [`nixarr.enable`](#nixarr.enable)
        '';
      };

      stateDir = mkOption {
        type = types.path;
        default = "${nixarr.stateDir}/plex";
        defaultText = literalExpression ''"''${nixarr.stateDir}/plex"'';
        example = "/nixarr/.state/plex";
        description = ''
          The location of the state directory for the Plex service.

          **Warning:** Setting this to any path, where the subpath is not
          owned by root, will fail! For example:

          ```nix
            stateDir = /home/user/nixarr/.state/plex
          ```

          Is not supported, because `/home/user` is owned by `user`.
        '';
      };

      openFirewall = mkOption {
        type = types.bool;
        defaultText = literalExpression ''!nixarr.plex.vpn.enable'';
        default = !cfg.vpn.enable;
        example = true;
        description = "Open firewall for Plex";
      };

      vpn.enable = mkOption {
        type = types.bool;
        default = false;
        example = true;
        description = ''
          **Required options:** [`nixarr.vpn.enable`](#nixarr.vpn.enable)

          **Conflicting options:** [`nixarr.plex.expose.https.enable`](#nixarr.plex.expose.https.enable)

          Route Plex traffic through the VPN.
        '';
      };

      expose = {
        vpn = {
          enable = mkOption {
            type = types.bool;
            default = false;
            example = true;
            description = ''
              **Required options:**

              - [`nixarr.plex.vpn.enable`](#nixarr.plex.vpn.enable)
              - [`nixarr.plex.expose.vpn.port`](#nixarr.plex.expose.vpn.port)
              - [`nixarr.plex.expose.vpn.accessibleFrom`](#nixarr.plex.expose.vpn.accessiblefrom)

              Expose the Plex web service to the internet, allowing anyone to
              access it.

              **Warning:** Do _not_ enable this without setting up Plex
              authentication through localhost first!
            '';
          };

          port = mkOption {
            type = with types; nullOr port;
            default = null;
            example = 12345;
            description = ''
              The port to access Plex on. Get this port from your VPN
              provider.
            '';
          };

          accessibleFrom = mkOption {
            type = with types; nullOr str;
            default = null;
            example = "plex.airvpn.org";
            description = ''
              The IP or domain that Plex should be able to be accessed from.
            '';
          };
        };

        https = {
          enable = mkOption {
            type = types.bool;
            default = false;
            example = true;
            description = ''
              **Required options:**

              - [`nixarr.plex.expose.https.acmeMail`](#nixarr.plex.expose.https.acmemail)
              - [`nixarr.plex.expose.https.domainName`](#nixarr.plex.expose.https.domainname)

              **Conflicting options:** [`nixarr.plex.vpn.enable`](#nixarr.plex.vpn.enable)

              Expose the Plex web service to the internet with https support,
              allowing anyone to access it.

              **Warning:** Do _not_ enable this without setting up Plex
              authentication through localhost first!
            '';
          };

          upnp.enable = mkEnableOption "UPNP to try to open ports 80 and 443 on your router.";

          domainName = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "plex.example.com";
            description = "The domain name to host Plex on.";
          };

          acmeMail = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "mail@example.com";
            description = "The ACME mail required for the letsencrypt bot.";
          };
        };
      };
    };

    config =
      mkIf cfg.enable
      {
        assertions = [
          {
            assertion = cfg.vpn.enable -> nixarr.vpn.enable;
            message = ''
              The nixarr.plex.vpn.enable option requires the
              nixarr.vpn.enable option to be set, but it was not.
            '';
          }
          {
            assertion = cfg.enable -> nixarr.enable;
            message = ''
              The nixarr.plex.enable option requires the nixarr.enable
              option to be set, but it was not.
            '';
          }
          {
            assertion = !(cfg.vpn.enable && cfg.expose.https.enable);
            message = ''
              The nixarr.plex.vpn.enable option conflicts with the
              nixarr.plex.expose.https.enable option. You cannot set both.
            '';
          }
          {
            assertion =
              cfg.expose.https.enable
              -> (
                (cfg.expose.https.domainName != null)
                && (cfg.expose.https.acmeMail != null)
              );
            message = ''
              The nixarr.plex.expose.https.enable option requires the
              following options to be set, but one of them were not:

              - nixarr.plex.expose.domainName
              - nixarr.plex.expose.acmeMail
            '';
          }
          {
            assertion =
              cfg.expose.vpn.enable
              -> (
                cfg.vpn.enable
                && (cfg.expose.vpn.port != null)
                && (cfg.expose.vpn.accessibleFrom != null)
              );
            message = ''
              The nixarr.plex.expose.vpn.enable option requires the
              following options to be set, but one of them were not:

              - nixarr.plex.vpn.enable
              - nixarr.plex.expose.vpn.port
              - nixarr.plex.expose.vpn.accessibleFrom
            '';
          }
        ];

        systemd.tmpfiles.rules = [
          "d '${cfg.stateDir}' 0700 streamer root - -"
        ];

        # Always prioritise Plex IO
        systemd.services.plex.serviceConfig.IOSchedulingPriority = 0;

        services.plex = {
          enable = cfg.enable;
          user = "streamer";
          group = "media";
          openFirewall = cfg.openFirewall;
          dataDir = "${cfg.stateDir}/data";
        };

        networking.firewall = mkIf cfg.expose.https.enable {
          allowedTCPPorts = [80 443];
        };

        util-nixarr.upnp = mkIf cfg.expose.https.upnp.enable {
          enable = true;
          openTcpPorts = [80 443];
        };

        services.nginx = mkMerge [
          (mkIf (cfg.expose.https.enable || cfg.vpn.enable) {
            enable = true;

            recommendedTlsSettings = true;
            recommendedOptimisation = true;
            recommendedGzipSettings = true;
          })
          (mkIf cfg.expose.https.enable {
            virtualHosts."${builtins.replaceStrings ["\n"] [""] cfg.expose.https.domainName}" = {
              enableACME = true;
              forceSSL = true;
              locations."/" = {
                recommendedProxySettings = true;
                proxyWebsockets = true;
                proxyPass = "http://127.0.0.1:${builtins.toString defaultPort}";
              };
            };
          })
          (mkIf cfg.vpn.enable {
            virtualHosts."127.0.0.1:${builtins.toString defaultPort}" = mkIf cfg.vpn.enable {
              listen = [
                {
                  addr = "0.0.0.0";
                  port = defaultPort;
                }
              ];
              locations."/" = {
                recommendedProxySettings = true;
                proxyWebsockets = true;
                proxyPass = "http://192.168.15.1:${builtins.toString defaultPort}";
              };
            };
          })
          (mkIf cfg.expose.vpn.enable {
            virtualHosts."${builtins.toString cfg.expose.vpn.accessibleFrom}:${builtins.toString cfg.expose.vpn.port}" = {
              enableACME = true;
              forceSSL = true;
              locations."/" = {
                recommendedProxySettings = true;
                proxyWebsockets = true;
                proxyPass = "http://192.168.15.1:${builtins.toString defaultPort}";
              };
            };
          })
        ];

        security.acme = mkIf cfg.expose.https.enable {
          acceptTerms = true;
          defaults.email = cfg.expose.https.acmeMail;
        };

        # Enable and specify VPN namespace to confine service in.
        systemd.services.plex.vpnconfinement = mkIf cfg.vpn.enable {
          enable = true;
          vpnnamespace = "wg";
        };

        # Port mappings
        # TODO: openports if expose.vpn
        vpnnamespaces.wg = mkIf cfg.vpn.enable {
          portMappings = [
            {
              from = defaultPort;
              to = defaultPort;
            }
          ];
          openVPNPorts = optional cfg.expose.vpn.enable {
            port = cfg.expose.vpn.port;
            protocol = "tcp";
          };
        };
      };
  }
