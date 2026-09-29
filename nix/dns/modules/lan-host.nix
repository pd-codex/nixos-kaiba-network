{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption mkIf types;
  primary = config.kaiba.lanPrimary;
  secondary = config.kaiba.lanSecondary;
  enabled = primary.enable || secondary.enable;
  isPrimary = primary.enable;
  cfg = if isPrimary then primary else secondary;
  role = if isPrimary then "primary" else "secondary";
  name = "kaiba-lan-${role}";
  credentialUnit = "${name}-credentials";
  base = "/var/lib/${credentialUnit}";
  peer = if isPrimary then cfg.secondary else cfg.primary;
  peers = lib.unique ([ peer.address ] ++ cfg.queryAllowedPeers);
  privateIPv4 =
    value:
    let
      parts = lib.splitString "." value;
      valid =
        builtins.length parts == 4
        && builtins.all (v: builtins.match "(0|[1-9][0-9]{0,2})" v != null && lib.toInt v <= 255) parts;
      numbers = map lib.toInt parts;
    in
    valid
    && (
      builtins.elemAt numbers 0 == 10
      || (
        builtins.elemAt numbers 0 == 172
        && builtins.elemAt numbers 1 >= 16
        && builtins.elemAt numbers 1 <= 31
      )
      || (builtins.elemAt numbers 0 == 192 && builtins.elemAt numbers 1 == 168)
    );
  commonOptions = {
    enable = lib.mkEnableOption "an explicit host in the private two-host DNS profile";
    zone = mkOption {
      type = types.str;
      default = "pilot.kaiba.pseudo.design";
    };
    listenAddress = mkOption {
      type = types.str;
      default = "";
      description = "Required exact RFC1918 address assigned to this host.";
    };
    queryAllowedPeers = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Exact RFC1918 query clients; the configured DNS partner is also permitted for transfer/NOTIFY.";
    };
    knotPackage = lib.mkPackageOption pkgs "knot-dns" { };
  };
  peerOptions =
    defaultPort:
    types.submodule {
      options = {
        address = mkOption {
          type = types.str;
          default = "";
          description = "Required exact RFC1918 address of the other DNS host.";
        };
        port = mkOption {
          type = types.port;
          default = defaultPort;
        };
      };
    };
  firewallBackend =
    config.networking.firewall.backend
      or (if config.networking.nftables.enable then "nftables" else "iptables");
  scope = pkgs.writeText "${name}-credential-scope.json" (
    builtins.toJSON (
      {
        inherit role;
        zone = cfg.zone;
        listen_address = cfg.listenAddress;
        peer_address = peer.address;
        dns_state = "/var/lib/${name}";
      }
      // lib.optionalAttrs (!isPrimary) { transfer_secret_file = cfg.transferSecretFile; }
    )
  );
  initialZone = pkgs.writeText "kaiba-lan-primary.zone" ''
    $ORIGIN ${cfg.zone}.
    $TTL 60
    @ IN SOA ns-primary.${cfg.zone}. hostmaster.${cfg.zone}. ( 1 300 5 3600 60 )
      IN NS ns-primary.${cfg.zone}.
      IN NS ns-secondary.${cfg.zone}.
    ns-primary IN A ${cfg.listenAddress}
    ns-secondary IN A ${peer.address}
  '';
  knotConfig = pkgs.writeText "${name}.conf" (
    ''
      server:
        listen: [127.0.0.1@${toString cfg.port}, ${cfg.listenAddress}@${toString cfg.port}]
        rundir: /run/${name}
        udp-workers: 1
        tcp-workers: 1
        background-workers: 1
      control:
        listen: /run/${name}/knot.sock
      log:
        - target: stdout
          any: info
      database:
        storage: /var/lib/${name}
      include: /run/credentials/${name}.service/keys.conf
      remote:
        - id: partner
          address: ${peer.address}@${toString peer.port}
          key: kaiba-lan-transfer
      acl:
    ''
    + (
      if isPrimary then
        ''
          - id: publisher
            address: 127.0.0.1
            key: kaiba-lan-update
            action: update
            update-type: [A, AAAA]
          - id: secondary-transfer
            address: ${peer.address}
            key: kaiba-lan-transfer
            action: transfer
        ''
      else
        ''
          - id: primary-notify
            address: ${peer.address}
            key: kaiba-lan-transfer
            action: notify
        ''
    )
    + ''
      template:
        - id: default
          storage: /var/lib/${name}
          journal-content: all
          zonefile-load: ${if isPrimary then "difference" else "none"}
          zonefile-sync: -1
          semantic-checks: true
      zone:
        - domain: ${cfg.zone}.
    ''
    + (
      if isPrimary then
        "    file: ${initialZone}\n    notify: partner\n    acl: [publisher, secondary-transfer]\n"
      else
        "    master: partner\n    acl: primary-notify\n"
    )
  );
in
{
  imports = [
    ./device-agent.nix
    ./update-controller.nix
  ];
  options.kaiba.lanPrimary = commonOptions // {
    port = mkOption {
      type = types.port;
      default = 15352;
    };
    secondary = mkOption {
      type = peerOptions 15353;
      default = { };
    };
  };
  options.kaiba.lanSecondary = commonOptions // {
    port = mkOption {
      type = types.port;
      default = 15353;
    };
    primary = mkOption {
      type = peerOptions 15352;
      default = { };
    };
    transferSecretFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Required root-owned0600 regular file with the primary's transfer-only base64 secret and newline. Provision outside the store through an authenticated channel; retained bytes must match after restart.";
    };
  };
  config = mkIf enabled (
    lib.mkMerge [
      {
        assertions = [
          {
            assertion = !(primary.enable && secondary.enable);
            message = "The two-host LAN profile requires one DNS role per host.";
          }
          {
            assertion =
              privateIPv4 cfg.listenAddress
              && privateIPv4 peer.address
              && peer.address != cfg.listenAddress
              && builtins.all privateIPv4 cfg.queryAllowedPeers;
            message = "LAN DNS requires distinct exact RFC1918 host/partner addresses and private query peers.";
          }
          {
            assertion = cfg.port >= 1024 && peer.port >= 1024;
            message = "LAN DNS qualification uses explicit unprivileged ports.";
          }
          {
            assertion =
              builtins.stringLength cfg.zone <= 253
              && builtins.all (label: builtins.match "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?" label != null) (
                lib.splitString "." cfg.zone
              );
            message = "LAN DNS zone must be a canonical lowercase DNS name.";
          }
          {
            assertion = config.networking.firewall.enable && firewallBackend == "iptables";
            message = "The two-host LAN profile requires the enabled NixOS iptables firewall.";
          }
          {
            assertion =
              isPrimary
              || (
                cfg.transferSecretFile != null
                && lib.hasPrefix "/" cfg.transferSecretFile
                && !(lib.hasPrefix "/nix/store/" cfg.transferSecretFile)
              );
            message = "The LAN secondary requires an absolute runtime transferSecretFile outside the Nix store.";
          }
          {
            assertion = !(config.kaiba.lanQualification.enable or false);
            message = "The two-host LAN profile cannot run alongside the same-host qualification profile.";
          }
        ];
        users.groups.${name} = { };
        users.users.${name} = {
          isSystemUser = true;
          group = name;
        };
        networking.firewall.extraCommands =
          lib.concatMapStringsSep "\n"
            (
              protocol:
              let
                match = "-d ${cfg.listenAddress}/32 -p ${protocol} --dport ${toString cfg.port}";
              in
              ''
                iptables -w -I nixos-fw 1 ${match} -j DROP
                ${lib.concatMapStringsSep "\n" (
                  address: "iptables -w -I nixos-fw 1 ${match} -s ${address}/32 -j nixos-fw-accept"
                ) peers}
                iptables -w -I nixos-fw 1 ${match} -i lo -j nixos-fw-accept
              ''
            )
            [
              "tcp"
              "udp"
            ];
        systemd.services.${credentialUnit} = {
          description = "Validate persistent ${role} DNS credentials and topology scope";
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            StateDirectory = credentialUnit;
            StateDirectoryMode = "0755";
            UMask = "0077";
            ExecStart = "${pkgs.python3}/bin/python3 ${./lan-host-credentials.py} ${role} ${base} ${scope}";
            ProtectSystem = "strict";
            ProtectHome = true;
            PrivateTmp = true;
            NoNewPrivileges = true;
          };
        };
        systemd.services.${name} = {
          description = "Private LAN DNS ${role}";
          wantedBy = [ "multi-user.target" ];
          after = [
            "network-online.target"
            "firewall.service"
            "${credentialUnit}.service"
          ];
          wants = [ "network-online.target" ];
          requires = [ "${credentialUnit}.service" ];
          bindsTo = [ "firewall.service" ];
          serviceConfig = {
            Type = "notify";
            User = name;
            Group = name;
            ExecStart = "${cfg.knotPackage}/bin/knotd -c ${knotConfig}";
            LoadCredential = [ "keys.conf:${base}/credentials/private/keys.conf" ];
            StateDirectory = name;
            StateDirectoryMode = "0700";
            RuntimeDirectory = name;
            RuntimeDirectoryMode = "0700";
            UMask = "0077";
            Restart = "on-failure";
            RestartSec = "2s";
            NoNewPrivileges = true;
            CapabilityBoundingSet = "";
            PrivateTmp = true;
            PrivateDevices = true;
            ProtectSystem = "strict";
            ProtectHome = true;
            ProtectKernelTunables = true;
            ProtectKernelModules = true;
            ProtectControlGroups = true;
            RestrictAddressFamilies = [
              "AF_INET"
              "AF_UNIX"
            ];
          };
        };
      }
      (mkIf isPrimary {
        assertions = [
          {
            assertion =
              config.kaiba.deviceAgent.identity.mode == "spiffe"
              && config.kaiba.updateController.identity.mode == "spiffe";
            message = "The LAN primary requires the existing SPIFFE updater/controller authorization path.";
          }
          {
            assertion = cfg.port != config.kaiba.updateController.controller.port;
            message = "LAN DNS and the update controller must use distinct ports.";
          }
        ];
        kaiba.deviceAgent = {
          enable = true;
          identity.mode = "spiffe";
          endpoint = "https://127.0.0.1:${toString config.kaiba.updateController.controller.port}";
          addresses = [ cfg.listenAddress ];
        };
        kaiba.updateController = {
          enable = true;
          identity.mode = "spiffe";
          zone = cfg.zone;
          controller = {
            listenAddress = "127.0.0.1";
            port = lib.mkDefault 18443;
            allowNonGlobalAddresses = true;
          };
          credentials = {
            publisherTSIGSecret = "${base}/credentials/publisher/update.secret";
            provisioningUnits = [ "${credentialUnit}.service" ];
          };
          publisher = {
            dnsServer = "127.0.0.1:${toString cfg.port}";
            tsigName = "kaiba-lan-update";
            observeServers = [
              "127.0.0.1:${toString cfg.port}"
              "${peer.address}:${toString peer.port}"
            ];
          };
        };
      })
    ]
  );
}
