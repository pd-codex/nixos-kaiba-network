{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.kaiba.lanQualification;
  inherit (lib) mkOption mkIf types;
  roles = [
    "primary"
    "replica-a"
    "replica-b"
  ];
  state = "/var/lib/kaiba-lan-dns";
  firewallBackend =
    config.networking.firewall.backend
      or (if config.networking.nftables.enable then "nftables" else "iptables");
  unit = role: "kaiba-lan-dns-${role}";
  port =
    role:
    if role == "primary" then
      cfg.primaryPort
    else if role == "replica-a" then
      cfg.replicaPorts.a
    else
      cfg.replicaPorts.b;
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
  zoneFile = pkgs.writeText "kaiba-lan-qualification.zone" ''
    $ORIGIN ${cfg.zone}.
    $TTL 60
    @ IN SOA ns-a.${cfg.zone}. hostmaster.${cfg.zone}. ( 1 5 5 3600 60 )
      IN NS ns-a.${cfg.zone}.
      IN NS ns-b.${cfg.zone}.
    ns-a IN A ${cfg.listenAddress}
    ns-b IN A ${cfg.listenAddress}
  '';
  knotConfig =
    role:
    pkgs.writeText "${unit role}.conf" (
      ''
        server:
          listen: [127.0.0.1@${toString (port role)}${
            lib.optionalString (role != "primary") ", ${cfg.listenAddress}@${toString (port role)}"
          }]
          rundir: /run/${unit role}
          udp-workers: 1
          tcp-workers: 1
          background-workers: 1
        control:
          listen: /run/${unit role}/knot.sock
        log:
          - target: stdout
            any: notice
        database:
          storage: /var/lib/${unit role}
        include: /run/credentials/${unit role}.service/keys.conf
        remote:
      ''
      + (
        if role == "primary" then
          ''
              - id: replica-a
                address: 127.0.0.1@${toString cfg.replicaPorts.a}
                key: kaiba-lan-transfer-a
              - id: replica-b
                address: 127.0.0.1@${toString cfg.replicaPorts.b}
                key: kaiba-lan-transfer-b
            acl:
              - id: publisher
                address: 127.0.0.1
                key: kaiba-lan-update
                action: update
                update-type: [A, AAAA]
              - id: transfer-a
                address: 127.0.0.1
                key: kaiba-lan-transfer-a
                action: transfer
              - id: transfer-b
                address: 127.0.0.1
                key: kaiba-lan-transfer-b
                action: transfer
          ''
        else
          ''
              - id: primary
                address: 127.0.0.1@${toString cfg.primaryPort}
                key: kaiba-lan-transfer-${if role == "replica-a" then "a" else "b"}
            acl:
              - id: primary-notify
                address: 127.0.0.1
                key: kaiba-lan-transfer-${if role == "replica-a" then "a" else "b"}
                action: notify
          ''
      )
      + ''
        template:
          - id: default
            storage: /var/lib/${unit role}
            journal-content: all
            zonefile-load: ${if role == "primary" then "difference" else "none"}
            zonefile-sync: -1
            semantic-checks: true
        zone:
          - domain: ${cfg.zone}.
      ''
      + (
        if role == "primary" then
          "    file: ${zoneFile}\n    notify: [replica-a, replica-b]\n    acl: [publisher, transfer-a, transfer-b]\n"
        else
          "    master: primary\n    acl: primary-notify\n"
      )
    );
  firewallRules =
    lib.concatMapStringsSep "\n"
      (
        protocol:
        let
          match = "-d ${cfg.listenAddress}/32 -p ${protocol} -m multiport --dports ${toString cfg.replicaPorts.a},${toString cfg.replicaPorts.b}";
        in
        ''
          iptables -w -I nixos-fw 1 ${match} -j DROP
          ${lib.concatMapStringsSep "\n" (
            peer: "iptables -w -I nixos-fw 1 ${match} -s ${peer}/32 -j nixos-fw-accept"
          ) cfg.allowedPeers}
          iptables -w -I nixos-fw 1 ${match} -i lo -j nixos-fw-accept
        ''
      )
      [
        "tcp"
        "udp"
      ];
in
{
  imports = [
    ./device-agent.nix
    ./update-controller.nix
  ];
  options.kaiba.lanQualification = {
    enable = lib.mkEnableOption "the explicit LAN-only SPIFFE DNS qualification profile";
    zone = mkOption {
      type = types.strMatching "[a-z0-9]([a-z0-9.-]*[a-z0-9])?";
      default = "pilot.kaiba.pseudo.design";
      description = "Isolated qualification zone; no delegation or resolver is configured.";
    };
    listenAddress = mkOption {
      type = types.strMatching "[0-9.]+";
      default = "192.168.8.214";
      description = "RFC 1918 address assigned to this host; also the updater's explicit address.";
    };
    allowedPeers = mkOption {
      type = types.listOf (types.strMatching "[0-9.]+");
      default = [ ];
      description = "Exact RFC 1918 client IPv4 addresses permitted to query both replicas.";
    };
    primaryPort = mkOption {
      type = types.port;
      default = 15352;
    };
    replicaPorts.a = mkOption {
      type = types.port;
      default = 15353;
    };
    replicaPorts.b = mkOption {
      type = types.port;
      default = 15354;
    };
    controllerPort = mkOption {
      type = types.port;
      default = 18443;
    };
    knotPackage = lib.mkPackageOption pkgs "knot-dns" { };
  };
  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = privateIPv4 cfg.listenAddress && builtins.all privateIPv4 cfg.allowedPeers;
        message = "LAN qualification requires exact RFC 1918 IPv4 listener and peer addresses.";
      }
      {
        assertion = cfg.allowedPeers != [ ];
        message = "LAN qualification requires an explicit nonempty allowedPeers list.";
      }
      {
        assertion =
          builtins.length (
            lib.unique [
              cfg.primaryPort
              cfg.replicaPorts.a
              cfg.replicaPorts.b
              cfg.controllerPort
            ]
          ) == 4
          && builtins.all (p: p > 1024) [
            cfg.primaryPort
            cfg.replicaPorts.a
            cfg.replicaPorts.b
            cfg.controllerPort
          ];
        message = "LAN qualification uses four distinct unprivileged ports.";
      }
      {
        assertion = config.networking.firewall.enable && firewallBackend == "iptables";
        message = "LAN qualification currently requires the enabled NixOS iptables firewall.";
      }
      {
        assertion =
          builtins.stringLength cfg.zone <= 253
          && builtins.all (label: builtins.match "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?" label != null) (
            lib.splitString "." cfg.zone
          );
        message = "LAN qualification zone must be a canonical lowercase DNS name.";
      }
      {
        assertion =
          config.kaiba.deviceAgent.identity.mode == "spiffe"
          && config.kaiba.updateController.identity.mode == "spiffe";
        message = "LAN qualification requires SPIFFE for both updater and controller.";
      }
    ];
    kaiba.deviceAgent = {
      enable = true;
      identity.mode = "spiffe";
      endpoint = "https://127.0.0.1:${toString cfg.controllerPort}";
      addresses = [ cfg.listenAddress ];
    };
    kaiba.updateController = {
      enable = true;
      identity.mode = "spiffe";
      zone = cfg.zone;
      controller = {
        listenAddress = "127.0.0.1";
        port = cfg.controllerPort;
        allowNonGlobalAddresses = true;
      };
      credentials = {
        publisherTSIGSecret = "${state}/credentials/publisher/update.secret";
        provisioningUnits = [ "kaiba-lan-dns-credentials.service" ];
      };
      publisher = {
        dnsServer = "127.0.0.1:${toString cfg.primaryPort}";
        tsigName = "kaiba-lan-update";
        observeServers = [
          "127.0.0.1:${toString cfg.replicaPorts.a}"
          "127.0.0.1:${toString cfg.replicaPorts.b}"
        ];
      };
    };
    networking.firewall.extraCommands = firewallRules;
    users.groups = lib.genAttrs (map unit roles) (_: { });
    users.users = lib.genAttrs (map unit roles) (name: {
      isSystemUser = true;
      group = name;
    });
    systemd.services = {
      kaiba-lan-dns-credentials = {
        description = "Initialize and validate private LAN DNS qualification credentials";
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          StateDirectory = "kaiba-lan-dns";
          StateDirectoryMode = "0755";
          UMask = "0077";
          ExecStart = "${pkgs.python3}/bin/python3 ${./lan-credentials.py} ${state}";
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          NoNewPrivileges = true;
        };
      };
    }
    // lib.genAttrs (map unit roles) (
      name:
      let
        role = lib.removePrefix "kaiba-lan-dns-" name;
      in
      {
        description = "LAN qualification Knot ${role}";
        wantedBy = [ "multi-user.target" ];
        after = [
          "network-online.target"
          "firewall.service"
          "kaiba-lan-dns-credentials.service"
        ];
        wants = [ "network-online.target" ];
        requires = [ "kaiba-lan-dns-credentials.service" ];
        bindsTo = [ "firewall.service" ];
        serviceConfig = {
          Type = "notify";
          User = name;
          Group = name;
          ExecStart = "${cfg.knotPackage}/bin/knotd -c ${knotConfig role}";
          LoadCredential = [ "keys.conf:${state}/credentials/private/${role}.conf" ];
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
      }
    );
  };
}
