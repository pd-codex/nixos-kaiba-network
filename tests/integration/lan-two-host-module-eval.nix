{
  pkgs,
  lib,
  kaibaPackage,
  kaibaModules,
}:
let
  evaluate =
    extra:
    (lib.nixosSystem {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        kaibaModules.lan-primary
        kaibaModules.lan-secondary
        {
          boot.loader.grub.devices = [ "nodev" ];
          fileSystems."/" = {
            device = "none";
            fsType = "tmpfs";
          };
          system.stateVersion = "26.05";
          kaiba.deviceAgent = {
            package = kaibaPackage;
            identity = {
              workloadAPISocket = "unix:///run/identity/api.sock";
              controllerSPIFFEID = "spiffe://pilot.kaiba.pseudo.design/service/dns-controller";
            };
          };
          kaiba.updateController = {
            controller.package = kaibaPackage;
            publisher.package = kaibaPackage;
            identity = {
              workloadAPISocket = "unix:///run/identity/api.sock";
              trustDomain = "pilot.kaiba.pseudo.design";
              fleetAuthorizationURL = "https://127.0.0.1:8096/api/v1/workloads/authorize-dns";
              fleetServerSPIFFEID = "spiffe://pilot.kaiba.pseudo.design/service/workload-registry";
            };
          };
        }
        extra
      ];
    }).config;
  primary = {
    kaiba.lanPrimary = {
      enable = true;
      listenAddress = "192.168.8.214";
      secondary.address = "192.168.8.247";
      queryAllowedPeers = [ "192.168.8.249" ];
    };
  };
  secondary = {
    kaiba.lanSecondary = {
      enable = true;
      listenAddress = "192.168.8.247";
      primary.address = "192.168.8.214";
      queryAllowedPeers = [ "192.168.8.249" ];
      transferSecretFile = "/var/lib/qualification/transfer.secret";
    };
  };
  merge = left: right: lib.recursiveUpdate left right;
  valid = config: builtins.all (item: item.assertion) config.assertions;
  a = evaluate primary;
  b = evaluate secondary;
  off = evaluate { };
in
assert valid a && valid b && valid off;
assert !(builtins.hasAttr "kaiba-lan-primary" off.systemd.services);
assert !(builtins.hasAttr "kaiba-lan-secondary" off.systemd.services);
assert !off.kaiba.deviceAgent.enable && !off.kaiba.updateController.enable;
assert !off.kaiba.updateController.controller.allowNonGlobalAddresses;
assert a.kaiba.deviceAgent.addresses == [ "192.168.8.214" ];
assert a.kaiba.deviceAgent.endpoint == "https://127.0.0.1:18443";
assert
  a.kaiba.updateController.publisher.observeServers == [
    "127.0.0.1:15352"
    "192.168.8.247:15353"
  ];
assert
  a.kaiba.updateController.credentials.publisherTSIGSecret
  == "/var/lib/kaiba-lan-primary-credentials/credentials/publisher/update.secret";
assert !b.kaiba.deviceAgent.enable && !b.kaiba.updateController.enable;
assert !b.kaiba.updateController.controller.allowNonGlobalAddresses;
assert
  b.systemd.services.kaiba-lan-secondary.serviceConfig.LoadCredential
  == [ "keys.conf:/var/lib/kaiba-lan-secondary-credentials/credentials/private/keys.conf" ];
assert b.systemd.services.kaiba-lan-secondary.serviceConfig.User == "kaiba-lan-secondary";
assert b.systemd.services.kaiba-lan-secondary.bindsTo == [ "firewall.service" ];
assert lib.hasInfix "-s 192.168.8.214/32" b.networking.firewall.extraCommands;
assert lib.hasInfix "--dport 15353 -j DROP" b.networking.firewall.extraCommands;
assert lib.hasInfix "-s 192.168.8.247/32" a.networking.firewall.extraCommands;
assert !(lib.elem 15352 a.networking.firewall.allowedTCPPorts);
assert !(lib.elem 15353 b.networking.firewall.allowedUDPPorts);
assert builtins.all (extra: !(valid (evaluate (merge primary extra)))) [
  { kaiba.lanPrimary.listenAddress = "0.0.0.0"; }
  { kaiba.lanPrimary.listenAddress = "192.168.08.214"; }
  { kaiba.lanPrimary.secondary.address = "192.168.8.214"; }
  { kaiba.lanPrimary.secondary.address = "203.0.113.1"; }
  { kaiba.lanPrimary.queryAllowedPeers = [ "0.0.0.0/0" ]; }
  { kaiba.lanPrimary.zone = "invalid..example"; }
  { kaiba.lanPrimary.port = 53; }
  { kaiba.lanPrimary.port = 18443; }
  { networking.firewall.enable = false; }
  { networking.nftables.enable = true; }
];
assert builtins.all (extra: !(valid (evaluate (merge secondary extra)))) [
  { kaiba.lanSecondary.transferSecretFile = null; }
  { kaiba.lanSecondary.transferSecretFile = "/nix/store/test-secret"; }
  { kaiba.lanSecondary.transferSecretFile = "relative.secret"; }
  { kaiba.lanSecondary.primary.address = ""; }
];
assert !(valid (evaluate (merge primary secondary)));
pkgs.runCommand "kaiba-lan-two-host-module-evaluation" { } ''
  mkdir -p "$out"
  echo 'Two-host LAN assertions and disabled defaults passed' > "$out/result"
''
