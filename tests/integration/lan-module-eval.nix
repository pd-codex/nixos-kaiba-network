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
        kaibaModules.lan-qualification
        {
          boot.loader.grub.devices = [ "nodev" ];
          fileSystems."/" = {
            device = "none";
            fsType = "tmpfs";
          };
          system.stateVersion = "26.05";
          kaiba.lanQualification = {
            enable = true;
            allowedPeers = [ "192.168.8.249" ];
          };
          kaiba.deviceAgent = {
            package = kaibaPackage;
            identity = {
              workloadAPISocket = "unix:///run/identity/api.sock";
              controllerSPIFFEID = "spiffe://pilot.kaiba.pseudo.design/device/ace/instance/check/workload/dns-controller";
            };
          };
          kaiba.updateController = {
            controller.package = kaibaPackage;
            publisher.package = kaibaPackage;
            identity = {
              workloadAPISocket = "unix:///run/identity/api.sock";
              trustDomain = "pilot.kaiba.pseudo.design";
              fleetAuthorizationURL = "https://127.0.0.1:8096/api/v1/workloads/authorize-dns";
              fleetServerSPIFFEID = "spiffe://pilot.kaiba.pseudo.design/device/ace/instance/check/workload/fleet-registry";
            };
          };
        }
        extra
      ];
    }).config;
  valid = c: builtins.all (a: a.assertion) c.assertions;
  configured = evaluate { };
  disabled = evaluate { kaiba.lanQualification.enable = lib.mkForce false; };
  roles = [
    "primary"
    "replica-a"
    "replica-b"
  ];
in
assert valid configured && valid disabled;
assert !disabled.kaiba.updateController.controller.allowNonGlobalAddresses;
assert !disabled.kaiba.deviceAgent.enable && !disabled.kaiba.updateController.enable;
assert !builtins.hasAttr "kaiba-lan-dns-primary" disabled.systemd.services;
assert configured.kaiba.deviceAgent.addresses == [ "192.168.8.214" ];
assert configured.kaiba.updateController.controller.allowNonGlobalAddresses;
assert
  configured.kaiba.updateController.publisher.observeServers == [
    "127.0.0.1:15353"
    "127.0.0.1:15354"
  ];
assert builtins.all (
  role:
  let
    name = "kaiba-lan-dns-${role}";
    service = configured.systemd.services.${name};
  in
  service.serviceConfig.User == name
  && service.serviceConfig.StateDirectory == name
  &&
    service.serviceConfig.LoadCredential
    == [ "keys.conf:/var/lib/kaiba-lan-dns/credentials/private/${role}.conf" ]
  && service.bindsTo == [ "firewall.service" ]
) roles;
assert !(lib.elem 15353 configured.networking.firewall.allowedTCPPorts);
assert lib.hasInfix "-s 192.168.8.249/32" configured.networking.firewall.extraCommands;
assert lib.hasInfix "--dports 15353,15354 -j DROP" configured.networking.firewall.extraCommands;
assert builtins.all (extra: !(valid (evaluate extra))) [
  { kaiba.lanQualification.allowedPeers = lib.mkForce [ ]; }
  { kaiba.lanQualification.allowedPeers = lib.mkForce [ "203.0.113.1" ]; }
  { kaiba.lanQualification.listenAddress = "0.0.0.0"; }
  { kaiba.lanQualification.listenAddress = "192.168.8.999"; }
  { kaiba.lanQualification.listenAddress = "192.168.08.214"; }
  { kaiba.lanQualification.replicaPorts.a = 15352; }
  { kaiba.lanQualification.primaryPort = 53; }
  { kaiba.lanQualification.zone = "invalid..example"; }
  { networking.firewall.enable = false; }
  { networking.nftables.enable = true; }
];
pkgs.runCommand "kaiba-lan-module-evaluation" { } ''
  mkdir -p $out
  echo 'Opt-in LAN DNS module assertions passed' > $out/result
''
