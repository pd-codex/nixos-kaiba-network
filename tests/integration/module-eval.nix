{
  pkgs,
  lib,
  kaibaPackage,
  kaibaModules,
}:

let
  fixtures = import ./fixtures.nix { inherit pkgs; };

  evaluateConfig =
    module:
    (lib.nixosSystem {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        kaibaModules.default
        {
          boot.loader.grub.devices = [ "nodev" ];
          fileSystems."/" = {
            device = "none";
            fsType = "tmpfs";
          };
          system.stateVersion = "26.05";
        }
        module
      ];
    }).config;

  evaluate = module: (evaluateConfig module).assertions;

  assertionsPass = module: builtins.all (assertion: assertion.assertion) (evaluate module);
  failedMessages =
    module:
    map (assertion: assertion.message) (
      builtins.filter (assertion: !assertion.assertion) (evaluate module)
    );

  primary = {
    kaiba.dns = {
      listenAddresses = [ "192.0.2.1" ];
      hiddenPrimary = {
        enable = true;
        initialZoneFile = fixtures.kaibaZone;
        publisherUpdate.keyFile = "/run/credentials/update.conf";
        standby = {
          address = "192.0.2.2";
          keyFile = "/run/credentials/standby.conf";
        };
        publicTransfer = {
          keyFile = "/run/credentials/public.conf";
          secondaries = [
            {
              id = "public-a";
              address = "192.0.2.3";
            }
          ];
        };
      };
    };
  };

  standby = {
    kaiba.dns = {
      listenAddresses = [ "192.0.2.2" ];
      hiddenStandby = {
        enable = true;
        primary = {
          address = "192.0.2.1";
          keyFile = "/run/credentials/standby.conf";
        };
        publicTransfer = {
          keyFile = "/run/credentials/public.conf";
          secondaries = [
            {
              id = "public-a";
              address = "192.0.2.3";
            }
          ];
        };
      };
    };
  };

  publicSecondary = {
    kaiba.dns = {
      listenAddresses = [ "192.0.2.3" ];
      publicSecondary = {
        enable = true;
        keyFiles = [ "/run/credentials/public.conf" ];
        masters = [
          {
            id = "p0";
            address = "192.0.2.1";
          }
          {
            id = "p1";
            address = "192.0.2.2";
          }
        ];
      };
    };
  };

  applicationServices = {
    kaiba.deviceAgent = {
      enable = true;
      package = kaibaPackage;
      endpoint = "https://updates.kaiba.network";
      addresses = [ "203.0.113.10" ];
      credentials = {
        clientCertificate = "/run/credentials/device.pem";
        clientKey = "/run/credentials/device-key.pem";
        serverCA = "/run/credentials/ca.pem";
      };
    };
    kaiba.updateController = {
      enable = true;
      credentials = {
        serverCertificate = "/run/credentials/controller.pem";
        serverKey = "/run/credentials/controller-key.pem";
        clientCA = "/run/credentials/ca.pem";
        publisherTSIGSecret = "/run/credentials/update.secret";
      };
      controller.package = kaibaPackage;
      publisher = {
        package = kaibaPackage;
        dnsServer = "192.0.2.1:53";
        observeServers = [
          "192.0.2.3:53"
          "192.0.2.4:53"
        ];
      };
    };
  };

  recursionViolation = lib.recursiveUpdate primary {
    kaiba.dns.recursion = true;
  };

  singleObserver = lib.recursiveUpdate applicationServices {
    kaiba.updateController.publisher.observeServers = [ "192.0.2.3:53" ];
  };

  duplicateObservers = lib.recursiveUpdate applicationServices {
    kaiba.updateController.publisher.observeServers = [
      "192.0.2.3:53"
      "192.0.2.3:53"
    ];
  };

  emptyObserver = lib.recursiveUpdate applicationServices {
    kaiba.updateController.publisher.observeServers = [
      "192.0.2.3:53"
      ""
    ];
  };

  applicationConfig = evaluateConfig applicationServices;
  controllerService = applicationConfig.systemd.services.kaiba-controller.serviceConfig;
  publisherService = applicationConfig.systemd.services.kaiba-publisher.serviceConfig;
  controllerUnit = applicationConfig.systemd.services.kaiba-controller;
  publisherUnit = applicationConfig.systemd.services.kaiba-publisher;
  serviceBoundary =
    applicationConfig.users.users.kaiba-controller.group == "kaiba-controller"
    && applicationConfig.users.users.kaiba-controller.extraGroups == [ ]
    && applicationConfig.users.users.kaiba-publisher.group == "kaiba-publisher"
    && applicationConfig.users.users.kaiba-publisher.extraGroups == [ ]
    && controllerService.User == "kaiba-controller"
    && controllerService.Group == "kaiba-controller"
    && controllerService.SupplementaryGroups == [ "kaiba-state" ]
    && controllerService.ReadWritePaths == [ "/var/lib/kaiba-controller" ]
    && controllerService.InaccessiblePaths == [ "/run/credentials/update.secret" ]
    && publisherService.User == "kaiba-publisher"
    && publisherService.Group == "kaiba-publisher"
    && publisherService.SupplementaryGroups == [ "kaiba-state" ]
    && publisherService.ReadWritePaths == [ "/var/lib/kaiba-controller" ]
    &&
      publisherService.InaccessiblePaths == [
        "/run/credentials/controller.pem"
        "/run/credentials/controller-key.pem"
        "/run/credentials/ca.pem"
      ]
    && builtins.elem "systemd-tmpfiles-setup.service" controllerUnit.requires
    && builtins.elem "systemd-tmpfiles-setup.service" controllerUnit.after
    && builtins.elem "systemd-tmpfiles-setup.service" publisherUnit.requires
    && builtins.elem "systemd-tmpfiles-setup.service" publisherUnit.after
    && builtins.elem "d /var/lib/kaiba-controller 2770 kaiba-controller kaiba-state - -" applicationConfig.systemd.tmpfiles.rules;

  sqlitePermissionPreparation =
    builtins.all (rule: builtins.elem rule applicationConfig.systemd.tmpfiles.rules)
      [
        "f /var/lib/kaiba-controller/desired-state.db 0660 kaiba-controller kaiba-state - -"
        "z /var/lib/kaiba-controller/desired-state.db-wal 0660 kaiba-controller kaiba-state - -"
        "z /var/lib/kaiba-controller/desired-state.db-shm 0660 kaiba-controller kaiba-state - -"
      ];

  invalidRejected = !assertionsPass recursionViolation;

  spiffeServices = lib.recursiveUpdate applicationServices {
    kaiba.deviceAgent = {
      identity = {
        mode = "spiffe";
        workloadAPISocket = "unix:///run/kaiba/identity/local/public/api.sock";
        controllerSPIFFEID = "spiffe://owner.test/device/controller/instance/one/workload/dns-controller";
      };
      credentials = {
        clientCertificate = null;
        clientKey = null;
        serverCA = null;
      };
    };
    kaiba.updateController = {
      identity = {
        mode = "spiffe";
        workloadAPISocket = "unix:///run/kaiba/identity/local/public/api.sock";
        trustDomain = "owner.test";
        fleetAuthorizationURL = "https://fleet.test:8096";
        fleetServerSPIFFEID = "spiffe://owner.test/device/fleet/instance/one/workload/registry";
      };
      credentials = {
        serverCertificate = null;
        serverKey = null;
        clientCA = null;
      };
    };
  };
  spiffeConfig = evaluateConfig spiffeServices;
  spiffeAgent = spiffeConfig.systemd.services.kaiba-agent.serviceConfig;
  spiffeController = spiffeConfig.systemd.services.kaiba-controller.serviceConfig;
  spiffePublisher = spiffeConfig.systemd.services.kaiba-publisher.serviceConfig;
  spiffeBoundary =
    builtins.elem "AF_UNIX" spiffeAgent.RestrictAddressFamilies
    && lib.hasInfix "--workload-api-socket" spiffeAgent.ExecStart
    && lib.hasInfix "--controller-spiffe-id" spiffeAgent.ExecStart
    && !(lib.hasInfix "--client-cert" spiffeAgent.ExecStart)
    && lib.hasInfix "--fleet-authorization-url" spiffeController.ExecStart
    && lib.hasInfix "--fleet-server-spiffe-id" spiffeController.ExecStart
    && !(lib.hasInfix "--tls-cert" spiffeController.ExecStart)
    && spiffeController.InaccessiblePaths == [ "/run/credentials/update.secret" ]
    && spiffePublisher.InaccessiblePaths == [ "-/run/kaiba/identity/local/public/api.sock" ]
    && lib.hasInfix "--tsig-secret-file" spiffePublisher.ExecStart
    && !(lib.hasInfix "--workload-api-socket" spiffePublisher.ExecStart);
in
assert lib.assertMsg (assertionsPass spiffeServices) (
  builtins.toJSON (failedMessages spiffeServices)
);
assert lib.assertMsg spiffeBoundary "SPIFFE transport or publisher isolation is not enforced";
assert lib.assertMsg (
  !assertionsPass (
    lib.recursiveUpdate spiffeServices {
      kaiba.deviceAgent.credentials.clientKey = "/run/unexpected.key";
    }
  )
) "mixed SPIFFE and file agent credentials were accepted";
assert lib.assertMsg (
  !assertionsPass (
    lib.recursiveUpdate spiffeServices {
      kaiba.updateController.credentials.serverKey = "/run/unexpected.key";
    }
  )
) "mixed SPIFFE and file controller credentials were accepted";
assert lib.assertMsg (
  !assertionsPass (
    lib.recursiveUpdate spiffeServices {
      kaiba.updateController.identity.fleetServerSPIFFEID = "";
    }
  )
) "missing exact fleet server ID was accepted";
assert lib.assertMsg (
  !assertionsPass (
    lib.recursiveUpdate spiffeServices {
      kaiba.updateController.identity.fleetAuthorizationURL = "http://fleet.test";
    }
  )
) "insecure fleet authorization endpoint was accepted";
assert lib.assertMsg (
  !assertionsPass (
    lib.recursiveUpdate spiffeServices {
      kaiba.deviceAgent.identity.workloadAPISocket = "unix://remote/run/socket";
    }
  )
) "remote workload socket was accepted";
assert lib.assertMsg (assertionsPass primary) (builtins.toJSON (failedMessages primary));
assert lib.assertMsg (assertionsPass standby) (builtins.toJSON (failedMessages standby));
assert lib.assertMsg (assertionsPass publicSecondary) (
  builtins.toJSON (failedMessages publicSecondary)
);
assert lib.assertMsg (assertionsPass applicationServices) (
  builtins.toJSON (failedMessages applicationServices)
);
assert invalidRejected;
assert lib.assertMsg (!assertionsPass singleObserver) "one observation endpoint was accepted";
assert lib.assertMsg (
  !assertionsPass duplicateObservers
) "duplicate observation endpoints were accepted";
assert lib.assertMsg (!assertionsPass emptyObserver) "an empty observation endpoint was accepted";
assert lib.assertMsg serviceBoundary "controller/publisher service boundary is not enforced";
assert lib.assertMsg sqlitePermissionPreparation "SQLite shared-file modes are not prepared";
pkgs.runCommand "kaiba-dns-module-evaluation" { } ''
  mkdir -p "$out"
  printf '%s\n' \
    'primary: pass' \
    'standby: pass' \
    'public-secondary: pass' \
    'application-services: pass' \
    'spiffe-current-authorization-and-publisher-isolation: pass' \
    'spiffe-file-mode-exclusivity: pass' \
    'controller-publisher-uid-and-state-boundary: pass' \
    'sqlite-main-wal-shm-permissions-prepared: pass' \
    'two-distinct-nonempty-observers-required: pass' \
    'authoritative-recursion-rejected: pass' \
    > "$out/results.txt"
''
