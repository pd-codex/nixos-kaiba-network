{
  pkgs,
  lib,
  kaibaPackage,
  kaibaModules,
}:
pkgs.testers.runNixOSTest {
  name = "kaiba-lan-two-host-dns";
  globalTimeout = 600;
  requiredFeatures.kvm = false;
  nodeDefaults = {
    virtualisation.memorySize = 512;
    virtualisation.cores = 1;
    environment.systemPackages = [
      pkgs.bind.dnsutils
      pkgs.python3
      pkgs.util-linux
    ];
    networking.useDHCP = false;
    system.stateVersion = "26.05";
  };
  nodes = {
    primary = {
      imports = [ kaibaModules.lan-primary ];
      networking.interfaces.eth1.ipv4.addresses = [
        {
          address = "192.168.50.1";
          prefixLength = 24;
        }
        {
          address = "192.168.50.4";
          prefixLength = 24;
        }
      ];
      kaiba.lanPrimary = {
        enable = true;
        listenAddress = "192.168.50.1";
        secondary.address = "192.168.50.2";
      };
      kaiba.deviceAgent = {
        package = kaibaPackage;
        identity = {
          workloadAPISocket = "unix:///run/fixture-unavailable/api.sock";
          controllerSPIFFEID = "spiffe://pilot.kaiba.pseudo.design/service/dns-controller";
        };
      };
      kaiba.updateController = {
        controller.package = kaibaPackage;
        publisher.package = kaibaPackage;
        identity = {
          workloadAPISocket = "unix:///run/fixture-unavailable/api.sock";
          trustDomain = "pilot.kaiba.pseudo.design";
          fleetAuthorizationURL = "https://127.0.0.1:8096/api/v1/workloads/authorize-dns";
          fleetServerSPIFFEID = "spiffe://pilot.kaiba.pseudo.design/service/workload-registry";
        };
      };
      # Focused real DNS transport test; the fleet integration checks the real
      # SPIFFE authorization/application path. No fake source or allow fallback.
      systemd.services.kaiba-controller.wantedBy = lib.mkForce [ ];
      systemd.services.kaiba-publisher.wantedBy = lib.mkForce [ ];
      systemd.services.kaiba-agent.wantedBy = lib.mkForce [ ];
    };
    secondary = {
      imports = [ kaibaModules.lan-secondary ];
      networking.interfaces.eth1.ipv4.addresses = [
        {
          address = "192.168.50.2";
          prefixLength = 24;
        }
        {
          address = "192.168.50.3";
          prefixLength = 24;
        }
      ];
      kaiba.lanSecondary = {
        enable = true;
        listenAddress = "192.168.50.2";
        primary.address = "192.168.50.1";
        transferSecretFile = "/run/qualification/transfer.secret";
      };
      systemd.services.kaiba-lan-secondary.wantedBy = lib.mkForce [ ];
    };
  };
  testScript = ''
    import json
    import os
    import shlex
    import time

    start_all()
    primary.wait_for_unit("kaiba-lan-primary")
    secondary.wait_for_unit("multi-user.target")
    secondary.wait_until_succeeds("ip -4 address show dev eth1 | grep -q 192.168.50.2")
    zone = "pilot.kaiba.pseudo.design"
    name = "pi-001." + zone
    credentials = "/var/lib/kaiba-lan-primary-credentials/credentials"
    checks = []

    # Synthetic out-of-band handoff via a private build-temp directory, never
    # copy_from_vm (which persists files in $out), command output or the store.
    primary.succeed("install -d -m0700 /tmp/shared/dns-transfer")
    primary.succeed(f"install -m0600 {credentials}/private/transfer.secret /tmp/shared/dns-transfer/transfer.secret")
    secondary.succeed("install -d -m0700 /run/qualification; install -m0600 /tmp/shared/dns-transfer/transfer.secret /run/qualification/transfer.secret")
    primary.succeed("rm /tmp/shared/dns-transfer/transfer.secret; rmdir /tmp/shared/dns-transfer")
    secondary.succeed("systemctl start kaiba-lan-secondary")
    secondary.wait_for_unit("kaiba-lan-secondary")
    secondary.wait_until_succeeds(f"dig @127.0.0.1 -p 15353 {zone} SOA +short | grep -q hostmaster")
    assert "AXFR" in secondary.succeed("journalctl -u kaiba-lan-secondary --no-pager -o cat")
    checks.append("cross-host-initial-axfr")

    def query(machine, address, port, record, rr="A", source=None):
        bind = "" if source is None else "-b " + source
        return machine.succeed(f"dig @{address} -p {port} {bind} {record} {rr} +short +time=1 +tries=1").strip()

    def make_key(machine, source, output, keyname):
        program = "import pathlib,os; os.umask(0o077); secret=pathlib.Path(" + repr(source) + ").read_text().strip(); pathlib.Path(" + repr(output) + ").write_text('key " + keyname + " { algorithm hmac-sha256; secret '+chr(34)+secret+chr(34)+'; };')"
        machine.succeed("python3 -c " + shlex.quote(program))

    make_key(primary, credentials + "/publisher/update.secret", "/run/update.key", "kaiba-lan-update")
    make_key(secondary, "/run/qualification/transfer.secret", "/run/transfer.key", "kaiba-lan-transfer")

    def update(machine, address, target="127.0.0.1", port=15352, key="/run/update.key"):
        text = f"server {target} {port}\nzone {zone}.\nupdate delete {name}. A\nupdate add {name}. 60 A {address}\nsend\n"
        machine.succeed("printf %s " + shlex.quote(text) + " > /run/update.txt")
        return machine.execute("nsupdate -t 3 " + ("-k " + key + " " if key else "") + "/run/update.txt")

    # The zone refresh is300s; convergence within30s after initial AXFR proves
    # authenticated NOTIFY drove this update, rather than the refresh timer.
    assert int(query(secondary, "127.0.0.1", 15353, zone, "SOA").split()[3]) == 300
    started = time.monotonic()
    assert update(primary, "192.168.50.1")[0] == 0
    secondary.wait_until_succeeds(f"test \"$(dig @127.0.0.1 -p 15353 {name} A +short)\" = 192.168.50.1", timeout=30)
    assert time.monotonic() - started < 60
    assert query(primary, "192.168.50.2", 15353, name) == "192.168.50.1"
    checks.append("cross-host-notify-propagation")
    assert name in secondary.succeed(f"dig -k /run/transfer.key @192.168.50.1 -p 15352 {zone} AXFR +time=2 +tries=1")
    assert "Transfer failed" in secondary.succeed(f"dig @192.168.50.1 -p 15352 {zone} AXFR +time=2 +tries=1")
    assert "Transfer failed" in primary.succeed(f"dig -k /run/update.key @127.0.0.1 -p 15352 {zone} AXFR")
    assert update(secondary, "192.168.50.99", target="192.168.50.1", key="/run/transfer.key")[0] != 0
    assert update(primary, "192.168.50.99", key=None)[0] != 0
    for key in (None, "/run/transfer.key"):
        assert update(secondary, "192.168.50.99", port=15353, key=key)[0] != 0
    assert "Transfer failed" in secondary.succeed(f"dig -k /run/transfer.key @127.0.0.1 -p 15353 {zone} AXFR")
    checks.append("update-transfer-role-isolation-and-readonly-secondary")

    for transport in ("", "+tcp"):
        secondary.fail(f"dig @192.168.50.1 -p 15352 -b 192.168.50.3 {zone} SOA {transport} +time=1 +tries=1")
        primary.fail(f"dig @192.168.50.2 -p 15353 -b 192.168.50.4 {zone} SOA {transport} +time=1 +tries=1")
    primary.succeed("iptables -A nixos-fw -p tcp --dport 15352 -j nixos-fw-accept")
    secondary.fail(f"dig -k /run/transfer.key @192.168.50.1 -p 15352 -b 192.168.50.3 {zone} AXFR +time=1 +tries=1")
    primary.succeed("systemctl reload firewall")
    checks.append("tcp-udp-source-firewall-before-broad-allow")

    # The secondary host never receives an update credential or publisher user.
    secondary.fail("getent passwd kaiba-publisher")
    secondary.succeed("test ! -e /var/lib/kaiba-lan-primary-credentials")
    for machine, role in [(primary, "primary"), (secondary, "secondary")]:
        machine.succeed(f"test \"$(stat -c '%U %a' /var/lib/kaiba-lan-{role})\" = 'kaiba-lan-{role} 700'")
        machine.fail(f"runuser -u kaiba-lan-{role} -- cat /var/lib/kaiba-lan-{role}-credentials/credentials/private/keys.json")
    primary.fail(f"runuser -u kaiba-controller -- test -r {credentials}/publisher/update.secret")
    primary.succeed(f"runuser -u kaiba-publisher -- test -r {credentials}/publisher/update.secret")
    checks.append("host-and-unix-credential-separation")

    secondary.succeed("systemctl stop kaiba-lan-secondary")
    assert update(primary, "192.168.50.9")[0] == 0
    secondary.succeed("systemctl start kaiba-lan-secondary")
    secondary.wait_until_succeeds(f"test \"$(dig @127.0.0.1 -p 15353 {name} A +short)\" = 192.168.50.9")
    primary.succeed("systemctl stop kaiba-lan-primary")
    assert query(secondary, "127.0.0.1", 15353, name) == "192.168.50.9"
    assert update(secondary, "192.168.50.99", port=15353, key="/run/transfer.key")[0] != 0
    secondary.succeed("systemctl restart kaiba-lan-secondary")
    secondary.wait_until_succeeds(f"test \"$(dig @127.0.0.1 -p 15353 {name} A +short)\" = 192.168.50.9")
    primary.succeed("systemctl start kaiba-lan-primary")
    primary.wait_until_succeeds(f"test \"$(dig @127.0.0.1 -p 15352 {name} A +short)\" = 192.168.50.9")
    checks.append("independent-primary-outage-secondary-journal-and-catchup")

    # Credential revalidation does not generate fresh secrets. Missing or
    # changed imported material fails closed and leaves persistent bytes alone.
    primary.succeed(f"cp {credentials}/private/keys.json /run/before-primary-keys; systemctl restart kaiba-lan-primary-credentials; cmp /run/before-primary-keys {credentials}/private/keys.json")
    secondary.succeed("cp /var/lib/kaiba-lan-secondary-credentials/credentials/private/keys.json /run/before-secondary-keys; systemctl stop kaiba-lan-secondary; mv /run/qualification/transfer.secret /run/saved-transfer.secret")
    secondary.fail("systemctl restart kaiba-lan-secondary-credentials")
    secondary.succeed("mv /run/saved-transfer.secret /run/qualification/transfer.secret; cp /run/qualification/transfer.secret /run/saved-transfer.secret")
    secondary.succeed("python3 -c 'import base64,secrets,pathlib; pathlib.Path(\"/run/qualification/transfer.secret\").write_text(base64.b64encode(secrets.token_bytes(32)).decode()+\"\\n\")'")
    secondary.fail("systemctl restart kaiba-lan-secondary-credentials")
    secondary.succeed("cmp /run/before-secondary-keys /var/lib/kaiba-lan-secondary-credentials/credentials/private/keys.json; mv /run/saved-transfer.secret /run/qualification/transfer.secret; systemctl reset-failed kaiba-lan-secondary-credentials; systemctl start kaiba-lan-secondary")
    secondary.wait_until_succeeds(f"test \"$(dig @127.0.0.1 -p 15353 {name} A +short)\" = 192.168.50.9")
    checks.append("persistent-key-reuse-and-missing-or-changed-import-denial")
    primary.succeed("systemctl stop kaiba-lan-primary; mv /var/lib/kaiba-lan-primary-credentials /var/lib/kaiba-lan-primary-credentials.saved")
    primary.fail("systemctl restart kaiba-lan-primary-credentials")
    primary.succeed("test ! -e /var/lib/kaiba-lan-primary-credentials/credentials; rmdir /var/lib/kaiba-lan-primary-credentials; mv /var/lib/kaiba-lan-primary-credentials.saved /var/lib/kaiba-lan-primary-credentials; systemctl reset-failed kaiba-lan-primary-credentials; systemctl start kaiba-lan-primary")
    primary.succeed(f"cmp /run/before-primary-keys {credentials}/private/keys.json")
    primary.wait_until_succeeds(f"test \"$(dig @127.0.0.1 -p 15352 {name} A +short)\" = 192.168.50.9")
    checks.append("lost-credential-base-with-retained-journal-denied")
    with open(os.environ["out"] + "/lan-two-host-result.json", "w") as stream:
        json.dump({"status":"passed", "synthetic":True, "hardware_qualified":False,
                   "application_path_checked":False, "separate_dns_hosts":True, "checks":checks}, stream)
  '';
}
