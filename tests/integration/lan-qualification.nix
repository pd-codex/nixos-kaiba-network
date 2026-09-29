{
  pkgs,
  lib,
  kaibaPackage,
  kaibaModules,
}:
pkgs.testers.runNixOSTest {
  name = "kaiba-lan-dns-qualification";
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
    server = {
      imports = [ kaibaModules.lan-qualification ];
      networking.interfaces.eth1.ipv4.addresses = [
        {
          address = "192.168.50.1";
          prefixLength = 24;
        }
      ];
      kaiba.lanQualification = {
        enable = true;
        listenAddress = "192.168.50.1";
        allowedPeers = [ "192.168.50.2" ];
      };
      kaiba.deviceAgent = {
        package = kaibaPackage;
        identity = {
          workloadAPISocket = "unix:///run/qualification-unavailable/api.sock";
          controllerSPIFFEID = "spiffe://pilot.kaiba.pseudo.design/device/ace/instance/fixture/workload/dns-controller";
        };
      };
      kaiba.updateController = {
        controller.package = kaibaPackage;
        publisher.package = kaibaPackage;
        identity = {
          workloadAPISocket = "unix:///run/qualification-unavailable/api.sock";
          trustDomain = "pilot.kaiba.pseudo.design";
          fleetAuthorizationURL = "https://127.0.0.1:8096/api/v1/workloads/authorize-dns";
          fleetServerSPIFFEID = "spiffe://pilot.kaiba.pseudo.design/device/ace/instance/fixture/workload/fleet-registry";
        };
      };
      # This check covers the reusable Knot profile. The separate fleet/DNS VM
      # and native pilot qualify the real registry + Workload API application path.
      systemd.services.kaiba-controller.wantedBy = lib.mkForce [ ];
      systemd.services.kaiba-publisher.wantedBy = lib.mkForce [ ];
      systemd.services.kaiba-agent.wantedBy = lib.mkForce [ ];
    };
    client = {
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
    };
  };
  testScript = ''
    import json
    import os
    import shlex

    start_all()
    for role in ["primary", "replica-a", "replica-b"]:
        server.wait_for_unit("kaiba-lan-dns-" + role)
    client.wait_for_unit("multi-user.target")
    client.wait_until_succeeds("ip -4 address show dev eth1 | grep -q 192.168.50.2")
    zone = "pilot.kaiba.pseudo.design"
    name = "pi-001." + zone
    base = "/var/lib/kaiba-lan-dns/credentials"

    def query(machine, port, record, rr="A", source=None, address="127.0.0.1"):
        bind = "" if source is None else "-b " + source
        return machine.succeed(f"dig @{address} -p {port} {bind} {record} {rr} +short +time=1 +tries=1").strip()

    for port in [15352, 15353, 15354]:
        server.wait_until_succeeds(f"dig @127.0.0.1 -p {port} {zone} SOA +short | grep -q hostmaster")
    for port in [15353, 15354]:
        assert "hostmaster" in query(client, port, zone, "SOA", "192.168.50.2", "192.168.50.1")
        client.fail(f"dig @192.168.50.1 -p {port} -b 192.168.50.3 {zone} SOA +time=1 +tries=1")
        client.fail(f"dig @192.168.50.1 -p {port} -b 192.168.50.3 {zone} SOA +tcp +time=1 +tries=1")
    server.succeed("iptables -A nixos-fw -p udp --dport 15353 -j nixos-fw-accept")
    client.fail(f"dig @192.168.50.1 -p 15353 -b 192.168.50.3 {zone} SOA +time=1 +tries=1")
    server.succeed("systemctl reload firewall")
    client.fail(f"dig @192.168.50.1 -p 15352 -b 192.168.50.2 {zone} SOA +time=1 +tries=1")

    # Build a root-only nsupdate credential from the generated secret inside
    # the VM. Its value never enters the test log, argv, or Nix store.
    key_script = (
        "import pathlib,os; os.umask(0o077); "
        f"secret=pathlib.Path('{base}/publisher/update.secret').read_text().strip(); "
        "pathlib.Path('/run/update.key').write_text('key kaiba-lan-update { algorithm hmac-sha256; secret '+chr(34)+secret+chr(34)+'; };')"
    )
    server.succeed("python3 -c " + shlex.quote(key_script))

    def update(address, port=15352, signed=True, key="/run/update.key"):
        request = f"server 127.0.0.1 {port}\nzone {zone}.\nupdate delete {name}. A\nupdate add {name}. 60 A {address}\nsend\n"
        server.succeed("printf %s " + shlex.quote(request) + " > /run/update.txt")
        command = "nsupdate " + ("-k " + shlex.quote(key) + " " if signed else "") + "/run/update.txt"
        return server.execute(command)

    assert update("192.168.50.1")[0] == 0
    for port in [15352, 15353, 15354]:
        server.wait_until_succeeds(f"test \"$(dig @127.0.0.1 -p {port} {name} A +short)\" = 192.168.50.1")
    for port in [15352, 15353, 15354]:
        assert update("192.168.50.99", port, signed=False)[0] != 0
        assert "Transfer failed" in server.succeed(f"dig @127.0.0.1 -p {port} {zone} AXFR")
    for port in [15353, 15354]:
        assert update("192.168.50.99", port)[0] != 0
    assert query(server, 15352, name) == "192.168.50.1"
    transfer_key_script = (
        "import pathlib,os,json; os.umask(0o077); "
        f"secret=json.loads(pathlib.Path('{base}/private/keys.json').read_text())['transfer-a']; "
        "pathlib.Path('/run/transfer-a.key').write_text('key kaiba-lan-transfer-a { algorithm hmac-sha256; secret '+chr(34)+secret+chr(34)+'; };')"
    )
    server.succeed("python3 -c " + shlex.quote(transfer_key_script))
    assert update("192.168.50.99", key="/run/transfer-a.key")[0] != 0
    assert "Transfer failed" in server.succeed(f"dig -k /run/update.key @127.0.0.1 -p 15352 {zone} AXFR")
    assert name in server.succeed(f"dig -k /run/transfer-a.key @127.0.0.1 -p 15352 {zone} AXFR")

    pids = [server.succeed("systemctl show --value -p MainPID kaiba-lan-dns-" + role).strip() for role in ["primary", "replica-a", "replica-b"]]
    assert len(set(pids)) == 3 and "0" not in pids
    for role in ["primary", "replica-a", "replica-b"]:
        assert server.succeed(f"stat -c '%U %a' /var/lib/kaiba-lan-dns-{role}").strip() == f"kaiba-lan-dns-{role} 700"
        server.fail(f"runuser -u kaiba-lan-dns-{role} -- cat {base}/publisher/update.secret")
    server.succeed(f"runuser -u kaiba-publisher -- test -r {base}/publisher/update.secret")
    server.fail(f"runuser -u kaiba-controller -- test -r {base}/publisher/update.secret")
    server.fail(f"runuser -u kaiba-publisher -- test -r {base}/private/primary.conf")
    # Failover means continued read service, never promoting a replica to writer.
    server.succeed("systemctl stop kaiba-lan-dns-replica-a")
    assert update("192.168.50.9")[0] == 0
    server.wait_until_succeeds(f"test \"$(dig @127.0.0.1 -p 15354 {name} A +short)\" = 192.168.50.9")
    server.succeed("systemctl start kaiba-lan-dns-replica-a")
    server.wait_until_succeeds(f"test \"$(dig @127.0.0.1 -p 15353 {name} A +short)\" = 192.168.50.9")
    server.succeed("systemctl stop kaiba-lan-dns-primary")
    for port in [15353, 15354]:
        assert query(server, port, name) == "192.168.50.9"
        assert update("192.168.50.99", port)[0] != 0
    server.succeed("systemctl start kaiba-lan-dns-primary")
    server.wait_until_succeeds(f"test \"$(dig @127.0.0.1 -p 15352 {name} A +short)\" = 192.168.50.9")

    before = server.succeed(f"sha256sum {base}/private/keys.json")
    server.succeed("systemctl restart kaiba-lan-dns-credentials")
    assert before == server.succeed(f"sha256sum {base}/private/keys.json")
    # Missing persisted material fails closed; no replacement keys are minted.
    server.succeed(f"mv {base}/private/replica-a.conf /run/saved-replica.conf")
    server.fail("systemctl restart kaiba-lan-dns-credentials")
    assert before == server.succeed(f"sha256sum {base}/private/keys.json")
    server.succeed(f"mv /run/saved-replica.conf {base}/private/replica-a.conf")
    server.succeed("systemctl reset-failed; systemctl start kaiba-lan-dns-credentials")
    server.succeed(f"mv {base}/private/replica-a.conf /run/saved-replica.conf; ln -s /run/saved-replica.conf {base}/private/replica-a.conf")
    server.fail("systemctl restart kaiba-lan-dns-credentials")
    server.succeed(f"rm {base}/private/replica-a.conf; mv /run/saved-replica.conf {base}/private/replica-a.conf")
    server.succeed("systemctl reset-failed; systemctl start kaiba-lan-dns-credentials")
    server.succeed(f"mv {base} /var/lib/kaiba-lan-dns/saved-credentials")
    server.fail("systemctl restart kaiba-lan-dns-credentials")
    server.succeed(f"test ! -e {base}; mv /var/lib/kaiba-lan-dns/saved-credentials {base}")
    server.succeed("systemctl reset-failed; systemctl start kaiba-lan-dns-credentials")
    with open("/tmp/lan-qualification-result.json", "w") as stream:
        json.dump({"status": "passed", "synthetic": True, "hardware_qualified": False,
          "application_path_checked": False,
          "checks": ["private-runtime-keys", "signed-update", "two-distinct-replicas", "lan-peer-firewall", "unsigned-denial", "replicas-read-only", "transfer-update-key-isolation", "uid-and-state-isolation", "replica-recovery", "primary-outage-read-only", "journal-restart", "credential-reuse", "missing-credential-denial", "linked-credential-denial", "removed-credential-tree-denial"]}, stream)
    import shutil
    shutil.copyfile("/tmp/lan-qualification-result.json", os.environ["out"] + "/lan-qualification-result.json")
  '';
}
