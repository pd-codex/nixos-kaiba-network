# LAN DNS qualification

The `lan-qualification` NixOS module is an explicit, opt-in qualification profile
for `pilot.kaiba.pseudo.design`. It composes the existing SPIFFE controller,
publisher, and updater with three separate Knot processes on the same host. It
does not establish public delegation, open port 53, configure recursion, change a
LAN resolver, or provide independent-host availability.

| Component | Default endpoint | Persistent state |
| --- | --- | --- |
| Writable primary | `127.0.0.1:15352` | `/var/lib/kaiba-lan-dns-primary` |
| Read-only replica A | `127.0.0.1:15353`, `192.168.8.214:15353` | `/var/lib/kaiba-lan-dns-replica-a` |
| Read-only replica B | `127.0.0.1:15354`, `192.168.8.214:15354` | `/var/lib/kaiba-lan-dns-replica-b` |
| SPIFFE update controller | `https://127.0.0.1:18443` | Existing controller SQLite state |

The replicas are distinct Unix users, processes, control sockets, transfer keys,
and journals. Both transfer from the sole writable primary; neither accepts
updates or serves outbound AXFR. The publisher verifies both loopback replica
endpoints. Their in-zone NS records are bootstrap data for this private test;
ordinary delegated DNS cannot encode these nonstandard ports.

## Host composition

Import `inputs.kaiba-dns.nixosModules.lan-qualification` and enable:

```nix
kaiba.lanQualification = {
  enable = true;
  zone = "pilot.kaiba.pseudo.design";
  listenAddress = "192.168.8.214";
  allowedPeers = [ "192.168.8.249" ]; # Explicitly approved qualification station.
};
```

The host must also supply `kaiba.deviceAgent.package`,
`kaiba.updateController.controller.package`, and
`kaiba.updateController.publisher.package`, plus the existing SPIFFE options:

- `kaiba.deviceAgent.identity.workloadAPISocket` and `controllerSPIFFEID`.
- `kaiba.updateController.identity.workloadAPISocket`, `trustDomain`,
  `fleetAuthorizationURL`, and `fleetServerSPIFFEID`.

These must reference real registered workloads and the authenticated current
fleet registry. The profile does not mint SPIFFE registrations, enroll a device,
or create a DNS assignment. Supply the actual current enrollment/instance and
operator-approved numeric DNS assignment through the fleet registry. A device's
logical ID is not a DNS device number. The resulting expected name is
`pi-<assigned-number>.pilot.kaiba.pseudo.design`.

Only this enabled qualification profile sets
`kaiba.updateController.controller.allowNonGlobalAddresses = true` and submits
the explicit host LAN address; the ordinary controller default remains false.
No WAN address is inferred. The firewall must use the enabled NixOS iptables
backend. Early rules limit UDP and TCP queries to `allowedPeers` on the configured
LAN address even if another service broadly allows the same port. The Knot units
are ordered after and bound to the firewall. Host composition must avoid port
conflicts with other services.

## Runtime credentials and restart

`kaiba-lan-dns-credentials.service` creates three independent random 256-bit
HMAC-SHA256 TSIG secrets on the host, outside the Nix store. No checked-in fixture
key is reused. Root-only material lives under
`/var/lib/kaiba-lan-dns/credentials/private`; systemd loads only the relevant Knot
include into each process's credential directory. The publisher can read only
its update secret under `credentials/publisher`; the controller and updater have
no TSIG access. The primary accepts that key only from loopback, for A/AAAA
updates in this zone. Transfer keys authorize transfer to their respective
replica and authenticated NOTIFY, and do not authorize updates.

Credentials and journals persist across service restarts. The helper validates
ownership, modes, file types, key encoding, and consistency before reuse. Missing,
partial, linked, or modified credential files stop initialization; they are not
silently replaced. An incomplete first initialization also requires explicit
operator recovery. Back up and restore the complete private credential tree,
initialization marker, and three journals consistently. Do not display secret
files, place their contents in argv, or copy them into configuration/source.

Disable `kaiba.lanQualification.enable` to remove these units and firewall rules;
retain state for a reviewed rollback. A replica outage leaves the other replica
queryable, but successful publication still requires both observations. A primary
outage permits reads of the retained replica zone until SOA expiry; replicas are
never promoted automatically. This same-host topology does not qualify power
loss, machine failure, offline rollback protection, production availability, or
public DNS reachability.

## Validation

```console
nix build .#checks.x86_64-linux.lan-module-eval --no-link -L
nix build .#checks.x86_64-linux.lan-qualification --no-link -L
```

The focused two-machine VM uses runtime-generated keys to check signed updates,
initial transfers and propagation to both distinct replicas, narrow UDP/TCP LAN
access, unsigned/replica update denial, UID/state separation, replica recovery,
primary-outage reads, journal persistence, and credential reuse/failure. It
intentionally leaves the SPIFFE application units stopped: the existing fleet
integration VM covers registry/controller/publisher/updater authorization, and a
native full-stack run must verify the actual enrollment and resulting LAN record.
Its `lan-qualification-result.json` explicitly marks synthetic evidence and the
unchecked application/hardware scope. On 2026-09-29, the two-machine VM passed all
15 checks in 132 seconds under QEMU TCG. The new and existing module checks,
workflow syntax check, and all-system flake evaluation also passed locally.
Remote CI and native activation remain pending.

For the authorized native run, record the exact enrollment/instance and assignment,
workload identities, systemd units, DNS serials, assigned A response from both
replicas, successful actual-updater request, and registry quarantine/recovery
results. Query from the approved station with an explicit port, for example
`dig @192.168.8.214 -p 15353 pi-<assigned-number>.pilot.kaiba.pseudo.design A`.
Do not treat direct TSIG updates in the focused VM as proof of the native SPIFFE
authorization path.
