# Two-host LAN DNS pilot

`lan-primary` and `lan-secondary` place the writable DNS primary on Ace and a
read-only secondary on Mako. The publisher observes the primary and secondary
as two distinct endpoints on different hosts. The existing public DNS profile
and its two-authority assertions are unchanged. This explicit private profile
does not configure public delegation, recursive DNS or a router resolver.

| Host | DNS role | Default endpoint | Other identity/application roles |
| --- | --- | --- | --- |
| Ace | Sole writable primary | `192.168.8.214:15352`, plus loopback | SPIRE server/local agent; existing SPIFFE updater/controller/publisher |
| Mako | Read-only secondary | `192.168.8.247:15353`, plus loopback | Independently configured SPIRE member; no DNS controller, publisher or update credential |
| Operator workstation | Explicit query client | No DNS listener required | Administration only; this DNS profile requires no runtime service there |

The DNS modules configure only the roles in their options. Host composition must
separately provide the SPIRE roles, current inventory authority, registry and
exact workload registrations. The primary's updater still needs an explicit
current fleet DNS assignment; the profile neither grants permission nor supplies
a registry fallback. This separation lets the operator workstation leave after
provisioning without making it the DNS transfer source.

## Primary configuration

```nix
{
  imports = [ inputs.kaiba-dns.nixosModules.lan-primary ];
  kaiba.lanPrimary = {
    enable = true;
    zone = "pilot.kaiba.pseudo.design";
    listenAddress = "192.168.8.214";
    port = 15352;
    secondary = { address = "192.168.8.247"; port = 15353; };
    queryAllowedPeers = [ "192.168.8.249" ];
  };
}
```

Supply the existing `kaiba.deviceAgent.package`, controller/publisher packages,
and SPIFFE options described in [LAN qualification](lan-qualification.md#host-composition).
The controller defaults to loopback port 18443. A migrated pilot issuer already
uses 18443, so that host must select a distinct controller port, for example
`kaiba.updateController.controller.port = 18447;`; the updater endpoint follows
this setting. The fleet authorization URL and exact registry identity must point
to the actual continuously available registry.
The module sets only the explicit private-address update exception, selected host
address, primary DNS endpoint and observation endpoints. The publisher's existing
two-endpoint observation gate remains in force: `127.0.0.1:15352` and
`192.168.8.247:15353`. One secondary is not two independent public authorities.

## Secondary configuration

```nix
{
  imports = [ inputs.kaiba-dns.nixosModules.lan-secondary ];
  kaiba.lanSecondary = {
    enable = true;
    zone = "pilot.kaiba.pseudo.design";
    listenAddress = "192.168.8.247";
    port = 15353;
    primary = { address = "192.168.8.214"; port = 15352; };
    queryAllowedPeers = [ "192.168.8.249" ];
    transferSecretFile = "/var/lib/kaiba-lan-secondary-admission/transfer.secret";
  };
}
```

The secondary enables no updater, controller or publisher. Its SPIRE agent is
configured separately by the host identity module. Knot transfer and NOTIFY use
a dedicated TSIG key, not a SPIFFE SVID or the update key. The secondary accepts
NOTIFY only from the configured primary with that key. It accepts no dynamic
updates and serves no outbound transfers, including to a client holding the
transfer key.

Both modules require explicit distinct RFC1918 addresses and unprivileged ports.
The enabled NixOS iptables firewall admits only the partner host, explicit query
peers and loopback, for TCP and UDP. Early destination/port drops prevent broad
port allowances elsewhere from bypassing that restriction. Each Knot service
follows and binds to the firewall. Host composition must assign the selected
addresses and avoid port conflicts. Both roles disabled produce no services or
firewall rules; the old same-host profile cannot be enabled alongside these roles.

## Credential handoff and state

On Ace, `kaiba-lan-primary-credentials.service` generates separate random 256-bit
HMAC-SHA256 update and transfer secrets. Persistent root-only material lives in
`/var/lib/kaiba-lan-primary-credentials/credentials/private`. Only the publisher
can read `credentials/publisher/update.secret`. Knot receives its include through
systemd `LoadCredential`; the controller and updater cannot read either secret.

Transfer **only** this root-owned0600 file to Mako through the operator's
verified, authenticated transport:

```text
/var/lib/kaiba-lan-primary-credentials/credentials/private/transfer.secret
```

Provision Mako's configured `transferSecretFile` as a root-owned0600 regular file
with a single link, under root-owned parent directories that are not writable by
group or others. Its contents are exactly the canonical base64 secret and one
newline. Retain it at that private runtime path for subsequent starts. Never
place bytes in Nix expressions, store files, source control, argv, environment
variables, terminal output or an operator report. Do not transfer the primary's
whole credential tree: that would disclose the update key.

`kaiba-lan-secondary-credentials.service` imports the transfer key once into its
own persistent private tree and validates the supplied file against that state
on every start. Both helpers bind retained material to role, zone and host pair.
Missing, malformed, linked, changed or partial credentials fail closed; there is
no silent key replacement or automatic rotation. A missing credential base also
refuses initialization when the existing Knot state directory contains data.
Complete loss or rollback of both credential and DNS state needs external
continuity evidence and remains unqualified. Changes require explicit
operator reconciliation of the source, both retained credential trees and DNS
journals. The primary accepts transfer from Mako's exact address with the transfer
key, while only the distinct update key from loopback may modify A/AAAA records.

Knot services and journals are `kaiba-lan-primary` and `kaiba-lan-secondary`, each
with its own Unix user and mode0700 `/var/lib/<service>` state. Disabling a role
removes its services/firewall rules and retains durable bytes. Primary outages
leave existing secondary answers available until SOA expiry. A returning
secondary catches up from the primary; it never becomes a writer automatically.
The publisher does not mark a new generation observed until both configured
endpoints match. This is a pilot with one authority, not automatic failover,
offline rollback protection or a production availability qualification.

## Verification

```console
nix build .#checks.x86_64-linux.lan-two-host-module-eval --no-link -L
nix build .#checks.x86_64-linux.lan-two-host --no-link -L
```

The focused VM uses two machines and runtime-generated secrets. It exercises
cross-host AXFR and NOTIFY, transfer/update permission separation, unsigned and
secondary update denial, source restrictions for TCP/UDP, host/user credential
separation, independent outages, journal restart and catch-up, and imported-key
failure. The handoff uses a temporary private build directory; no secret enters
the check output. `lan-two-host-result.json` marks the evidence synthetic and
explicitly leaves the SPIFFE application path and hardware unqualified. The
separate fleet integration and native acceptance must verify the actual admitted
instance, registry decision, real updater request and resulting records on both
hosts. Direct TSIG writes in this transport test do not prove that authorization
path.
