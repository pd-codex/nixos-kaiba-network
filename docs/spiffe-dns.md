# SPIFFE identities for the DNS updater

The DNS agent and controller have an explicit `spiffe` identity mode. They
obtain rotating X.509-SVIDs and trust bundles from a local SPIFFE Workload API.
The controller checks every protected request with the authenticated Kaiba
fleet workload registry before reading or writing desired state. The default
`file` mode retains its certificate, key and CA paths and legacy `/device/001`
identity policy.

This integration does not enroll devices, install SPIRE, enable fleet roles,
or attest hardware. A separately administered SPIRE deployment must register
each service with restrictive Unix-user and systemd-unit selectors. DNS
updater identities have this exact form:

```
spiffe://<trust-domain>/device/<logical-device>/instance/<instance>/workload/dns-updater
```

SPIFFE authentication does not activate enrollment or replace the existing
certificate-tuple activation protocol. Fleet must already have an active
enrollment instance, an active `dns-updater` WorkloadBinding granting
`dns:update`, and a separately assigned numeric DNS ID. For example, logical
device `device-alpha` may be assigned DNS ID `007`, producing the name
`pi-007.kaiba.network`. The controller never extracts that ID from the URI
or accepts a hostname supplied by the device.

## Transport and current authorization

The updater verifies the controller's exact configured SPIFFE ID. The
controller verifies the updater's certificate against its current Workload
API bundle and wall clock on every protected request, including an existing
TLS connection. It sends a fresh random 16-byte nonce and authenticated peer
ID to `POST /api/v1/workloads/authorize-dns`:

```json
{"spiffe_id":"spiffe://.../workload/dns-updater","request_id":"<32 lowercase hex>"}
```

This RPC uses the controller's Workload API source and verifies the registry's
exact configured SPIFFE ID. Fleet must separately allowlist the controller.
The closed `DNSWorkloadAuthorization` response uses contract version
`0.5.0-draft.1`. The consumer checks the nonce, exact identity, logical device,
instance, permission, numeric DNS assignment and configured zone. It requires
`checked_at <= now < expires_at`, with expiry exactly five seconds after the
check, and canonical UTC timestamps with at most six fractional digits.

Decisions are consumed immediately once and never cached. Redirects, stale
responses, malformed decisions and unavailable inventory fail closed before
desired-state access. Authorization denial returns HTTP 403; unavailable or
invalid registry decisions return HTTP 503. Invalid workload credentials
return HTTP 401 when the request reaches the handler.

Each outbound updater request and registry RPC establishes a new TLS
connection without session resumption, validating the current server leaf and
bundle. Inbound keep-alive rechecks credential validity and fleet policy on
every request. After quarantine, permission removal or instance replacement
commits, the next registry query denies the old workload; an already-authorized
in-flight request can finish.

The publisher retains its desired-state database and TSIG credential. Its
systemd sandbox hides the controller's Workload API socket; SPIRE selectors
must also exclude the publisher. Devices never receive publisher credentials.
DNS leases, generation preconditions, idempotency and publication semantics
are unchanged.

## NixOS configuration

Use the existing `device-agent` and `update-controller` modules with packages
from the same DNS revision. File credentials and SPIFFE options are mutually
exclusive. Configure SPIRE and the registry separately.

```nix
kaiba.deviceAgent = {
  enable = true;
  package = dns.packages.${system}.kaiba-agent;
  endpoint = "https://updates.kaiba.network:8443";
  interfaces = [ "eth0" ];
  identity = {
    mode = "spiffe";
    workloadAPISocket = "unix:///run/kaiba/identity/provider/public/api.sock";
    controllerSPIFFEID = "spiffe://kaiba.network/device/dns-controller/instance/controller-1/workload/dns-controller";
  };
  credentials.provisioningUnits = [ "kaiba-spire-provider.service" ];
};

kaiba.updateController = {
  enable = true;
  zone = "kaiba.network.";
  identity = {
    mode = "spiffe";
    workloadAPISocket = "unix:///run/kaiba/identity/local/public/api.sock";
    trustDomain = "kaiba.network";
    fleetAuthorizationURL = "https://fleet-registry.kaiba.network:8096";
    fleetServerSPIFFEID = "spiffe://kaiba.network/device/fleet/instance/fleet-1/workload/registry";
  };
  controller = {
    package = dns.packages.${system}.kaiba-controller;
    listenAddress = "0.0.0.0";
    openFirewall = true;
  };
  publisher = {
    package = dns.packages.${system}.kaiba-publisher;
    dnsServer = "192.0.2.10:53";
    observeServers = [ "192.0.2.11:53" "192.0.2.12:53" ];
  };
  credentials = {
    publisherTSIGSecret = "/run/credentials/kaiba-publisher/update.secret";
    provisioningUnits = [ "spire-agent.service" "kaiba-dns-secrets.service" ];
  };
};
```

Service names, addresses and identities above are examples. Runtime
provisioning must supply trust bundles, bootstrap grants when needed, and
publisher secrets outside the Nix store. Register the actual
`kaiba-agent.service` and `kaiba-controller.service` users/units. Use a separate
provider agent/socket when the owner and provider domains differ; owner
credentials do not authorize provider DNS access.

Equivalent CLI options:

- Agent: `--identity-mode spiffe --workload-api-socket unix:///... --controller-spiffe-id spiffe://...`.
- Controller: `--identity-mode spiffe --workload-api-socket unix:///... --spiffe-trust-domain kaiba.network --fleet-authorization-url https://registry:8096 --fleet-server-spiffe-id spiffe://...`.

Options also have environment variables with the existing `KAIBA_AGENT_` or
`KAIBA_CONTROLLER_` prefix and uppercase underscore spelling. The optional
controller test clock only changes DNS lease tests; credential and decision
validation always uses wall time.

## Validation and remaining qualification

Run `go test ./dns/...` and
`nix build .#checks.x86_64-linux.unit .#checks.x86_64-linux.module-eval`.
Tests cover live mutual TLS, exact server identity, certificate rotation,
expiry, uncached decisions, nonce replay denial, closed JSON, assigned names,
denial before storage, and legacy behavior. Contract examples are copied from
`kaiba-contracts` commit `a6ce2a397b2fe2dbdee8d5d2236fbd002ef6dc21`, with checksums
in `dns/internal/identity/testdata/dns-authorization/manifest.json`.

The combined fleet VM is responsible for exercising actual SPIRE, PostgreSQL
inventory, operator admission, this API, the publisher and Knot together. Existing DNS topology
tests retain static test PKI. Neither unit nor VM tests qualify hardware,
persistent storage or production provisioning.
