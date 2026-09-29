package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/dns/internal/cliutil"
	clocksource "github.com/ams-tech/nixos-kaiba-network/dns/internal/clock"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/controller"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/identity"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/store"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func main() {
	log.SetFlags(0)
	leaseDefault := mustDuration("KAIBA_CONTROLLER_LEASE_DURATION", 24*time.Hour)
	renewDefault := mustDuration("KAIBA_CONTROLLER_RENEW_AFTER", 6*time.Hour)
	allowDefault := mustBool("KAIBA_CONTROLLER_ALLOW_NON_GLOBAL_ADDRESSES", false)
	listen := flag.String("listen", cliutil.Env("KAIBA_CONTROLLER_LISTEN", ":8443"), "HTTPS listen address")
	database := flag.String("db", cliutil.Env("KAIBA_CONTROLLER_DB", "/var/lib/kaiba-controller/controller.db"), "SQLite desired-state database")
	certFile := flag.String("tls-cert", cliutil.Env("KAIBA_CONTROLLER_TLS_CERT", ""), "server certificate file")
	keyFile := flag.String("tls-key", cliutil.Env("KAIBA_CONTROLLER_TLS_KEY", ""), "server private-key file")
	clientCAFile := flag.String("client-ca", cliutil.Env("KAIBA_CONTROLLER_CLIENT_CA", ""), "trusted device CA bundle")
	mode := flag.String("identity-mode", cliutil.Env("KAIBA_CONTROLLER_IDENTITY_MODE", "file"), "identity transport: file or spiffe")
	socket := flag.String("workload-api-socket", cliutil.Env("KAIBA_CONTROLLER_WORKLOAD_API_SOCKET", ""), "explicit unix:/// SPIFFE Workload API socket")
	domain := flag.String("spiffe-trust-domain", cliutil.Env("KAIBA_CONTROLLER_SPIFFE_TRUST_DOMAIN", ""), "accepted device workload trust domain")
	fleetURL := flag.String("fleet-authorization-url", cliutil.Env("KAIBA_CONTROLLER_FLEET_AUTHORIZATION_URL", ""), "fleet authorization HTTPS origin")
	fleetID := flag.String("fleet-server-spiffe-id", cliutil.Env("KAIBA_CONTROLLER_FLEET_SERVER_SPIFFE_ID", ""), "exact expected fleet authorization server SPIFFE ID")
	zone := flag.String("zone", cliutil.Env("KAIBA_CONTROLLER_ZONE", "kaiba.network"), "device DNS zone")
	clockFile := flag.String("clock-file", cliutil.Env("KAIBA_CONTROLLER_CLOCK_FILE", ""), "RFC3339 clock file for controlled tests (empty uses wall clock)")
	leaseDuration := flag.Duration("lease-duration", leaseDefault, "device address lease duration")
	renewAfter := flag.Duration("renew-after", renewDefault, "recommended device renewal interval")
	allowNonGlobal := flag.Bool("allow-non-global-addresses", allowDefault, "allow test-only non-public addresses")
	flag.Parse()
	spiffe := workloadOptions{Mode: *mode, Socket: *socket, TrustDomain: *domain, FleetURL: *fleetURL, FleetID: *fleetID}
	if err := run(*listen, *database, *certFile, *keyFile, *clientCAFile, *zone, *clockFile, *leaseDuration, *renewAfter, *allowNonGlobal, spiffe); err != nil {
		log.Fatal(err)
	}
}

type workloadOptions struct{ Mode, Socket, TrustDomain, FleetURL, FleetID string }

func run(listen, database, certFile, keyFile, clientCAFile, zone, clockFile string, leaseDuration, renewAfter time.Duration, allowNonGlobal bool, options workloadOptions) error {
	now, err := clocksource.New(clockFile, func(err error) {
		if err == nil {
			log.Printf("clock file recovered")
			return
		}
		log.Printf("clock file error: %v", err)
	})
	if err != nil {
		return err
	}
	desiredState, err := store.OpenSQLite(database)
	if err != nil {
		return err
	}
	defer desiredState.Close()
	config := controller.Config{
		Store: desiredState, LeaseDuration: leaseDuration, RenewAfter: renewAfter,
		AllowNonGlobalAddresses: allowNonGlobal,
		Now:                     now,
	}
	var tlsConfig *tls.Config
	switch options.Mode {
	case "file":
		if certFile == "" || keyFile == "" || clientCAFile == "" || options.Socket != "" || options.TrustDomain != "" || options.FleetURL != "" || options.FleetID != "" {
			return errors.New("file mode requires --tls-cert, --tls-key, --client-ca and forbids SPIFFE options")
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("load controller certificate: %w", err)
		}
		caPEM, err := os.ReadFile(clientCAFile)
		if err != nil {
			return fmt.Errorf("read device CA: %w", err)
		}
		clientCAs := x509.NewCertPool()
		if !clientCAs.AppendCertsFromPEM(caPEM) {
			return errors.New("device CA file contains no certificates")
		}
		tlsConfig = controller.TLSConfig(cert, clientCAs)
		config.Identity = identity.SPIFFEPolicy{TrustDomain: "kaiba.network", Zone: zone}
	case "spiffe":
		if certFile != "" || keyFile != "" || clientCAFile != "" || options.FleetURL == "" || options.FleetID == "" || !identity.ValidTrustDomain(options.TrustDomain) {
			return errors.New("spiffe mode requires workload socket, canonical trust domain, fleet URL and exact fleet server ID; file credentials are forbidden")
		}
		source, err := identity.NewWorkloadSource(context.Background(), options.Socket, 20*time.Second)
		if err != nil {
			return err
		}
		defer source.Close()
		authorizer, err := identity.NewFleetAuthorizer(source, options.FleetURL, options.FleetID, zone, 5*time.Second)
		if err != nil {
			return err
		}
		defer authorizer.Close()
		tlsConfig, err = identity.WorkloadServerTLS(source, options.TrustDomain)
		if err != nil {
			return err
		}
		domain, _ := spiffeid.TrustDomainFromString(options.TrustDomain)
		// Authentication always uses wall time, independently of the optional
		// controlled clock for DNS lease tests.
		config.RequestIdentity = identity.WorkloadPolicy{Bundles: source, TrustDomain: domain, Authorizer: authorizer}
	default:
		return errors.New("--identity-mode must be file or spiffe")
	}
	handler, err := controller.New(config)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: listen, Handler: handler, TLSConfig: tlsConfig,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second,
	}
	log.Printf("kaiba-controller listening on %s", listen)
	return server.ListenAndServeTLS("", "")
}

func mustDuration(name string, fallback time.Duration) time.Duration {
	value, err := cliutil.EnvDuration(name, fallback)
	if err != nil {
		log.Fatal(err)
	}
	return value
}

func mustBool(name string, fallback bool) bool {
	value, err := cliutil.EnvBool(name, fallback)
	if err != nil {
		log.Fatal(err)
	}
	return value
}
