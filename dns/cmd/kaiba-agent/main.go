package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/dns/internal/agent"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/cliutil"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/identity"
)

func main() {
	log.SetFlags(0)
	renewDefault := mustDuration("KAIBA_AGENT_RENEW_INTERVAL", 6*time.Hour)
	timeoutDefault := mustDuration("KAIBA_AGENT_REQUEST_TIMEOUT", 30*time.Second)
	onceDefault := mustBool("KAIBA_AGENT_ONCE", false)
	endpoint := flag.String("endpoint", cliutil.Env("KAIBA_AGENT_ENDPOINT", ""), "controller base HTTPS URL")
	certFile := flag.String("client-cert", cliutil.Env("KAIBA_AGENT_CLIENT_CERT", ""), "device certificate file")
	keyFile := flag.String("client-key", cliutil.Env("KAIBA_AGENT_CLIENT_KEY", ""), "device private-key file")
	caFile := flag.String("ca", cliutil.Env("KAIBA_AGENT_CA", ""), "controller CA bundle")
	identityMode := flag.String("identity-mode", cliutil.Env("KAIBA_AGENT_IDENTITY_MODE", "file"), "identity transport: file or spiffe")
	socket := flag.String("workload-api-socket", cliutil.Env("KAIBA_AGENT_WORKLOAD_API_SOCKET", ""), "explicit unix:/// SPIFFE Workload API socket")
	controllerID := flag.String("controller-spiffe-id", cliutil.Env("KAIBA_AGENT_CONTROLLER_SPIFFE_ID", ""), "exact expected controller SPIFFE ID")
	addresses := cliutil.CSVEnv("KAIBA_AGENT_ADDRESSES")
	flag.Var(&addresses, "address", "explicit endpoint IP address (repeatable)")
	interfaces := cliutil.CSVEnv("KAIBA_AGENT_INTERFACES")
	flag.Var(&interfaces, "interface", "interface eligible for address discovery (repeatable)")
	statePath := flag.String("idempotency-state", cliutil.Env("KAIBA_AGENT_IDEMPOTENCY_STATE", "/var/lib/kaiba-agent/idempotency.json"), "pending request state file")
	renewInterval := flag.Duration("renew-interval", renewDefault, "lease-renewal interval")
	requestTimeout := flag.Duration("request-timeout", timeoutDefault, "one HTTP request timeout")
	once := flag.Bool("once", onceDefault, "submit once and exit")
	flag.Parse()
	if *endpoint == "" {
		log.Fatal("--endpoint is required")
	}
	parsedAddresses := make([]netip.Addr, 0, len(addresses))
	for _, value := range addresses {
		addr, err := netip.ParseAddr(value)
		if err != nil || addr.Is4In6() {
			log.Fatalf("invalid --address %q", value)
		}
		parsedAddresses = append(parsedAddresses, addr)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var httpClient *http.Client
	var err error
	switch *identityMode {
	case "file":
		if *certFile == "" || *keyFile == "" || *caFile == "" || *socket != "" || *controllerID != "" {
			log.Fatal("file mode requires --client-cert, --client-key, --ca and forbids SPIFFE options")
		}
		httpClient, err = agent.NewHTTPClient(*certFile, *keyFile, *caFile, *requestTimeout)
	case "spiffe":
		if *certFile != "" || *keyFile != "" || *caFile != "" || *controllerID == "" {
			log.Fatal("spiffe mode requires --controller-spiffe-id and --workload-api-socket and forbids file credentials")
		}
		source, sourceErr := identity.NewWorkloadSource(ctx, *socket, *requestTimeout)
		if sourceErr != nil {
			log.Fatal(sourceErr)
		}
		defer source.Close()
		httpClient, err = identity.WorkloadHTTPClient(source, *controllerID, *requestTimeout)
	default:
		log.Fatal("--identity-mode must be file or spiffe")
	}
	if err != nil {
		log.Fatal(err)
	}
	defer httpClient.CloseIdleConnections()
	service, err := agent.New(agent.Config{
		Endpoint: *endpoint, Addresses: parsedAddresses, Interfaces: interfaces,
		StatePath: *statePath, HTTPClient: httpClient, RenewInterval: *renewInterval,
		RequestTimeout: *requestTimeout, Once: *once,
		OnError: func(err error) { log.Printf("endpoint update failed: %v", err) },
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := service.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
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
