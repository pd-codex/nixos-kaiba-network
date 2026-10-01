package identity

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type X509Source interface {
	x509svid.Source
	x509bundle.Source
}

func NewWorkloadSource(ctx context.Context, socket string, timeout time.Duration) (*workloadapi.X509Source, error) {
	u, err := url.Parse(socket)
	if err != nil || u.Scheme != "unix" || u.Host != "" || !strings.HasPrefix(u.Path, "/") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || timeout <= 0 {
		return nil, errors.New("Workload API socket must be an explicit unix:///absolute/path with a positive timeout")
	}
	startup, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return workloadapi.NewX509Source(startup, workloadapi.WithClientOptions(workloadapi.WithAddr(socket)))
}

func WorkloadHTTPClient(source X509Source, expectedID string, timeout time.Duration) (*http.Client, error) {
	id, err := spiffeid.FromString(expectedID)
	if err != nil || id.String() != expectedID || expectedID == "" || timeout <= 0 {
		return nil, errors.New("an exact server SPIFFE ID and positive timeout are required")
	}
	config := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(id))
	config.MinVersion = tls.VersionTLS13
	// A fresh handshake verifies the current server leaf and bundle for each
	// request. No TLS resumption cache or redirect can bypass the exact ID.
	transport := &http.Transport{TLSClientConfig: config, DisableKeepAlives: true}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func WorkloadServerTLS(source X509Source, domain string) (*tls.Config, error) {
	if !ValidTrustDomain(domain) {
		return nil, errors.New("a canonical workload trust domain is required")
	}
	td, err := spiffeid.TrustDomainFromString(domain)
	if err != nil {
		return nil, err
	}
	config := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeMemberOf(td))
	config.MinVersion = tls.VersionTLS13
	config.SessionTicketsDisabled = true
	return config, nil
}
