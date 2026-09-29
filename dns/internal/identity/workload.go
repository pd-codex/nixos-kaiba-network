package identity

import (
	"context"
	"crypto/tls"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

var (
	ErrUnauthenticated = errors.New("invalid workload credential")
	ErrDenied          = errors.New("workload is not authorized for DNS")
	ErrUnavailable     = errors.New("workload authorization is unavailable")
	workloadSegment    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	domainLabel        = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// RequestPolicy is an explicitly selected alternative to the legacy file
// certificate policy. It must revalidate transport and inventory on every
// request, including requests on an existing TLS connection.
type RequestPolicy interface {
	ResolveRequest(context.Context, *tls.ConnectionState) (Device, error)
}

type DNSAuthorizer interface {
	AuthorizeDNS(context.Context, spiffeid.ID) (Device, error)
}

type WorkloadPolicy struct {
	Bundles     x509bundle.Source
	TrustDomain spiffeid.TrustDomain
	Authorizer  DNSAuthorizer
	Now         func() time.Time
}

func (p WorkloadPolicy) ResolveRequest(ctx context.Context, state *tls.ConnectionState) (Device, error) {
	if state == nil || len(state.PeerCertificates) == 0 || p.Bundles == nil || p.Authorizer == nil {
		return Device{}, ErrUnauthenticated
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	// go-spiffe uses VerifyPeerCertificate, so VerifiedChains need not be
	// populated. Only this explicit mode accepts peers after its own complete
	// chain validation against the CURRENT Workload API bundle and wall clock.
	at := now()
	leaf := state.PeerCertificates[0]
	if at.Before(leaf.NotBefore) || !at.Before(leaf.NotAfter) {
		return Device{}, ErrUnauthenticated
	}
	id, _, err := x509svid.Verify(state.PeerCertificates, p.Bundles, x509svid.WithTime(at))
	if err != nil || id.TrustDomain() != p.TrustDomain {
		return Device{}, ErrUnauthenticated
	}
	if _, _, err := WorkloadComponents(id); err != nil {
		return Device{}, ErrDenied
	}
	return p.Authorizer.AuthorizeDNS(ctx, id)
}

func ValidTrustDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if !domainLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// WorkloadComponents enforces the shared WorkloadBinding identity grammar.
// Logical IDs are NOT interpreted as numeric DNS device IDs.
func WorkloadComponents(id spiffeid.ID) (device, instance string, err error) {
	parts := strings.Split(id.Path(), "/")
	if !ValidTrustDomain(id.TrustDomain().String()) || len(parts) != 7 || parts[0] != "" || parts[1] != "device" || parts[3] != "instance" || parts[5] != "workload" {
		return "", "", ErrDenied
	}
	for _, part := range []string{parts[2], parts[4], parts[6]} {
		if !workloadSegment.MatchString(part) {
			return "", "", ErrDenied
		}
	}
	return parts[2], parts[4], nil
}
