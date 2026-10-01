package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

type testSource struct {
	mu     sync.Mutex
	svid   *x509svid.SVID
	bundle *x509bundle.Bundle
}

func (s *testSource) GetX509SVID() (*x509svid.SVID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.svid, nil
}
func (s *testSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if td != s.bundle.TrustDomain() {
		return nil, errors.New("unknown domain")
	}
	return s.bundle, nil
}
func (s *testSource) set(svid *x509svid.SVID) { s.mu.Lock(); defer s.mu.Unlock(); s.svid = svid }

type testAuthority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	now  time.Time
	td   spiffeid.TrustDomain
}

func authority(t *testing.T) *testAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testAuthority{cert: cert, key: key, now: now, td: spiffeid.RequireTrustDomainFromString("owner.test")}
}
func (a *testAuthority) source(t *testing.T, id string, serial int64) *testSource {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), URIs: []*url.URL{u}, NotBefore: a.now.Add(-time.Minute), NotAfter: a.now.Add(10 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, leaf, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testSource{svid: &x509svid.SVID{ID: spiffeid.RequireFromString(id), Certificates: []*x509.Certificate{cert}, PrivateKey: key}, bundle: x509bundle.FromX509Authorities(a.td, []*x509.Certificate{a.cert})}
}

type authorizerFunc func(context.Context, spiffeid.ID) (Device, error)

func (f authorizerFunc) AuthorizeDNS(ctx context.Context, id spiffeid.ID) (Device, error) {
	return f(ctx, id)
}

func TestWorkloadPolicyRevalidatesCurrentCertificateAndInventory(t *testing.T) {
	a := authority(t)
	source := a.source(t, "spiffe://owner.test/device/alpha/instance/one/workload/dns-updater", 2)
	now := a.now
	calls := 0
	denied := false
	p := WorkloadPolicy{Bundles: source, TrustDomain: a.td, Now: func() time.Time { return now }, Authorizer: authorizerFunc(func(context.Context, spiffeid.ID) (Device, error) {
		calls++
		if denied {
			return Device{}, ErrDenied
		}
		return Device{ID: "001", Hostname: "pi-001.kaiba.test"}, nil
	})}
	// VerifiedChains is deliberately absent; this path must validate the raw
	// peer itself, including when the same connection is used again.
	state := &tls.ConnectionState{PeerCertificates: source.svid.Certificates}
	if _, err := p.ResolveRequest(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	denied = true
	if _, err := p.ResolveRequest(context.Background(), state); !errors.Is(err, ErrDenied) {
		t.Fatalf("cached authorization: %v", err)
	}
	denied = false
	now = source.svid.Certificates[0].NotAfter.Add(time.Second)
	if _, err := p.ResolveRequest(context.Background(), state); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired connection accepted: %v", err)
	}
	if calls != 2 {
		t.Fatalf("inventory queried with invalid certificate: %d", calls)
	}
	now = a.now
	other := authority(t).source(t, source.svid.ID.String(), 3)
	if _, err := p.ResolveRequest(context.Background(), &tls.ConnectionState{PeerCertificates: other.svid.Certificates}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("untrusted certificate accepted: %v", err)
	}
	if _, err := p.ResolveRequest(context.Background(), nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
}

func TestWorkloadTLSExactServerIdentityAndRotation(t *testing.T) {
	a := authority(t)
	serverID := "spiffe://owner.test/device/controller/instance/one/workload/dns-controller"
	clientID := "spiffe://owner.test/device/alpha/instance/one/workload/dns-updater"
	serverSource := a.source(t, serverID, 2)
	clientSource := a.source(t, clientID, 3)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Serial", r.TLS.PeerCertificates[0].SerialNumber.String())
		w.WriteHeader(204)
	}))
	var err error
	config, err := WorkloadServerTLS(serverSource, "owner.test")
	if err != nil {
		t.Fatal(err)
	}
	// httptest injects its own localhost leaf; return the production dynamic
	// configuration independently so the Workload API source supplies the leaf.
	server.TLS = config.Clone()
	server.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return config, nil }
	server.StartTLS()
	defer server.Close()
	client, err := WorkloadHTTPClient(clientSource, serverID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	check := func(serial string) {
		t.Helper()
		response, err := client.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		if response.StatusCode != 204 || response.Header.Get("X-Test-Serial") != serial {
			t.Fatalf("unexpected response: %v", response)
		}
	}
	check("3")
	clientSource.set(a.source(t, clientID, 4).svid)
	serverSource.set(a.source(t, serverID, 5).svid)
	check("4")
	wrong, err := WorkloadHTTPClient(clientSource, "spiffe://owner.test/device/other/instance/one/workload/dns-controller", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.CloseIdleConnections()
	if response, err := wrong.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("wrong exact server ID was accepted")
	}
	otherSource := authority(t).source(t, clientID, 6)
	untrusted, _ := WorkloadHTTPClient(otherSource, serverID, time.Second)
	defer untrusted.CloseIdleConnections()
	if response, err := untrusted.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("untrusted server bundle was accepted")
	}
	if !client.Transport.(*http.Transport).DisableKeepAlives || client.Transport.(*http.Transport).TLSClientConfig.ClientSessionCache != nil {
		t.Fatal("outbound requests must validate current credentials each time")
	}
	if err := client.CheckRedirect(&http.Request{}, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy: %v", err)
	}
}

func TestCanonicalWorkloadIdentity(t *testing.T) {
	for _, id := range []string{"spiffe://owner.test/device/alpha", "spiffe://OWNER.test/device/alpha/instance/one/workload/dns-updater", "spiffe://owner.test/device/a/instance/one/workload/dns-updater/extra", "spiffe://owner.test/device/a/instance/../workload/dns-updater", "spiffe://owner.test/device/a/instance/one/workload/DNS-updater"} {
		parsed, err := spiffeid.FromString(id)
		if err == nil {
			_, _, err = WorkloadComponents(parsed)
		}
		if err == nil {
			t.Fatalf("accepted %q", id)
		}
	}
}
