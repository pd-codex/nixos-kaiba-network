package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/dns/internal/identity"
	"github.com/ams-tech/nixos-kaiba-network/dns/internal/store"
)

type requestPolicyFunc func(context.Context, *tls.ConnectionState) (identity.Device, error)

func (f requestPolicyFunc) ResolveRequest(ctx context.Context, s *tls.ConnectionState) (identity.Device, error) {
	return f(ctx, s)
}

func TestWorkloadAuthorizationPrecedesEveryStateReadAndWrite(t *testing.T) {
	db, err := store.OpenSQLite(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var policyErr error
	calls := 0
	policy := requestPolicyFunc(func(ctx context.Context, _ *tls.ConnectionState) (identity.Device, error) {
		calls++
		if ctx.Err() != nil {
			return identity.Device{}, identity.ErrUnavailable
		}
		return identity.Device{ID: "007", Hostname: "pi-007.kaiba.test"}, policyErr
	})
	h, err := New(Config{RequestIdentity: policy, Store: db, LeaseDuration: time.Hour, RenewAfter: time.Minute, AllowNonGlobalAddresses: true})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method string) *httptest.ResponseRecorder {
		path := "/v1/devices/self/status"
		if method == http.MethodPut {
			path = "/v1/devices/self/endpoints"
		}
		r := httptest.NewRequest(method, path, strings.NewReader(`{"addresses":[{"family":"ipv4","address":"192.0.2.10"}]}`))
		r.Header.Set("Idempotency-Key", "test-request")
		r.Header.Set("If-None-Match", "*")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		err    error
		status int
	}{{identity.ErrDenied, 403}, {identity.ErrUnavailable, 503}, {identity.ErrUnauthenticated, 401}} {
		policyErr = tc.err
		for _, method := range []string{http.MethodPut, http.MethodGet} {
			if r := request(method); r.Code != tc.status {
				t.Fatalf("%s: got %d want %d", method, r.Code, tc.status)
			}
		}
		if _, err := db.GetIntent(context.Background(), "007"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("denial persisted state: %v", err)
		}
	}
	policyErr = nil
	if r := request(http.MethodPut); r.Code != 202 {
		t.Fatalf("authorized PUT: %d %s", r.Code, r.Body.String())
	}
	policyErr = identity.ErrDenied
	if r := request(http.MethodGet); r.Code != 403 {
		t.Fatalf("cached authorization after quarantine: %d", r.Code)
	}
	if calls != 8 {
		t.Fatalf("authorization not called per request: %d", calls)
	}
	intent, err := db.GetIntent(context.Background(), "007")
	if err != nil || intent.Generation != 1 || intent.Hostname != "pi-007.kaiba.test" {
		t.Fatalf("bad assigned DNS mapping: %+v %v", intent, err)
	}
	if _, err := New(Config{Identity: identity.SPIFFEPolicy{}, RequestIdentity: policy, Store: db, LeaseDuration: time.Hour, RenewAfter: time.Minute}); err == nil {
		t.Fatal("mixed policies accepted")
	}
}
