package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFleetDecisionValidation(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 1, 0, time.UTC)
	id := spiffeid.RequireFromString("spiffe://owner.test/device/device-alpha/instance/instance-1/workload/dns-updater")
	tests := []struct {
		name   string
		mutate func(map[string]any)
		raw    func(string) string
		status int
		want   error
	}{
		{name: "mapped numeric DNS ID"},
		{name: "wrong nonce", mutate: func(d map[string]any) { d["request_id"] = strings.Repeat("0", 32) }, want: ErrUnavailable},
		{name: "other workload", mutate: func(d map[string]any) { d["spiffe_id"] = strings.Replace(id.String(), "dns-updater", "controller", 1) }, want: ErrUnavailable},
		{name: "other logical device", mutate: func(d map[string]any) { d["logical_device_id"] = "other" }, want: ErrUnavailable},
		{name: "replaced instance", mutate: func(d map[string]any) { d["instance_id"] = "instance-2" }, want: ErrUnavailable},
		{name: "wrong zone", mutate: func(d map[string]any) { d["hostname"] = "pi-007.other.test" }, want: ErrUnavailable},
		{name: "wrong mapping", mutate: func(d map[string]any) { d["hostname"] = "pi-008.kaiba.test" }, want: ErrUnavailable},
		{name: "non numeric ID", mutate: func(d map[string]any) { d["dns_device_id"] = "device-alpha" }, want: ErrUnavailable},
		{name: "short numeric ID", mutate: func(d map[string]any) { d["dns_device_id"] = "07" }, want: ErrUnavailable},
		{name: "oversized label", mutate: func(d map[string]any) {
			d["dns_device_id"] = strings.Repeat("1", 61)
			d["hostname"] = "pi-" + strings.Repeat("1", 61) + ".kaiba.test"
		}, want: ErrUnavailable},
		{name: "wrong permission", mutate: func(d map[string]any) { d["permission"] = "dns:read" }, want: ErrUnavailable},
		{name: "wrong version", mutate: func(d map[string]any) { d["contract_version"] = "0.4.0" }, want: ErrUnavailable},
		{name: "wrong contract", mutate: func(d map[string]any) { d["contract"] = "WorkloadBinding" }, want: ErrUnavailable},
		{name: "expired", mutate: func(d map[string]any) {
			d["checked_at"] = now.Add(-5 * time.Second).Format(time.RFC3339)
			d["expires_at"] = now.Format(time.RFC3339)
		}, want: ErrUnavailable},
		{name: "future", mutate: func(d map[string]any) {
			d["checked_at"] = now.Add(time.Second).Format(time.RFC3339)
			d["expires_at"] = now.Add(6 * time.Second).Format(time.RFC3339)
		}, want: ErrUnavailable},
		{name: "too long", mutate: func(d map[string]any) { d["expires_at"] = now.Add(6 * time.Second).Format(time.RFC3339) }, want: ErrUnavailable},
		{name: "too short", mutate: func(d map[string]any) { d["expires_at"] = now.Add(4 * time.Second).Format(time.RFC3339) }, want: ErrUnavailable},
		{name: "noncanonical UTC", mutate: func(d map[string]any) { d["checked_at"] = "2026-09-29T12:00:01+00:00" }, want: ErrUnavailable},
		{name: "nanosecond precision", mutate: func(d map[string]any) { d["checked_at"] = "2026-09-29T12:00:01.0000000Z" }, want: ErrUnavailable},
		{name: "unknown field", mutate: func(d map[string]any) { d["state"] = "active" }, want: ErrUnavailable},
		{name: "missing field", mutate: func(d map[string]any) { delete(d, "checked_at") }, want: ErrUnavailable},
		{name: "null field", mutate: func(d map[string]any) { d["checked_at"] = nil }, want: ErrUnavailable},
		{name: "case aliased key", raw: func(s string) string { return strings.Replace(s, `"contract":`, `"Contract":`, 1) }, want: ErrUnavailable},
		{name: "duplicate key", raw: func(s string) string { return `{"contract":"DNSWorkloadAuthorization",` + s[1:] }, want: ErrUnavailable},
		{name: "second object", raw: func(s string) string { return s + "{}" }, want: ErrUnavailable},
		{name: "oversized", raw: func(s string) string { return s + strings.Repeat(" ", 16385) }, want: ErrUnavailable},
		{name: "denied", status: 403, want: ErrDenied},
		{name: "dependency outage", status: 503, want: ErrUnavailable},
		{name: "redirect", status: 307, want: ErrUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != "POST" || r.URL.Path != decisionPath || r.Header.Get("Content-Type") != "application/json" {
					t.Fatalf("unexpected request: %v", r)
				}
				var request map[string]string
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Fatal(err)
				}
				if len(request) != 2 || request["spiffe_id"] != id.String() || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(request["request_id"]) {
					t.Fatalf("invalid request: %v", request)
				}
				decision := map[string]any{"contract": "DNSWorkloadAuthorization", "contract_version": DecisionVersion, "request_id": request["request_id"], "spiffe_id": id.String(), "logical_device_id": "device-alpha", "instance_id": "instance-1", "dns_device_id": "007", "hostname": "pi-007.kaiba.test", "permission": "dns:update", "checked_at": now.Format(time.RFC3339), "expires_at": now.Add(5 * time.Second).Format(time.RFC3339)}
				if tc.mutate != nil {
					tc.mutate(decision)
				}
				data, _ := json.Marshal(decision)
				body := string(data)
				if tc.raw != nil {
					body = tc.raw(body)
				}
				status := tc.status
				if status == 0 {
					status = 200
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			f := &FleetAuthorizer{client: &http.Client{Transport: transport}, endpoint: "https://fleet.test" + decisionPath, zone: "kaiba.test", now: func() time.Time { return now }}
			device, err := f.AuthorizeDNS(context.Background(), id)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if tc.want == nil && (device.ID != "007" || device.Hostname != "pi-007.kaiba.test") {
				t.Fatalf("untrusted mapping: %+v", device)
			}
		})
	}
}

func TestFleetDecisionsAreNotCachedAndNonceCannotBeReplayed(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	id := spiffeid.RequireFromString("spiffe://owner.test/device/alpha/instance/one/workload/dns-updater")
	var first []byte
	seen := map[string]bool{}
	calls := 0
	f := &FleetAuthorizer{endpoint: "https://fleet.test" + decisionPath, zone: "kaiba.test", now: func() time.Time { return now }}
	f.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if seen[req["request_id"]] {
			t.Fatal("nonce reused")
		}
		seen[req["request_id"]] = true
		if first == nil {
			first, _ = json.Marshal(authorizationDecision{Contract: "DNSWorkloadAuthorization", ContractVersion: DecisionVersion, RequestID: req["request_id"], SPIFFEID: id.String(), LogicalDeviceID: "alpha", InstanceID: "one", DNSDeviceID: "001", Hostname: "pi-001.kaiba.test", Permission: "dns:update", CheckedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(5 * time.Second).Format(time.RFC3339)})
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(first)))}, nil
	})}
	if _, err := f.AuthorizeDNS(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.AuthorizeDNS(context.Background(), id); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("replayed decision accepted: %v", err)
	}
	if calls != 2 {
		t.Fatalf("cached allow: %d calls", calls)
	}
}

func TestFleetAuthorizationConfiguration(t *testing.T) {
	for _, endpoint := range []string{"http://fleet.test", "https://user@fleet.test", "https://fleet.test/api", "https://fleet.test?x=y", "https://fleet.test/#fragment"} {
		if _, err := NewFleetAuthorizer(nil, endpoint, "spiffe://owner.test/service/fleet", "kaiba.test", time.Second); err == nil {
			t.Fatalf("accepted %q", endpoint)
		}
	}
	for _, id := range []string{"", "https://fleet.test", "spiffe://owner.test/service/fleet?x=1"} {
		if _, err := WorkloadHTTPClient(nil, id, time.Second); err == nil {
			t.Fatalf("accepted %q", id)
		}
	}
	for _, socket := range []string{"", "/run/api.sock", "unix://remote/run/api.sock", "unix:///run/api.sock?", "unix:///run/api.sock#x"} {
		if _, err := NewWorkloadSource(context.Background(), socket, time.Millisecond); err == nil {
			t.Fatalf("accepted %q", socket)
		}
	}
}
