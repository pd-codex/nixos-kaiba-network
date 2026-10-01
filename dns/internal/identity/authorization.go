package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const DecisionVersion = "0.5.0-draft.1"
const decisionPath = "/api/v1/workloads/authorize-dns"

var decisionTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:[0-5]\d:[0-5]\d(?:\.\d{1,6})?Z$`)

type authorizationDecision struct {
	Contract        string `json:"contract"`
	ContractVersion string `json:"contract_version"`
	RequestID       string `json:"request_id"`
	SPIFFEID        string `json:"spiffe_id"`
	LogicalDeviceID string `json:"logical_device_id"`
	InstanceID      string `json:"instance_id"`
	DNSDeviceID     string `json:"dns_device_id"`
	Hostname        string `json:"hostname"`
	Permission      string `json:"permission"`
	CheckedAt       string `json:"checked_at"`
	ExpiresAt       string `json:"expires_at"`
}

// FleetAuthorizer consumes an authenticated, nonce-bound decision immediately.
// It never accepts a locally supplied binding file or caches a past allow.
type FleetAuthorizer struct {
	client   *http.Client
	endpoint string
	zone     string
	now      func() time.Time
}

func NewFleetAuthorizer(source X509Source, endpoint, serverID, zone string, timeout time.Duration) (*FleetAuthorizer, error) {
	client, err := WorkloadHTTPClient(source, serverID, timeout)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("fleet authorization URL must be an HTTPS origin without path, query, or userinfo")
	}
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	if !ValidTrustDomain(zone) {
		return nil, errors.New("invalid DNS zone")
	}
	u.Path = decisionPath
	return &FleetAuthorizer{client: client, endpoint: u.String(), zone: zone, now: time.Now}, nil
}

func (f *FleetAuthorizer) Close() { f.client.CloseIdleConnections() }

func (f *FleetAuthorizer) AuthorizeDNS(ctx context.Context, id spiffeid.ID) (Device, error) {
	logical, instance, err := WorkloadComponents(id)
	if err != nil || !strings.HasSuffix(id.Path(), "/workload/dns-updater") {
		return Device{}, ErrDenied
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Device{}, ErrUnavailable
	}
	requestID := hex.EncodeToString(nonce[:])
	data, err := json.Marshal(struct {
		SPIFFEID  string `json:"spiffe_id"`
		RequestID string `json:"request_id"`
	}{id.String(), requestID})
	if err != nil {
		return Device{}, ErrUnavailable
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint, bytes.NewReader(data))
	if err != nil {
		return Device{}, ErrUnavailable
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := f.client.Do(r)
	if err != nil {
		return Device{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden {
		return Device{}, ErrDenied
	}
	if response.StatusCode != http.StatusOK {
		return Device{}, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(body) > 16384 {
		return Device{}, ErrUnavailable
	}
	decision, err := decodeDecision(body)
	if err != nil {
		return Device{}, ErrUnavailable
	}
	now := f.now()
	checked, checkedErr := time.Parse(time.RFC3339Nano, decision.CheckedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, decision.ExpiresAt)
	if decision.Contract != "DNSWorkloadAuthorization" || decision.ContractVersion != DecisionVersion || decision.RequestID != requestID || decision.SPIFFEID != id.String() || decision.LogicalDeviceID != logical || decision.InstanceID != instance || decision.Permission != "dns:update" || !deviceIDPattern.MatchString(decision.DNSDeviceID) || decision.Hostname != "pi-"+decision.DNSDeviceID+"."+f.zone || len(decision.Hostname) > 253 || len("pi-"+decision.DNSDeviceID) > 63 || checkedErr != nil || expiresErr != nil || !decisionTimestamp.MatchString(decision.CheckedAt) || !decisionTimestamp.MatchString(decision.ExpiresAt) || checked.After(now) || !now.Before(expires) || expires.Sub(checked) != 5*time.Second {
		return Device{}, ErrUnavailable
	}
	return Device{ID: decision.DNSDeviceID, Hostname: decision.Hostname}, nil
}

// encoding/json alone accepts duplicate and case-aliased fields. Require the
// exact closed wire object before decoding its string values.
func decodeDecision(data []byte) (authorizationDecision, error) {
	fields := map[string]bool{}
	for _, field := range []string{"contract", "contract_version", "request_id", "spiffe_id", "logical_device_id", "instance_id", "dns_device_id", "hostname", "permission", "checked_at", "expires_at"} {
		fields[field] = false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return authorizationDecision{}, errors.New("expected decision object")
	}
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return authorizationDecision{}, err
		}
		key, ok := token.(string)
		seen, known := fields[key]
		if !ok || !known || seen {
			return authorizationDecision{}, errors.New("unknown or duplicate decision field")
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return authorizationDecision{}, err
		}
		fields[key] = true
	}
	if _, err = decoder.Token(); err != nil {
		return authorizationDecision{}, err
	}
	for _, seen := range fields {
		if !seen {
			return authorizationDecision{}, errors.New("missing decision field")
		}
	}
	if decoder.Decode(new(any)) != io.EOF {
		return authorizationDecision{}, errors.New("trailing decision data")
	}
	var decision authorizationDecision
	err = json.Unmarshal(data, &decision)
	return decision, err
}
