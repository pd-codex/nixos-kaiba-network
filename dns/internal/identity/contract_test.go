package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func TestPinnedDNSAuthorizationContractCorpus(t *testing.T) {
	root := "testdata/dns-authorization"
	manifestData, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Commit string            `json:"commit"`
		Files  map[string]string `json:"files"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Commit != "a6ce2a397b2fe2dbdee8d5d2236fbd002ef6dc21" {
		t.Fatal("unexpected contract pin")
	}
	for path, digest := range manifest.Files {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != digest {
			t.Fatalf("fixture drift: %s", path)
		}
	}
	contextData, err := os.ReadFile(filepath.Join(root, "context/dns-authorization-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]string
	if err := json.Unmarshal(contextData, &expected); err != nil {
		t.Fatal(err)
	}
	id := spiffeid.RequireFromString(expected["spiffe_id"])
	for path := range manifest.Files {
		if !strings.HasPrefix(path, "valid/") && !strings.HasPrefix(path, "invalid/") {
			continue
		}
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, path))
			if err != nil {
				t.Fatal(err)
			}
			var fixture map[string]any
			if err := json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			// Use the producer's check instant for valid fractional rollover
			// examples. Invalid timestamps still fail the canonical grammar.
			now, _ := time.Parse(time.RFC3339Nano, fixture["checked_at"].(string))
			f := &FleetAuthorizer{endpoint: "https://registry.test" + decisionPath, zone: "kaiba.network", now: func() time.Time { return now }}
			f.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				var request map[string]string
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Fatal(err)
				}
				// Rebind only the fixture's matching synthetic nonce. Deliberate
				// wrong-nonce examples remain wrong against the fresh RPC nonce.
				if fixture["request_id"] == expected["request_id"] {
					fixture["request_id"] = request["request_id"]
				}
				body, err := json.Marshal(fixture)
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			})}
			_, err = f.AuthorizeDNS(context.Background(), id)
			if (err == nil) != strings.HasPrefix(path, "valid/") {
				t.Fatalf("contract result: %v", err)
			}
		})
	}
}
