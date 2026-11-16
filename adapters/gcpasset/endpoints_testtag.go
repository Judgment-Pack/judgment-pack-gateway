//go:build gcpasset_testendpoints

package gcpasset

// A binary built with the gcpasset_testendpoints tag reads the platform's
// endpoints, and the roots it trusts for them, from its environment, so
// the gateway's end-to-end tests can serve hand-written answers from a
// server of their own. No release build carries the tag (.goreleaser.yml,
// the Dockerfile), and a build without it cannot change the endpoints.

import (
	"crypto/x509"
	"encoding/json"
	"os"
)

// TestEndpointsVariable names a JSON object of the endpoints to use, its
// members those of endpoints; TestRootsVariable a PEM file of the roots.
const (
	TestEndpointsVariable = "ADAPTER_GCP_ASSET_TEST_ENDPOINTS"
	TestRootsVariable     = "ADAPTER_GCP_ASSET_TEST_CA"
)

func init() {
	if text := os.Getenv(TestEndpointsVariable); text != "" {
		if err := json.Unmarshal([]byte(text), &endpoints); err != nil {
			panic("adapter-gcp-asset: " + TestEndpointsVariable + " is not an object of endpoints")
		}
	}
	if path := os.Getenv(TestRootsVariable); path != "" {
		pemText, err := os.ReadFile(path)
		if err != nil {
			panic("adapter-gcp-asset: " + TestRootsVariable + " could not be read")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemText) {
			panic("adapter-gcp-asset: " + TestRootsVariable + " holds no certificate")
		}
		testRoots = pool
	}
}
