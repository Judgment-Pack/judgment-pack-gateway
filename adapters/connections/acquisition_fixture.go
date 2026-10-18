//go:build gateway_acquisition_fixture

package connections

import (
	"adapters/internal/acquisitionfixture"
	"context"
	"net/http"
)

const (
	// ErrFixtureBuild refuses a tagged program the builder did not mark.
	ErrFixtureBuild Error = "fixture-build-required"
	// ErrFixtureStore refuses a connection that is not the fixture's own.
	ErrFixtureStore Error = "fixture-store-required"
)

// fixtureStoreHeld refuses, before any charge, a connection that is not the
// fixture's: a tavily connection holding acquisitionfixture.Credential. A
// connection the store does not hold is left to production's own refusal.
func fixtureStoreHeld(s *Store, id string) error {
	return s.locked(func(v *state) error {
		if v.Search == nil {
			return nil
		}
		for _, c := range v.Search.Connections {
			if c.ID == id && (c.Provider != "tavily" || c.Credential != acquisitionfixture.Credential) {
				return ErrFixtureStore
			}
		}
		return nil
	})
}

// DescribeSearchAcquisitionFixture is DescribeSearchBinding for the fixture,
// under the same marker and fixture-only store rules as the read.
func DescribeSearchAcquisitionFixture(store *Store, raw []byte) ([]byte, error) {
	if !acquisitionfixture.Marked() {
		return nil, ErrFixtureBuild
	}
	var q struct {
		Connection string `json:"connection"`
		Revision   string `json:"revision"`
	}
	if decode(raw, &q) != nil {
		return nil, ErrRequest
	}
	if err := fixtureStoreHeld(store, q.Connection); err != nil {
		return nil, err
	}
	return DescribeSearchBinding(store, raw)
}

// ReadSearchAcquisitionFixture reads a request by production's own path,
// readSearch (the argument table, then the production acquisition); only its
// existing client is injected. It is absent from ordinary builds and retains
// the canonical provider endpoint.
func ReadSearchAcquisitionFixture(ctx context.Context, store *Store, raw []byte) ([]byte, error) {
	return readSearchAcquisitionFixture(ctx, store, raw, nil)
}

// readSearchAcquisitionFixture lets a test wrap the fixture's transport to see
// the requests it carries.
func readSearchAcquisitionFixture(ctx context.Context, store *Store, raw []byte, wrap func(http.RoundTripper) http.RoundTripper) ([]byte, error) {
	if !acquisitionfixture.Marked() {
		return nil, ErrFixtureBuild
	}
	q, _, err := readSearchArguments(raw)
	if err != nil {
		return nil, err
	}
	if err := fixtureStoreHeld(store, q.Connection); err != nil {
		return nil, err
	}
	network, err := acquisitionfixture.New()
	if err != nil {
		return nil, ErrProvider
	}
	defer network.Close()
	p := googleProvider()
	client, closeClient := network.SearchClient()
	defer closeClient()
	if wrap != nil {
		client.Transport = wrap(client.Transport)
	}
	p.client = client
	return readSearch(ctx, store, raw, p)
}
