//go:build gateway_acquisition_fixture

package connections

import (
	"adapters/internal/acquisitionfixture"
	"context"
	"net/http"
)

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
