//go:build gateway_acquisition_fixture

package connections

import (
	"adapters/internal/acquisitionfixture"
	"context"
)

// ReadSearchAcquisitionFixture delegates validation, charging, normalization and
// envelope construction to searchAcquire; only its existing client is injected.
// It is absent from ordinary builds and retains the canonical provider endpoint.
func ReadSearchAcquisitionFixture(ctx context.Context, store *Store, raw []byte) ([]byte, error) {
	var request SearchRequest
	if decode(raw, &request) != nil {
		return nil, ErrRequest
	}
	network, err := acquisitionfixture.New()
	if err != nil {
		return nil, ErrProvider
	}
	defer network.Close()
	p := googleProvider()
	client, closeClient := network.SearchClient()
	defer closeClient()
	p.client = client
	return searchAcquire(ctx, store, request, p)
}
