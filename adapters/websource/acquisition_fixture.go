//go:build gateway_acquisition_fixture

package websource

import (
	"adapters/internal/acquisitionfixture"
	"context"
)

// ReadAcquisitionFixture reaches the complete production page acquisition body
// through its existing private network seam. It is absent from ordinary builds.
func ReadAcquisitionFixture(ctx context.Context, raw []byte) ([]byte, error) {
	network, err := acquisitionfixture.New()
	if err != nil {
		return nil, ErrNetwork
	}
	defer network.Close()
	f := fetcher{lookup: network.LookupNetIP, dial: network.DialPage, tls: network.TLSConfig()}
	return readOptions(ctx, raw, f, Options{})
}
