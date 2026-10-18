//go:build gateway_acquisition_fixture

package websource

import (
	"adapters/internal/acquisitionfixture"
	"context"
	"errors"
)

// ErrFixtureBuild is the refusal of a tagged program the builder did not mark.
var ErrFixtureBuild = errors.New(acquisitionfixture.ErrBuild.Error())

// DescribeAcquisitionFixture is DescribeResearchBinding for the fixture, which
// refuses unless the program is marked as the fixture.
func DescribeAcquisitionFixture() ([]byte, error) {
	if !acquisitionfixture.Marked() {
		return nil, ErrFixtureBuild
	}
	return DescribeResearchBinding()
}

// ReadAcquisitionFixture reaches the complete production page acquisition body
// through its existing private network seam. It is absent from ordinary builds.
func ReadAcquisitionFixture(ctx context.Context, raw []byte) ([]byte, error) {
	if !acquisitionfixture.Marked() {
		return nil, ErrFixtureBuild
	}
	network, err := acquisitionfixture.New()
	if err != nil {
		return nil, ErrNetwork
	}
	defer network.Close()
	f := fetcher{lookup: network.LookupNetIP, dial: network.DialPage, tls: network.TLSConfig()}
	return readOptions(ctx, raw, f, Options{})
}
