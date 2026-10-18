//go:build gateway_acquisition_fixture

package websource

import (
	"adapters/document"
	"testing"
)

// markedBuild makes the test run as the builder stamps the fixture; a test of
// the refusal of an unmarked build sets the version itself.
func markedBuild(t *testing.T) {
	t.Helper()
	was := document.Version
	document.Version = "fixture.test"
	t.Cleanup(func() { document.Version = was })
}

func unmarked(t *testing.T) {
	t.Helper()
	was := document.Version
	document.Version = "0"
	t.Cleanup(func() { document.Version = was })
}

func TestAcquisitionFixturePageRefusesAnUnmarkedBuild(t *testing.T) {
	unmarked(t)
	if _, err := ReadAcquisitionFixture(t.Context(), []byte(`{"url":"https://example.com/fixtures/company"}`)); err != ErrFixtureBuild {
		t.Fatal("unmarked build read a page", err)
	}
	if _, err := DescribeAcquisitionFixture(); err != ErrFixtureBuild {
		t.Fatal("unmarked build described itself", err)
	}
	if RefusalLine(ErrFixtureBuild) != "fixture-build-required" {
		t.Fatal("refusal is not the fixture's own", RefusalLine(ErrFixtureBuild))
	}
}
