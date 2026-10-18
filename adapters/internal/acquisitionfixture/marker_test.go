//go:build gateway_acquisition_fixture

package acquisitionfixture

import (
	"adapters/document"
	"testing"
)

func TestFixtureMarkerIsTheBuildersVersionPrefix(t *testing.T) {
	was := document.Version
	t.Cleanup(func() { document.Version = was })
	for version, want := range map[string]bool{"0": false, "": false, "v0.18.0": false, "fixture": false, "xfixture.abc": false, "fixture.abc": true, "fixture.abc.dirty": true} {
		document.Version = version
		if Marked() != want {
			t.Error("marker read wrongly for", version)
		}
	}
}
