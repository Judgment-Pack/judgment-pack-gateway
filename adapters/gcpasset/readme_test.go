package gcpasset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The adapters README's section lists, each as code, what the adapter
// holds to: the write list's version and every permission on it, every
// read-only role, every identity scope, both scopes requested and every
// asset type projected.
func TestTheREADMEListsWhatTheAdapterHoldsTo(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	start := strings.Index(text, "## adapter-gcp-asset\n")
	if start < 0 {
		t.Fatal("the README has no adapter-gcp-asset section")
	}
	section := text[start+3:]
	if end := strings.Index(section, "\n## "); end >= 0 {
		section = section[:end]
	}
	want := append(append([]string{WriteListVersion, AssetScope, CheckScope}, writeList...), ReadOnlyRoles()...)
	want = append(want, ServedAssetTypes()...)
	for scope := range identityScopes {
		want = append(want, scope)
	}
	for _, item := range want {
		if !strings.Contains(section, "`"+item+"`") {
			t.Errorf("the README's section does not list %s", item)
		}
	}
}
