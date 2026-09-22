package connections

import (
	"encoding/json"
	"testing"
)

func TestCatalogCannotMutateDispatchOrAdvertiseWrites(t *testing.T) {
	first := ConnectionCatalog()
	first.Providers[0].Operations[0] = "send"
	first.Providers[0].ID = "fake"
	for _, descriptor := range ConnectionCatalog().Providers {
		if !descriptor.supports("status") || descriptor.supports("send") || descriptor.supports("delete") || descriptor.supports("read") {
			t.Fatal("catalog confuses control operations and source grants", descriptor.ID)
		}
		if _, ok := LookupProvider(descriptor.ID); !ok {
			t.Fatal("catalog provider cannot be dispatched")
		}
	}
	if _, ok := LookupProvider("slack"); ok {
		t.Fatal("unimplemented provider advertised")
	}
	raw, err := json.Marshal(ConnectionCatalog())
	if err != nil || len(raw) > 32<<10 {
		t.Fatal("catalog does not fit the transport budget")
	}
}

func TestCatalogDoesNotAdvertiseUnsupportedOperations(t *testing.T) {
	for _, example := range []struct {
		provider string
		method   string
	}{
		{"google-drive", "search"}, {"google-drive", "delete"},
		{"gmail", "pick"}, {"gmail", "send"},
		{"notion", "configure"}, {"notion", "pick"},
		{"obsidian", "connect"}, {"obsidian", "poll"},
	} {
		descriptor, ok := LookupProvider(example.provider)
		if !ok || descriptor.supports(example.method) {
			t.Fatalf("unsupported %s advertised for %s", example.method, example.provider)
		}
	}
}
