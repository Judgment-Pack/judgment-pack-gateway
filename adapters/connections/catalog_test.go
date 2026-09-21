package connections

import (
	"context"
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

func TestUnsupportedCatalogOperationsRefusedBeforeCustody(t *testing.T) {
	// Nil stores prove that refused operations cannot open or mutate custody.
	for _, example := range []struct {
		broker *Broker
		method string
	}{
		{New(nil, false), "search"}, {New(nil, true), "delete"},
		{NewGmail(nil, false), "pick"}, {NewGmail(nil, false), "send"},
		{NewNotion(nil, false), "configure"}, {NewNotion(nil, false), "pick"},
		{NewObsidian(nil, false), "connect"}, {NewObsidian(nil, false), "poll"},
	} {
		out, err := example.broker.Handle(context.Background(), example.method, []byte(`{}`))
		if err != ErrRequest || out != nil {
			t.Fatalf("unsupported %s did not fail closed: %v", example.method, err)
		}
	}
}
