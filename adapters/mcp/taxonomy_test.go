package mcp

import (
	"reflect"
	"testing"
)

func TestOwnerTaxonomyCheckpoint(t *testing.T) {
	valid := []string{
		`{"operation":"discover","effect":"read-external"}`,
		`{"operation":"check","effect":"pure","checkKind":"validate","experimental":false}`,
		`{"operation":"act","effect":"act","experimental":true}`,
		`{"operation":"run","effect":"act"}`,
	}
	for _, raw := range valid {
		if _, err := decodeTaxonomy([]byte(raw)); err != nil {
			t.Errorf("valid %s: %v", raw, err)
		}
	}
	invalid := []string{
		`null`, `[]`, `{}`, `{"operation":"read"}`,
		`{"operation":"read","effect":"pure"}`,
		`{"operation":"evaluate","effect":"read"}`,
		`{"operation":"read","effect":"read-external","CheckKind":"test"}`,
		`{"operation":"read","effect":"read-external","checkKind":null}`,
		`{"operation":"read","effect":"read-external","checkKind":""}`,
		`{"operation":"check","effect":"read-external"}`,
		`{"operation":"check","effect":"read-external","checkKind":"execute"}`,
		`{"operation":"read","effect":"read-external","experimental":null}`,
		`{"operation":"read","effect":"read-external","experimental":"true"}`,
		`{"operation":"read","effect":"read-external","unknown":true}`,
		`{"operation":"act","effect":"act","effect":"read-external"}`,
	}
	for _, raw := range invalid {
		if _, err := decodeTaxonomy([]byte(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	read := ToolTaxonomy{Operation: "read", Effect: "read-external"}
	act := ToolTaxonomy{Operation: "act", Effect: "act"}
	if !read.External() || !act.External() || (ToolTaxonomy{Operation: "transform", Effect: "pure"}).External() {
		t.Fatal("external boundary")
	}
	for _, hints := range []map[string]bool{{"destructiveHint": true}, {"readOnlyHint": false}} {
		if !read.Contradiction(hints) {
			t.Fatal("server constraint downgraded")
		}
		if act.Contradiction(hints) {
			t.Fatal("stronger owner effect refused")
		}
	}
	if act.Contradiction(map[string]bool{"readOnlyHint": true, "idempotentHint": true}) {
		t.Fatal("server weakened owner act")
	}
	if got := act.Annotations(); !reflect.DeepEqual(got, map[string]bool{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true}) {
		t.Fatalf("act annotations: %v", got)
	}
	if got := read.Annotations(); !reflect.DeepEqual(got, map[string]bool{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": true}) {
		t.Fatalf("read annotations: %v", got)
	}
	profile, err := DeriveProfile(map[string]ToolTaxonomy{"execute": act, "discover": {Operation: "discover", Effect: "read-external"}, "read": read})
	if err != nil || !reflect.DeepEqual(profile, CapabilityProfile{Effect: "act", Operations: []string{"discover", "read", "act"}}) {
		t.Fatalf("profile %v %v", profile, err)
	}
	if _, err := DeriveProfile(map[string]ToolTaxonomy{"undeclared": {}}); err == nil {
		t.Fatal("unknown child admitted")
	}
}
