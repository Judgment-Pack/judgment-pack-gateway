//go:build linux || darwin

package connections

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// An observation journal exports as the custody holds it -- the bindings'
// operation records, revoked ones kept, and nothing of the credentials --
// read under the custody lock; the empty journal where none is kept yet;
// nothing made for a custody that is not there; and a journal that does not
// read as one is refused, never exported.
func TestSourceObservationJournalExportsAsHeld(t *testing.T) {
	b, dir, _ := sourceBroker(t)
	empty, err := ExportSourceObservations(dir, "alice")
	if err != nil || string(empty) != `{"version":"1","operations":[]}` {
		t.Fatalf("the journal of a custody that keeps none: %q %v", empty, err)
	}
	first := bindSource(t, b)
	revokeSource(t, b, first.BindingID)
	bindSource(t, b)
	journal, err := ExportSourceObservations(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	held, err := os.ReadFile(filepath.Join(b.store.root.Name(), "source-bindings.json"))
	if err != nil || !bytes.Equal(journal, held) {
		t.Fatalf("the exported journal is not the journal held: %q, held %q %v", journal, held, err)
	}
	for _, secret := range []string{"source-access-private", "source-refresh-private", "source-client-secret"} {
		if bytes.Contains(journal, []byte(secret)) {
			t.Fatalf("the journal carries %s", secret)
		}
	}
	var parsed sourceBindingStore
	if err := json.Unmarshal(journal, &parsed); err != nil || len(parsed.Operations) != 2 || !parsed.Operations[0].Revoked || parsed.Operations[1].Revoked {
		t.Fatalf("the journal's records: %+v %v", parsed, err)
	}
	absent := filepath.Join(t.TempDir(), "absent")
	if _, err := ExportSourceObservations(absent, "alice"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a custody that is not there: %v", err)
	}
	if _, err := os.Lstat(absent); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the export made a custody")
	}
	if _, err := ExportSourceObservations("relative", "alice"); err != ErrRequest {
		t.Fatalf("a relative custody: %v", err)
	}
	if err := os.WriteFile(filepath.Join(b.store.root.Name(), "source-bindings.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := ExportSourceObservations(dir, "alice"); err != ErrStorage || out != nil {
		t.Fatalf("a journal that does not read as one: %q %v", out, err)
	}
}
