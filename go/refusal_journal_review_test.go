package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An /acquire refusal is journaled under the code it maps to, and one that
// maps to none is not journaled (ADR-0059 §4).
func TestRefusalJournalAcquireCodeIsNoneWhereNoneMaps(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{badRequest{errors.New("arguments: an object is expected")}, ""},
		{ofSession(badRequest{errors.New("session id must match the pattern")}), "session"},
		{ofSession(badRequest{errors.New("the registry could not be read")}), "session"},
		{badRequest{errors.New(scopeRefusal)}, "scope"},
		{ofSession(errors.New("a 503 stays as it was")), ""},
	} {
		if got := acquireRefusalCode(c.err); got != c.want {
			t.Errorf("%q: code %q, want %q", c.err, got, c.want)
		}
	}
}

// A run cut off after its operator entry names the refusal journal and
// before the journal goes is completed by a second: the journal the entry
// names goes with its key and cursor; one holding other bytes stands.
func TestRemoveScopeCompletesTheRefusalJournalItsEntryNames(t *testing.T) {
	g, _ := scopeStore(t)
	dir := filepath.Join(g.storeRoot, journalsDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	name := refusalJournalName(testScope)
	data := []byte("{\"claimed\":1}\n")
	write := func(file string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, file), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(name+".jsonl", data)
	write(name+".key", []byte(strings.Repeat("ab", 32)+"\n"))
	write(name+".forwarded", []byte("0\n"))
	body := removalBody("remove-scope", "operator-1", testScope)
	body.set("registryFrom", vInt(0))
	body.set("removalFrom", vInt(0))
	body.set("removalBytes", vInt(1))
	body.set("removalDigest", vString(strings.Repeat("0", 64)))
	describeRefusalRemoval(body, data)
	line, err := signedJournalEntry(g.store.signing.key(), operatorJournal, 0, "", "2026-11-23T00:00:00Z", body)
	if err != nil {
		t.Fatal(err)
	}
	write(operatorJournal+".jsonl", line)
	keys, err := g.reachedKeys()
	if err != nil {
		t.Fatal(err)
	}
	// other bytes than the entry names stand
	write(name+".jsonl", append(bytes.Clone(data), data...))
	var out removalOutcome
	if err := completeClaimedRefusalRemoval(g.storeRoot, testScope, keys, &out); err != nil || len(out.notes) != 1 || !strings.Contains(out.notes[0], "it stands") {
		t.Fatalf("other bytes: %v %q", err, out.notes)
	}
	if _, err := os.Lstat(filepath.Join(dir, name+".key")); err != nil {
		t.Fatalf("the key of a journal no entry names went: %v", err)
	}
	write(name+".jsonl", data)
	out = removalOutcome{}
	if err := completeClaimedRefusalRemoval(g.storeRoot, testScope, keys, &out); err != nil || len(out.notes) != 1 || !strings.Contains(out.notes[0], "removed now") {
		t.Fatalf("the bytes named: %v %q", err, out.notes)
	}
	for _, suffix := range []string{".jsonl", ".key", ".forwarded"} {
		if _, err := os.Lstat(filepath.Join(dir, name+suffix)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s stands: %v", suffix, err)
		}
	}
}

