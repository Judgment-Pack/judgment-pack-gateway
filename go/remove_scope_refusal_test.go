package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// refusedOnly is a scope identifier whose callers were only ever refused:
// it holds a refusal journal and no session.
const refusedOnly = "refused-only"

// refusedOnlyJournal writes one refusal entry of scope to the store's
// journal under a key drawn for it, and a forwarding cursor beside it, and
// answers the journal's bytes.
func refusedOnlyJournal(t *testing.T, g *gatewayService, config, scope string) []byte {
	t.Helper()
	key := testSigningKey(t, config)
	j, err := newRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, map[string]bool{scope: true}, refusalFS{root: g.storeRoot},
		func() *signingKey { return key }, g.reachedKeys, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	s := j.scopes[scope]
	j.handOff(s, "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
	j.round()
	j.stop()
	dir := filepath.Join(g.storeRoot, journalsDir)
	if err := os.WriteFile(filepath.Join(dir, s.name+".forwarded"), []byte("0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, s.name+".jsonl"))
	if err != nil || len(data) == 0 {
		t.Fatalf("the refusal journal: %v", err)
	}
	return data
}

// remove-scope of a scope that holds no record and a refusal journal
// removes the journal, its key and its cursor after an operator entry that
// names no record and the journal (ADR-0059 §8, as built 2026-11-24); the
// journal verifies, the entry can no longer be opened, and a second run, or a
// scope holding nothing, removes nothing, as before.
func TestRemoveScopeTakesTheRefusalJournalOfAScopeThatHoldsNoRecord(t *testing.T) {
	g, config := journalStore(t)
	data := refusedOnlyJournal(t, g, config, refusedOnly)
	dir := filepath.Join(g.storeRoot, journalsDir)
	name := refusalJournalName(refusedOnly)
	raw, err := readBounded(config, maxEngineConfigBytes)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseEngineConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, err := openRefusalEntry(cfg, name, 0, "/seal", nil); !ok || err != nil {
		t.Fatalf("the entry before the removal: %v %v", ok, err)
	}
	removalsNow := func() string {
		b, _ := os.ReadFile(filepath.Join(g.storeRoot, removalsFile))
		return string(b)
	}
	removals := removalsNow()
	before := 0
	if _, err := os.Lstat(journalFile(g)); err == nil {
		before = len(journalEntries(t, g))
	}
	run := func(scope string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := cmdRemoveScopeAt([]string{"--config", config, "--scope", scope, "--by", "operator-2"}, &stdout, &stderr, fixedStamp(removalStamp))
		return code, stdout.String(), stderr.String()
	}

	code, stdout, stderr := run(refusedOnly)
	want := "remove-scope: the scope's refusal journal, " + strconv.Itoa(len(data)) + " bytes, its key and its cursor are removed\n" +
		"remove-scope: no session of the scope identifier is in the store; nothing else was removed\n" + scopeUnlockedLine()
	if code != 0 || stdout != "" || stderr != want {
		t.Fatalf("remove-scope: exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	for _, suffix := range []string{".jsonl", ".key", ".forwarded"} {
		if _, err := os.Lstat(filepath.Join(dir, name+suffix)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s stands: %v", suffix, err)
		}
	}
	if removalsNow() != removals {
		t.Fatal("the removal file changed")
	}
	entries := journalEntries(t, g)
	if len(entries) != before+1 {
		t.Fatalf("%d entries, %d before", len(entries), before)
	}
	body, _ := entries[len(entries)-1]["body"].(map[string]any)
	if body["kind"] != "remove-scope" || body["scope"] != refusedOnly || body["by"] != "operator-2" ||
		body["removalBytes"] != float64(0) || body["removalDigest"] != journalDigest(nil) || body["removalFrom"] != float64(len(removals)) ||
		body["refusalJournalBytes"] != float64(len(data)) || body["refusalJournalDigest"] != journalDigest(data) || len(body) != 9 {
		t.Fatalf("the entry: %v", body)
	}
	// the store's open session a2 is its only finding; the operator journal
	// loads whole, its new entry with it
	if _, said := journalVerdict(t, g, operatorJournal); strings.Join(said, ",") != "journal-from" {
		t.Fatalf("the journal's verdict: %v", said)
	}
	if ok, _, err := openRefusalEntry(cfg, name, 0, "/seal", nil); ok || err == nil {
		t.Fatalf("an entry of the removed journal opens: %v %v", ok, err)
	}

	// a second run, and a scope that never held anything, remove nothing
	journal := readFile(t, journalFile(g))
	for _, scope := range []string{refusedOnly, "never-held"} {
		code, stdout, stderr := run(scope)
		if code != 0 || stdout != "" || stderr != "remove-scope: no session of the scope identifier is in the store; nothing was removed\n"+scopeUnlockedLine() {
			t.Fatalf("%s: exit %d\nstdout %q\nstderr %q", scope, code, stdout, stderr)
		}
	}
	if readFile(t, journalFile(g)) != journal {
		t.Fatal("a run that removed nothing wrote an entry")
	}
}

// A run cut off after its entry and before the journal went is completed by
// the next run, as a record path's is, with no second entry; a key drawn for
// a scope that refused nothing stays.
func TestRemoveScopeCompletesARefusalJournalAloneItWasCutOffIn(t *testing.T) {
	g, config := journalStore(t)
	refusedOnlyJournal(t, g, config, refusedOnly)
	dir := filepath.Join(g.storeRoot, journalsDir)
	name := refusalJournalName(refusedOnly)
	key := testSigningKey(t, config)
	keys, err := g.reachedKeys()
	if err != nil {
		t.Fatal(err)
	}
	o := removeScopeOptions{scope: refusedOnly, by: "operator-2", engineVersion: operatorJournalVersion}
	if o.journal, err = beginOperatorJournal(g.storeRoot, g.regPath, o.engineVersion, key, keys, fixedStamp(removalStamp)); err != nil {
		t.Fatal(err)
	}
	r, err := holdRefusalRemoval(g.storeRoot, refusedOnly)
	if err != nil {
		t.Fatal(err)
	}
	body := removalBody("remove-scope", o.by, o.scope)
	describeRefusalRemoval(body, r.data)
	if err := o.journal.refusalRemovalEntry(body); err != nil {
		t.Fatal(err)
	}
	r.release()
	entries := len(journalEntries(t, g))

	var stdout, stderr bytes.Buffer
	if code := cmdRemoveScopeAt([]string{"--config", config, "--scope", refusedOnly, "--by", "operator-2"}, &stdout, &stderr, fixedStamp(removalStamp)); code != 0 ||
		stderr.String() != "remove-scope: "+refusalRemovalCompletedNote+"\nremove-scope: no session of the scope identifier is in the store; nothing else was removed\n"+scopeUnlockedLine() {
		t.Fatalf("the second run: %d %q", code, stderr.String())
	}
	if n := len(journalEntries(t, g)); n != entries {
		t.Fatalf("%d entries after the second run, %d before", n, entries)
	}
	for _, suffix := range []string{".jsonl", ".key", ".forwarded"} {
		if _, err := os.Lstat(filepath.Join(dir, name+suffix)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s stands: %v", suffix, err)
		}
	}

	// a key alone, as a start draws for a scope that refused nothing yet
	if _, _, err := (refusalFS{root: g.storeRoot}).key(name); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := cmdRemoveScopeAt([]string{"--config", config, "--scope", refusedOnly, "--by", "operator-2"}, &stdout, &stderr, fixedStamp(removalStamp)); code != 0 ||
		stderr.String() != "remove-scope: no session of the scope identifier is in the store; nothing was removed\n"+scopeUnlockedLine() {
		t.Fatalf("a key alone: %d %q", code, stderr.String())
	}
	if _, err := os.Lstat(filepath.Join(dir, name+".key")); err != nil {
		t.Fatalf("the key of a scope that refused nothing went: %v", err)
	}
}

// Restarts before the scope's first entry, after a removal that completed,
// keep the key drawn at the first and say nothing of a cut-off run: a key
// beside no journal is never a removal's leftover, since the journal goes
// last.
func TestRestartsBeforeAnyEntryKeepTheKeyAfterACompletedRemoval(t *testing.T) {
	h := limitsSetup(t, refusalLimits())
	dir := filepath.Join(h.g.storeRoot, journalsDir)
	name := refusalJournalName(callerScopeA)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := removalBody("remove-scope", "operator-1", callerScopeA)
	body.set("registryFrom", vInt(0))
	body.set("removalFrom", vInt(0))
	body.set("removalBytes", vInt(0))
	body.set("removalDigest", vString(journalDigest(nil)))
	describeRefusalRemoval(body, []byte("{\"removed\":1}\n"))
	line, err := signedJournalEntry(h.g.store.signing.key(), operatorJournal, 0, "", "2026-11-24T00:00:00Z", body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, operatorJournal+".jsonl"), line, 0o600); err != nil {
		t.Fatal(err)
	}
	var key string
	for start := 0; start < 3; start++ {
		stderr := &refusalStderr{}
		if err := h.g.openRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, stderr); err != nil {
			t.Fatal(err)
		}
		h.g.refusals.stop()
		if stderr.String() != "" {
			t.Errorf("start %d: %q", start, stderr.String())
		}
		got := readFile(t, filepath.Join(dir, name+".key"))
		if start > 0 && got != key {
			t.Fatalf("start %d drew another key", start)
		}
		key = got
	}
}
