package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A remove-scope run cut off after the scope's journal went and before its
// key did is completed at the next start, before any key is read (ADR-0059
// §8, as built): the first refusal after the start makes the journal under
// a key drawn then, never under the old one, and the start says so.
func TestARestartCompletesACutOffRemovalBeforeAnyKeyIsRead(t *testing.T) {
	h := limitsSetup(t, refusalLimits())
	dir := filepath.Join(h.g.storeRoot, journalsDir)
	if err := h.g.openRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, &refusalStderr{}); err != nil {
		t.Fatal(err)
	}
	first := h.g.refusals
	s := first.scopes[callerScopeA]
	first.handOff(s, "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
	first.round()
	first.stop()
	name := refusalJournalName(callerScopeA)
	oldKey, err := os.ReadFile(filepath.Join(dir, name+".key"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, name+".jsonl"))
	if err != nil || len(data) == 0 {
		t.Fatalf("the first run's journal: %v", err)
	}

	// the remove-scope run: its operator entry names the journal, the
	// journal goes, and the run is cut off before the key does
	body := removalBody("remove-scope", "operator-1", callerScopeA)
	body.set("registryFrom", vInt(0))
	body.set("removalFrom", vInt(0))
	body.set("removalBytes", vInt(1))
	body.set("removalDigest", vString(strings.Repeat("0", 64)))
	describeRefusalRemoval(body, data)
	line, err := signedJournalEntry(h.g.store.signing.key(), operatorJournal, 0, "", "2026-11-24T00:00:00Z", body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, operatorJournal+".jsonl"), line, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, name+".jsonl")); err != nil {
		t.Fatal(err)
	}

	stderr := &refusalStderr{}
	if err := h.g.openRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, stderr); err != nil {
		t.Fatal(err)
	}
	again := h.g.refusals
	t.Cleanup(again.stop)
	if !strings.Contains(stderr.String(), "refusal journal: journal "+name+": a remove-scope run was cut off; ") {
		t.Errorf("stderr: %q", stderr.String())
	}
	newKey, err := os.ReadFile(filepath.Join(dir, name+".key"))
	if err != nil || bytes.Equal(newKey, oldKey) {
		t.Fatalf("the key after the start is the old one, or none: %v", err)
	}
	s = again.scopes[callerScopeA]
	again.handOff(s, "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
	again.round()
	made, err := os.ReadFile(filepath.Join(dir, name+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines, _ := journalLines(made)
	if len(lines) != 1 {
		t.Fatalf("%d entries in the journal made after the start", len(lines))
	}
	if ok, _, err := matchRefusalEntry(lines[0], s.secret, "/seal", nil); !ok || err != nil || strings.TrimSpace(string(oldKey)) == hex.EncodeToString(s.secret) {
		t.Fatalf("the entry is not under the key drawn at the start: %v", err)
	}
	// a start after the scope journaled again under its new key says
	// nothing of the removal the entry names
	again.stop()
	quiet := &refusalStderr{}
	if err := h.g.openRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, quiet); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.g.refusals.stop)
	if strings.Contains(quiet.String(), "cut off") {
		t.Errorf("a later start: %q", quiet.String())
	}
}

// A round that made the journal's file and then wrote nothing to it, its
// entry failing under the lock, takes the empty file away: it was never a
// journal, so the next round makes it again rather than taking it as a
// removal.
func TestARoundThatMadeTheJournalAndWroteNothingLeavesNoFile(t *testing.T) {
	h, j, s := refusalUnit(t, refusalDefaultCap)
	path := filepath.Join(h.g.storeRoot, journalsDir, s.name+".jsonl")
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("a journal before the first entry: %v", err)
	}
	failed := errors.New("the entry could not be made")
	if err := (refusalFS{root: h.g.storeRoot}).append(s, func(refusalEnd) ([]byte, error) { return nil, failed }); !errors.Is(err, failed) {
		t.Fatalf("the round: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("the round left a file: %v", err)
	}
	if s.found || s.lost {
		t.Fatalf("found %v, lost %v after a round that wrote nothing", s.found, s.lost)
	}
	j.handOff(s, "/seal", refusalNote{reason: "session"}, 404, unitCaller(), nil, time.Now())
	j.round()
	if n := len(refusalBodies(t, h.g.storeRoot, callerScopeA)); n != 1 {
		t.Fatalf("%d entries after the next round", n)
	}
}
