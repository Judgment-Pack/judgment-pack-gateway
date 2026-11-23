package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The operator journal (ADR-0056) on the filesystem kind: what the commands
// write, what a crash leaves and the next run settles, and what gateway
// verify finds of it. Synthetic stores and keys only.

// journalStore is retainStore's store with its configuration raised to
// operatorJournalVersion, so the commands begin the journal.
func journalStore(t *testing.T) (*gatewayService, string) {
	t.Helper()
	g, config := retainStore(t)
	raw := readFile(t, config)
	raised := strings.Replace(raw, `"engineVersion":"`+retentionVersion+`"`, `"engineVersion":"`+operatorJournalVersion+`"`, 1)
	if raised == raw {
		t.Fatal("the configuration's version was not raised")
	}
	if err := os.WriteFile(config, []byte(raised), 0o600); err != nil {
		t.Fatal(err)
	}
	return g, config
}

// retainA1 is a retention call for a1, past its window, that can be run
// again with the same acknowledgments at the same time; sum is the
// acknowledgment file's SHA-256.
func retainA1(t *testing.T, g *gatewayService, config string) (run func() (int, string), sum string) {
	t.Helper()
	a1 := sealOf(t, g.regPath, g.publicKey, "a1")
	now := sealTime(t, a1).Add(31 * 24 * time.Hour)
	acks := writeAcks(t, retentionAckLine(retentionAckKey, "a1", a1.signature, a1.finalCount, stampOf(sealTime(t, a1).Add(time.Hour))))
	data, _ := os.ReadFile(acks)
	return func() (int, string) {
		code, _, stderr := runRetain(config, acks, now)
		return code, stderr
	}, sha256Hex(data)
}

func journalFile(g *gatewayService) string {
	return filepath.Join(g.storeRoot, journalsDir, operatorJournal+".jsonl")
}

func pendingFile(g *gatewayService) string {
	return filepath.Join(g.storeRoot, journalsDir, operatorJournal+".pending")
}

func journalEntries(t *testing.T, g *gatewayService) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSuffix(readFile(t, journalFile(g)), "\n"), "\n") {
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("an entry is not JSON: %v %q", err, line)
		}
		out = append(out, e)
	}
	return out
}

// journalVerdict is the store's verdict: its journal findings and its
// journal observations, each as status/observation, journal and ordinal.
func journalVerdict(t *testing.T, g *gatewayService, require ...string) (*report, []string) {
	t.Helper()
	rep, err := verifyWithRegistry(g.storeRoot, g.regPath, "gateway:test", g.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	rep.requireJournals(require)
	var said []string
	for _, f := range append(append([]finding{}, rep.Findings...), rep.Observations...) {
		if _, of := f["journal"]; !of {
			continue
		}
		what, _ := f["status"].(string)
		if what == "" {
			what, _ = f["observation"].(string)
		}
		if ordinal, ok := f["ordinal"]; ok {
			what += " " + journalJSON(ordinal)
		}
		said = append(said, what)
	}
	return rep, said
}

func journalJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func testSigningKey(t *testing.T, config string) *signingKey {
	t.Helper()
	cfg, err := retainConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := loadSeed(cfg.seed)
	if err != nil {
		t.Fatal(err)
	}
	return newSigningKey(newSeedSigner(seed))
}

// After a retain, the acknowledgment file's digest and the key ids are read
// back from the store, in an entry signed by the key in force that names
// the bytes the call appended; the store verifies with the journal observed,
// and an entry altered is found.
func TestOperatorJournalRetainEntryReadsBackAndAnAlteredEntryIsFound(t *testing.T) {
	g, config := journalStore(t)
	run, sum := retainA1(t, g, config)
	if code, stderr := run(); code != 0 {
		t.Fatalf("retain: %d %q", code, stderr)
	}
	entries := journalEntries(t, g)
	removal := []byte(readFile(t, filepath.Join(g.storeRoot, removalsFile)))
	if len(entries) != 1 {
		t.Fatalf("the journal: %v", entries)
	}
	e := entries[0]
	body, _ := e["body"].(map[string]any)
	ids, _ := body["acknowledgedBy"].([]any)
	if e["journal"] != "operator" || e["journalVersion"] != "1" || e["ordinal"] != float64(0) || e["previous"] != nil || e["keyId"] != keyIDFor(g.publicKey) ||
		body["kind"] != "retain" || body["acknowledgments"] != sum || len(ids) != 1 || ids[0] != keyIDFor(retentionAckKey.Public().(ed25519.PublicKey)) ||
		body["by"] != "operator-1" || body["sessions"] != float64(1) || body["removalFrom"] != float64(0) ||
		body["removalBytes"] != float64(len(removal)) || body["removalDigest"] != sha256Hex(removal) || body["scope"] != nil {
		t.Fatalf("the entry: %v", e)
	}
	if _, said := journalVerdict(t, g, "operator"); strings.Join(said, ",") != "journal-from" {
		t.Fatalf("the verdict: %v", said)
	}
	line := readFile(t, journalFile(g))
	flipped := strings.Replace(line, sum, strings.Repeat("0", 64), 1)
	if err := os.WriteFile(journalFile(g), []byte(flipped), 0o600); err != nil {
		t.Fatal(err)
	}
	if rep, said := journalVerdict(t, g); strings.Join(said, ",") != "journal-entry-forged 0" || rep.OK {
		t.Fatalf("an altered entry: %v", said)
	}
}

// A configuration of an earlier version, on a store with no journal, writes
// none, and the verdict says nothing of journals; --require-journal then
// finds the journal missing. Once a journal is begun, a command given flags,
// which name no version, still writes its entry.
func TestOperatorJournalVersionGate(t *testing.T) {
	g, config := retainStore(t)
	run, _ := retainA1(t, g, config)
	if code, stderr := run(); code != 0 {
		t.Fatalf("retain: %d %q", code, stderr)
	}
	if _, err := os.Lstat(filepath.Join(g.storeRoot, journalsDir)); !os.IsNotExist(err) {
		t.Fatalf("a journal under an earlier version: %v", err)
	}
	rep, said := journalVerdict(t, g)
	out, _ := rep.marshal()
	if len(said) != 0 || bytes.Contains(out, []byte("journal")) {
		t.Fatalf("a store with no journal: %s", out)
	}
	if _, said := journalVerdict(t, g, "operator"); strings.Join(said, ",") != "journal-missing" {
		t.Fatalf("--require-journal: %v", said)
	}

	g, config = journalStore(t)
	run, _ = retainA1(t, g, config)
	if code, stderr := run(); code != 0 {
		t.Fatalf("retain: %d %q", code, stderr)
	}
	cfg, _ := retainConfig(config)
	before := len(readFile(t, filepath.Join(g.storeRoot, removalsFile)))
	var stdout, stderr bytes.Buffer
	if code := cmdRemoveScopeAt([]string{"--store", g.storeRoot, "--seed", cfg.seed, "--registry", g.regPath, "--authority", "gateway:test", "--scope", otherScope, "--by", "operator-2"},
		&stdout, &stderr, fixedStamp(removalStamp)); code != 0 {
		t.Fatalf("remove-scope: %d %q", code, stderr.String())
	}
	removal := []byte(readFile(t, filepath.Join(g.storeRoot, removalsFile)))
	entries := journalEntries(t, g)
	if len(entries) != 2 {
		t.Fatalf("the journal: %v", entries)
	}
	body, _ := entries[1]["body"].(map[string]any)
	if body["kind"] != "remove-scope" || body["scope"] != otherScope || body["by"] != "operator-2" || body["removalFrom"] != float64(before) ||
		body["removalBytes"] != float64(len(removal)-before) || body["removalDigest"] != sha256Hex(removal[before:]) {
		t.Fatalf("the remove-scope entry: %v", entries[1])
	}
	if _, said := journalVerdict(t, g, "operator"); strings.Join(said, ",") != "journal-from" {
		t.Fatalf("the verdict: %v", said)
	}
}

// A crash after the records leaves the staged entry, which verify reports
// journal-entry-missing until it commits; the rerun commits the first run's
// own entry, its digest kept, and writes no second one.
func TestOperatorJournalSettlesAStagedEntryAfterTheRecords(t *testing.T) {
	g, config := journalStore(t)
	run, sum := retainA1(t, g, config)
	journalStepCut = func(step string) error {
		if step == "records" {
			return errors.New("cut off")
		}
		return nil
	}
	code, _ := run()
	journalStepCut = nil
	if code == 0 {
		t.Fatal("the cut run succeeded")
	}
	staged := readFile(t, pendingFile(g))
	if _, err := os.Lstat(journalFile(g)); !os.IsNotExist(err) {
		t.Fatalf("an entry was committed: %v", err)
	}
	for _, require := range [][]string{nil, {"operator"}} {
		if _, said := journalVerdict(t, g, require...); strings.Join(said, ",") != "journal-entry-missing 0" {
			t.Fatalf("a staged entry %v: %v", require, said)
		}
	}
	if code, stderr := run(); code != 0 {
		t.Fatalf("the rerun: %d %q", code, stderr)
	}
	if got := readFile(t, journalFile(g)); got != staged || !strings.Contains(got, sum) {
		t.Fatalf("the committed entry is not the first run's: %q %q", got, staged)
	}
	if _, err := os.Lstat(pendingFile(g)); !os.IsNotExist(err) {
		t.Fatalf("the staged entry is still there: %v", err)
	}
	if _, said := journalVerdict(t, g, "operator"); strings.Join(said, ",") != "journal-from" {
		t.Fatalf("the verdict: %v", said)
	}
}

// A crash after staging, before the records, leaves an entry naming bytes
// that are not there: the rerun removes it and writes its own, one entry.
func TestOperatorJournalReplacesAStagedEntryWithNoRecords(t *testing.T) {
	g, config := journalStore(t)
	run, _ := retainA1(t, g, config)
	journalStepCut = func(step string) error {
		if step == "staged" {
			return errors.New("cut off")
		}
		return nil
	}
	code, _ := run()
	journalStepCut = nil
	if code == 0 {
		t.Fatal("the cut run succeeded")
	}
	if _, err := os.Lstat(filepath.Join(g.storeRoot, removalsFile)); !os.IsNotExist(err) {
		t.Fatalf("records were appended: %v", err)
	}
	if code, stderr := run(); code != 0 {
		t.Fatalf("the rerun: %d %q", code, stderr)
	}
	if entries := journalEntries(t, g); len(entries) != 1 {
		t.Fatalf("the journal: %v", entries)
	}
	if _, said := journalVerdict(t, g); strings.Join(said, ",") != "journal-from" {
		t.Fatalf("the verdict: %v", said)
	}
}

// A staged entry whose range the removal file does not hold is refused,
// and nothing changes.
func TestOperatorJournalRefusesAStagedEntryTheStoreDoesNotMatch(t *testing.T) {
	g, config := journalStore(t)
	run, _ := retainA1(t, g, config)
	journalStepCut = func(step string) error {
		if step == "records" {
			return errors.New("cut off")
		}
		return nil
	}
	run()
	journalStepCut = nil
	removal := filepath.Join(g.storeRoot, removalsFile)
	appendLine(t, removal, "{}\n")
	before := readFile(t, removal)
	if code, stderr := run(); code == 0 || !strings.Contains(stderr, "journal-pending") {
		t.Fatalf("the rerun: %d %q", code, stderr)
	}
	if readFile(t, removal) != before {
		t.Fatal("the removal file changed")
	}
	if _, err := os.Lstat(pendingFile(g)); err != nil {
		t.Fatalf("the staged entry: %v", err)
	}
}

func appendLine(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}

// Each of step 9's findings, the first in its order, and journal-from.
func TestOperatorJournalVerifyFindings(t *testing.T) {
	g, config := journalStore(t)
	run, _ := retainA1(t, g, config)
	if code, stderr := run(); code != 0 {
		t.Fatalf("retain: %d %q", code, stderr)
	}
	key := testSigningKey(t, config)
	other := newSigningKey(newSeedSigner(bytes.Repeat([]byte{9}, 32)))
	e0 := readFile(t, journalFile(g))
	removal0 := readFile(t, filepath.Join(g.storeRoot, removalsFile))
	registry0 := readFile(t, g.regPath)
	commandSealLine := `{"kind":"seal-after-interruption","sealedVia":"command"}` + "\n"
	junk := "{}\n"
	line0 := strings.TrimSuffix(e0, "\n")
	removalEntry := func(k *signingKey, ordinal int64, previous string, from int, appended string) string {
		body := removalBody("remove-artifact", "operator-3", "")
		body.set("registryFrom", vInt(len(registry0)))
		body.set("removalFrom", vInt(from))
		body.set("removalBytes", vInt(len(appended)))
		body.set("removalDigest", vString(sha256Hex([]byte(appended))))
		line, err := signedJournalEntry(k, operatorJournal, ordinal, previous, removalStamp, body)
		if err != nil {
			t.Fatal(err)
		}
		return string(line)
	}
	sealEntry := func(seals int, sealed string) string {
		body := newObject()
		body.set("kind", vString("seal-open"))
		body.set("registryFrom", vInt(len(registry0)))
		body.set("removalFrom", vInt(len(removal0)))
		body.set("seals", vInt(seals))
		body.set("sealDigest", vString(sha256Hex([]byte(sealed))))
		body.set("delivered", vBool(false))
		line, err := signedJournalEntry(key, operatorJournal, 1, sha256Hex([]byte(line0)), removalStamp, body)
		if err != nil {
			t.Fatal(err)
		}
		return string(line)
	}
	reSigned := func(k *signingKey) string {
		v, _ := parseRecordJSON([]byte(line0))
		obj := v.(*vObject)
		raw, _ := obj.get("body")
		line, err := signedJournalEntry(k, operatorJournal, 0, "", removalStamp, raw.(*vObject))
		if err != nil {
			t.Fatal(err)
		}
		return string(line)
	}
	sig := strings.LastIndex(line0, `"signature":"`) + len(`"signature":"`)
	flip := map[byte]byte{'0': '1'}[line0[sig]]
	if flip == 0 {
		flip = '0'
	}
	badSignature := line0[:sig] + string(flip) + line0[sig+1:] + "\n"
	e1 := removalEntry(key, 1, sha256Hex([]byte(line0)), len(removal0), junk)
	trimmed := strings.TrimSuffix(removal0, "\n")
	lastRecord := trimmed[strings.LastIndex(trimmed, "\n")+1:]
	piece := `{"kind":"artifact-rem`
	for _, c := range []struct {
		name, journal, removal, registry, pending string
		require                                   []string
		want                                      string
	}{
		{name: "holds", journal: e0, want: "journal-from"},
		{name: "two entries hold", journal: e0 + e1, removal: junk, want: "journal-from"},
		{name: "a signature that does not verify", journal: badSignature, want: "journal-entry-forged 0"},
		{name: "a key the walk did not reach", journal: reSigned(other), want: "journal-entry-forged 0"},
		{name: "a torn last line", journal: e0 + `{"journal":"operator"`, want: "journal-from"},
		{name: "the first entry removed", journal: e1, removal: junk, want: "journal-order 0"},
		{name: "the order broken in the middle", journal: e0 + removalEntry(key, 1, strings.Repeat("0", 64), len(removal0), junk), removal: junk, want: "journal-order 1"},
		{name: "a range not of its digest", journal: e0 + e1, removal: "[]\n", want: "journal-entry-mismatch 1"},
		{name: "a range past the file", journal: e0 + e1, want: "journal-entry-mismatch 1"},
		{name: "a missing tail", journal: e0, removal: junk, want: "journal-entry-missing 1"},
		{name: "a command seal no entry takes", journal: e0, registry: commandSealLine, want: "journal-entry-missing 1"},
		{name: "seals not of their digest", journal: e0 + sealEntry(1, junk), registry: commandSealLine, want: "journal-entry-mismatch 1"},
		{name: "seals beyond those that remain", journal: e0 + sealEntry(1, commandSealLine), want: "journal-entry-mismatch 1"},
		{name: "seals of their digest", journal: e0 + sealEntry(1, commandSealLine), registry: commandSealLine, want: "journal-from"},
		{name: "a staged entry", journal: e0, pending: e1, require: []string{"operator"}, want: "journal-entry-missing 1"},
		{name: "the journal removed whole", require: []string{"operator"}, want: "journal-missing"},
		{name: "a torn tail that loads as no record", journal: e0, removal: piece, require: []string{"operator"}, want: "journal-from,journal-torn-tail"},
		{name: "a torn tail that loads as a record", journal: e0, removal: lastRecord, want: "journal-entry-missing 1"},
		{name: "a torn tail while an entry is staged", journal: e0, pending: e1, removal: piece, want: "journal-entry-missing 1"},
		{name: "an uncovered line before a torn tail", journal: e0, removal: junk + piece, want: "journal-entry-missing 1"},
		{name: "the journal removed whole, not required", want: ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(g.storeRoot, removalsFile), []byte(removal0+c.removal), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(g.regPath, []byte(registry0+c.registry), 0o600); err != nil {
				t.Fatal(err)
			}
			os.Remove(journalFile(g))
			os.Remove(pendingFile(g))
			if c.journal != "" {
				if err := os.WriteFile(journalFile(g), []byte(c.journal), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if c.pending != "" {
				if err := os.WriteFile(pendingFile(g), []byte(c.pending), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, said := journalVerdict(t, g, c.require...); strings.Join(said, ",") != c.want {
				t.Fatalf("%v, want %q", said, c.want)
			}
		})
	}
}

// seal-open's entry names the command seals it appended, delivered false
// where no receipt sink is configured, after the retain's entry.
func TestOperatorJournalSealOpenNamesItsSeals(t *testing.T) {
	g, config := journalStore(t)
	run, _ := retainA1(t, g, config)
	if code, stderr := run(); code != 0 {
		t.Fatalf("retain: %d %q", code, stderr)
	}
	before := len(readFile(t, g.regPath))
	var stdout, stderr bytes.Buffer
	if code := cmdSealOpenAt([]string{"--config", config, "--session", "a2"}, &stdout, &stderr, fixedStamp(removalStamp)); code != 0 {
		t.Fatalf("seal-open: %d %q", code, stderr.String())
	}
	registry := readFile(t, g.regPath)
	entries := journalEntries(t, g)
	if len(entries) != 2 {
		t.Fatalf("the journal: %v", entries)
	}
	body, _ := entries[1]["body"].(map[string]any)
	if body["kind"] != "seal-open" || body["seals"] != float64(1) || body["delivered"] != false || body["registryFrom"] != float64(before) ||
		body["sealDigest"] != sha256Hex([]byte(registry[before:])) {
		t.Fatalf("the seal-open entry: %v", entries[1])
	}
	if _, said := journalVerdict(t, g, "operator"); strings.Join(said, ",") != "journal-from" {
		t.Fatalf("the verdict: %v", said)
	}
}

// A full export carries the journal, whole, and its verdict observes it; an
// export by scope carries none.
func TestOperatorJournalExport(t *testing.T) {
	g, config := journalStore(t)
	run, _ := retainA1(t, g, config)
	if code, stderr := run(); code != 0 {
		t.Fatalf("retain: %d %q", code, stderr)
	}
	out := filepath.Join(t.TempDir(), "export")
	if _, err := exportEngine(config, out, nil, ""); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(out, "store", journalsDir, operatorJournal+".jsonl")); got != readFile(t, journalFile(g)) {
		t.Fatalf("the exported journal: %q", got)
	}
	// its directory and file check against the manifest, as every other
	// place an export writes
	requireExportChecks(t, out)
	rep, err := verifyWithRegistry(filepath.Join(out, "store"), filepath.Join(out, "registry"), "gateway:test", g.publicKey)
	if err != nil || !strings.Contains(journalJSON(rep.Observations), `"journal-from"`) {
		t.Fatalf("the export's verdict: %v %v", err, rep)
	}
	if keep := os.Getenv("GATEWAY_TEST_JOURNAL_EXPORT"); keep != "" {
		if err := os.CopyFS(keep, os.DirFS(out)); err != nil {
			t.Fatal(err)
		}
	}
	scoped := filepath.Join(t.TempDir(), "scoped")
	if _, err := exportEngine(config, scoped, nil, testScope); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(scoped, "store", journalsDir)); !os.IsNotExist(err) {
		t.Fatalf("an export by scope carries a journal: %v", err)
	}
}

// A reader refuses an export whose manifest names a path it does not write:
// the check by which a reader of v0.38.0, whose paths hold no journal,
// refuses an export that holds store/journals/operator.jsonl (ADR-0056 §7).
func TestOperatorJournalExportOlderReaderRefuses(t *testing.T) {
	g, config := journalStore(t)
	run, _ := retainA1(t, g, config)
	if code, stderr := run(); code != 0 {
		t.Fatalf("retain: %d %q", code, stderr)
	}
	out := filepath.Join(t.TempDir(), "export")
	if _, err := exportEngine(config, out, nil, ""); err != nil {
		t.Fatal(err)
	}
	if !exportPathWritten("store/journals/operator.jsonl") || exportPathWritten("store/journals/operator.txt") || exportPathWritten("store/journals/Operator.jsonl") {
		t.Fatal("the journal paths an export writes")
	}
	manifest := filepath.Join(out, "manifest.json")
	text := readFile(t, manifest)
	unknown := strings.Replace(text, `"store/journals/operator.jsonl"`, `"store/journals/operator.txt"`, 1)
	if unknown == text {
		t.Fatalf("the manifest names no journal: %s", text)
	}
	if err := os.WriteFile(manifest, []byte(unknown), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := checkExport(out); err == nil || !strings.Contains(err.Error(), "not one an export writes") {
		t.Fatalf("a path the reader does not write: %v", err)
	}
}

// store rotate's store-rotate entry, in the store rotated from, names the
// seals the rotation appended, and the old store verifies with its journal.
func TestOperatorJournalStoreRotateNamesItsSealsInTheOldStore(t *testing.T) {
	g, config := journalStore(t)
	run, _ := retainA1(t, g, config)
	if code, stderr := run(); code != 0 {
		t.Fatalf("retain: %d %q", code, stderr)
	}
	before := len(readFile(t, g.regPath))
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := cmdStoreRotateAt([]string{"--config", config, "--new-store", filepath.Join(dir, "store"), "--new-registry", filepath.Join(dir, "registry.jsonl")},
		&stdout, &stderr, fixedStamp(removalStamp)); code != 0 {
		t.Fatalf("store rotate: %d %q", code, stderr.String())
	}
	registry := readFile(t, g.regPath)
	entries := journalEntries(t, g)
	if len(entries) != 2 {
		t.Fatalf("the journal: %v", entries)
	}
	body, _ := entries[1]["body"].(map[string]any)
	if body["kind"] != "store-rotate" || body["seals"] != float64(1) || body["delivered"] != false || body["registryFrom"] != float64(before) ||
		body["sealDigest"] != sha256Hex([]byte(registry[before:])) {
		t.Fatalf("the store-rotate entry: %v", entries[1])
	}
	if _, said := journalVerdict(t, g, "operator"); strings.Join(said, ",") != "journal-from" {
		t.Fatalf("the old store's verdict: %v", said)
	}
}

// A removal call that finds the removal file ending in an unterminated line
// that loads as a record refuses, naming the file and how to mend it, and
// changes nothing; one that finds a piece that loads as none begins its
// range with the piece, and the journal then holds (ADR-0056, Amendment B).
func TestOperatorJournalTornRemovalPiece(t *testing.T) {
	g, config := journalStore(t)
	run, _ := retainA1(t, g, config)
	if code, stderr := run(); code != 0 {
		t.Fatalf("retain: %d %q", code, stderr)
	}
	key := testSigningKey(t, config)
	removalPath := filepath.Join(g.storeRoot, removalsFile)
	removal0 := readFile(t, removalPath)
	trimmed := strings.TrimSuffix(removal0, "\n")
	lastRecord := trimmed[strings.LastIndex(trimmed, "\n")+1:]
	keys := walkRegistry([]byte(readFile(t, g.regPath)), g.publicKey).keys
	call := func() error {
		j, err := beginOperatorJournal(g.storeRoot, g.regPath, operatorJournalVersion, key, keys, func() string { return removalStamp })
		if err != nil {
			return err
		}
		return journaledAppendRemovals(j, g.storeRoot, true, []byte("{}\n"), removalBody("remove-artifact", "operator-3", ""))
	}
	t.Run("a piece that loads as a record is refused", func(t *testing.T) {
		if err := os.WriteFile(removalPath, []byte(removal0+lastRecord), 0o600); err != nil {
			t.Fatal(err)
		}
		journal0 := readFile(t, journalFile(g))
		err := call()
		if err == nil || !strings.Contains(err.Error(), removalPath) || !strings.Contains(err.Error(), "cut the file back to the end of its last complete line") {
			t.Fatalf("the call on a piece that loads: %v", err)
		}
		if readFile(t, removalPath) != removal0+lastRecord || readFile(t, journalFile(g)) != journal0 {
			t.Fatal("a refused call changed the store")
		}
		if _, err := os.Lstat(pendingFile(g)); err == nil {
			t.Fatal("a refused call staged an entry")
		}
	})
	t.Run("a piece that loads as none is covered by the next call", func(t *testing.T) {
		piece := `{"kind":"artifact-rem`
		if err := os.WriteFile(removalPath, []byte(removal0+piece), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, said := journalVerdict(t, g); strings.Join(said, ",") != "journal-from,journal-torn-tail" {
			t.Fatalf("before the call: %v", said)
		}
		if err := call(); err != nil {
			t.Fatal(err)
		}
		if got := readFile(t, removalPath); got != removal0+piece+"\n{}\n" {
			t.Fatalf("the removal file: %q", got)
		}
		entries := journalEntries(t, g)
		body, _ := entries[len(entries)-1]["body"].(map[string]any)
		if journalJSON(body["removalFrom"]) != fmt.Sprint(len(removal0)) || journalJSON(body["removalBytes"]) != fmt.Sprint(len(piece)+4) {
			t.Fatalf("the entry's range: %v", body)
		}
		if _, said := journalVerdict(t, g); strings.Join(said, ",") != "journal-from" {
			t.Fatalf("after the call: %v", said)
		}
	})
}
