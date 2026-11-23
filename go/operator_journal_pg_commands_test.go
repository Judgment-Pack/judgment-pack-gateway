package main

// The operator journal written by the commands of the PostgreSQL kind
// (operator_journal_pg.go; ADR-0056 §5, Amendment A): the entries of
// gateway store retain, gateway store remove-scope, gateway seal-open and
// gateway store rotate, read back from gateway.journal_records and through
// gateway export, and verified as the filesystem kind's are.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pgJournalService is a stopped service of two scope identifiers and of
// none, s-a, s-b and s-none sealed and, where open, s-a-open left open, its
// configuration raised to operatorJournalVersion with a retention member,
// so the commands begin the journal. The working directory is dir.
func pgJournalService(t *testing.T, open bool) (db *pgTestDB, dir, config string, pub ed25519.PublicKey) {
	t.Helper()
	db = newPgTestDB(t)
	db.migrate(t)
	dir = tempDirAt(t, 0o700)
	t.Setenv(envSourceHelper, "1")
	helper := sourceSpec{argv: []string{os.Args[0]}, env: helperEnv}
	scoped := func(scope string) sourceSpec { s := helper; s.scope = scope; return s }
	sources := map[string]sourceSpec{"screening-a": scoped("scope-a"), "screening-b": scoped("scope-b"), "plain": helper}
	config, started, server := scopedServiceStart(t, db, dir, sources)
	for _, body := range []string{
		`{"session":"s-a","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`,
		`{"session":"s-a-open","source":"screening-a","scope":"scope-a","arguments":{"q":"third"}}`,
		`{"session":"s-b","source":"screening-b","scope":"scope-b","arguments":{"q":"acme"}}`,
		`{"session":"s-none","source":"plain","arguments":{"q":"acme"}}`,
	} {
		if !open && strings.Contains(body, "s-a-open") {
			continue
		}
		if code, got := post(t, server, "/acquire", body); code != http.StatusOK {
			t.Fatalf("%s: %d %v", body, code, got)
		}
	}
	for _, session := range []string{"s-a", "s-b", "s-none"} {
		if code, got := post(t, server, "/seal", `{"session":"`+session+`"}`); code != http.StatusOK {
			t.Fatalf("seal %s: %d %v", session, code, got)
		}
	}
	var said bytes.Buffer
	started.stop(&said)
	server.Close()
	pub = started.service.publicKey
	text := readFile(t, config)
	raised := strings.Replace(text, `"engineVersion":"24"`, `"engineVersion":"`+operatorJournalVersion+`"`, 1)
	if raised == text {
		t.Fatal("the configuration's version was not raised")
	}
	raised = strings.TrimSuffix(strings.TrimSpace(raised), "}") + `,"retention":{"window":30,"acknowledgedBy":["` + hex.EncodeToString(retentionAckKey.Public().(ed25519.PublicKey)) + `"]}}`
	if err := os.WriteFile(config, []byte(raised), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	return db, dir, config, pub
}

// pgJournalRetain runs gateway store retain for session, past its window,
// with its acknowledgment; sum is the acknowledgment file's SHA-256.
func pgJournalRetain(t *testing.T, db *pgTestDB, dir, config string, pub ed25519.PublicKey, session string) (code int, stdout, stderr, sum string) {
	t.Helper()
	seals := filepath.Join(t.TempDir(), "seals")
	if _, err := exportEngine(config, seals, nil, ""); err != nil {
		t.Fatalf("export: %v", err)
	}
	s := sealOf(t, filepath.Join(seals, "registry"), pub, session)
	now := sealTime(t, s).Add(31 * 24 * time.Hour)
	acks := writeAcks(t, retentionAckLine(retentionAckKey, session, s.signature, s.finalCount, stampOf(sealTime(t, s).Add(time.Hour))))
	var out, errs bytes.Buffer
	code = cmdStoreRetainAt([]string{"--connection-file", writeConnection(t, db.migrator), "--owner", db.roles.owner, "--runtime", db.roles.runtime,
		"--config", config, "--acknowledgments", acks, "--by", "operator-1", "--timeout", "60"},
		&out, &errs, fixedStamp(removalStamp), func() time.Time { return now })
	return code, out.String(), errs.String(), sha256Hex([]byte(readFile(t, acks)))
}

// pgRowsFile is a table's lines, of no scope, each with its 0x0A, in
// ordinal order: the bytes an export writes of them.
func pgRowsFile(t *testing.T, db *pgTestDB, table string) string {
	t.Helper()
	c := db.runtimeConn(t)
	var lines []string
	pgInScopeOn(t, c, pgNoScope, func() {
		lines = pgColumn(t, c, `SELECT line FROM gateway.`+table+` ORDER BY ordinal`)
	})
	var file strings.Builder
	for _, line := range lines {
		file.WriteString(line + "\n")
	}
	return file.String()
}

// journalBodiesOf is each entry of a journal's bytes, with its body.
func journalBodiesOf(t *testing.T, file string) (entries, bodies []map[string]any) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSuffix(file, "\n"), "\n") {
		if line == "" {
			continue
		}
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("an entry is not JSON: %v %q", err, line)
		}
		body, _ := e["body"].(map[string]any)
		entries, bodies = append(entries, e), append(bodies, body)
	}
	return entries, bodies
}

// journalSaid is a verdict's journal findings and observations, each as
// status or observation, with the ordinal where there is one.
func journalSaid(rep *report) []string {
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
	return said
}

// gateway store retain inserts its entry with its records, in one
// transaction: the acknowledgments' digest and key ids, the sessions and the
// records' bytes read back from the table and through an export, which
// verifies with the journal required. A failure injected after the entry
// and before COMMIT leaves neither the records nor the entry.
func TestAPostgresStoreRetainWritesItsJournalEntryWithItsRecords(t *testing.T) {
	db, dir, config, pub := pgJournalService(t, false)
	registry := pgRegistryOf(t, db)
	code, stdout, stderr, sum := pgJournalRetain(t, db, dir, config, pub, "s-a")
	if code != 0 || !strings.Contains(stderr, "removed 1 session(s)") {
		t.Fatalf("retain: %d %q %q", code, stdout, stderr)
	}
	journal := pgRowsFile(t, db, "journal_records")
	entries, bodies := journalBodiesOf(t, journal)
	if len(entries) != 1 || entries[0]["ordinal"] != float64(0) || entries[0]["journal"] != operatorJournal {
		t.Fatalf("the journal: %q", journal)
	}
	body := bodies[0]
	if body["kind"] != "retain" || body["by"] != "operator-1" || body["acknowledgments"] != sum ||
		journalJSON(body["acknowledgedBy"]) != `["`+edKey(retentionAckKey.Public().(ed25519.PublicKey)).keyID()+`"]` ||
		body["sessions"] != float64(1) || body["registryFrom"] != float64(len(registry)) || body["removalFrom"] != float64(0) ||
		body["removalBytes"] != float64(len(stdout)) || body["removalDigest"] != sha256Hex([]byte(stdout)) {
		t.Fatalf("the retain entry: %v", body)
	}
	if got := pgRowsFile(t, db, "removal_records"); got != stdout {
		t.Fatalf("the records: %q, printed %q", got, stdout)
	}
	rep, _ := pgExportVerdict(t, dir, config, "export-after", "")
	rep.requireJournals([]string{operatorJournal})
	if said := journalSaid(rep); !rep.OK || strings.Join(said, ",") != "journal-from" {
		t.Fatalf("the export's verdict: %v %v", said, rep.Findings)
	}
	if got := readFile(t, filepath.Join(dir, "export-after", "store", journalsDir, operatorJournal+".jsonl")); got != journal {
		t.Fatalf("the export's journal is %q, not the rows %q", got, journal)
	}

	records := pgRowsFile(t, db, "removal_records")
	journalCutOff = func() error { return errors.New("cut off before the commit") }
	t.Cleanup(func() { journalCutOff = nil })
	code, stdout, stderr, _ = pgJournalRetain(t, db, dir, config, pub, "s-b")
	journalCutOff = nil
	if code != 1 || stdout != "" || !strings.Contains(stderr, "cut off before the commit") {
		t.Fatalf("the cut-off retain: %d %q %q", code, stdout, stderr)
	}
	if pgRowsFile(t, db, "journal_records") != journal || pgRowsFile(t, db, "removal_records") != records {
		t.Fatal("a removal rolled back left its entry or its records")
	}
}

// gateway store remove-scope inserts its entry, whose range is its records'
// bytes, in the records' transaction; a second removal's entry follows the
// first, and a failure before COMMIT leaves neither.
func TestAPostgresStoreRemoveScopeWritesItsJournalEntryWithItsRecords(t *testing.T) {
	db, dir, config, _ := pgJournalService(t, true)
	connection := writeConnection(t, db.migrator)
	remove := func(scope string) (int, string, string) {
		return runStoreRemoveScope("--connection-file", connection, "--owner", db.roles.owner, "--runtime", db.roles.runtime,
			"--config", config, "--scope", scope, "--by", "operator-1", "--timeout", "60")
	}
	journalCutOff = func() error { return errors.New("cut off before the commit") }
	t.Cleanup(func() { journalCutOff = nil })
	if code, stdout, stderr := remove("scope-b"); code != 1 || !strings.Contains(stderr, "cut off before the commit") {
		t.Fatalf("the cut-off remove-scope: %d %q %q", code, stdout, stderr)
	}
	journalCutOff = nil
	if pgRowsFile(t, db, "journal_records") != "" || pgRowsFile(t, db, "removal_records") != "" {
		t.Fatal("a removal rolled back left its entry or its records")
	}
	registry := pgRegistryOf(t, db)
	if code, stdout, stderr := remove("scope-b"); code != 0 {
		t.Fatalf("remove-scope: %d %q %q", code, stdout, stderr)
	}
	first := pgRowsFile(t, db, "removal_records")
	if code, stdout, stderr := remove("scope-a"); code != 0 {
		t.Fatalf("the second remove-scope: %d %q %q", code, stdout, stderr)
	}
	records := pgRowsFile(t, db, "removal_records")
	journal := pgRowsFile(t, db, "journal_records")
	entries, bodies := journalBodiesOf(t, journal)
	if len(entries) != 2 || entries[1]["previous"] != sha256Hex([]byte(strings.SplitN(journal, "\n", 2)[0])) {
		t.Fatalf("the journal: %q", journal)
	}
	for i, want := range []struct {
		scope    string
		from, to int
	}{{"scope-b", 0, len(first)}, {"scope-a", len(first), len(records)}} {
		b := bodies[i]
		if b["kind"] != "remove-scope" || b["scope"] != want.scope || b["by"] != "operator-1" || b["registryFrom"] != float64(len(registry)) ||
			b["removalFrom"] != float64(want.from) || b["removalBytes"] != float64(want.to-want.from) || b["removalDigest"] != sha256Hex([]byte(records[want.from:want.to])) {
			t.Fatalf("entry %d: %v", i, b)
		}
	}
	rep, _ := pgExportVerdict(t, dir, config, "export-after", "")
	rep.requireJournals([]string{operatorJournal})
	if said := journalSaid(rep); !rep.OK || strings.Join(said, ",") != "journal-from" {
		t.Fatalf("the export's verdict: %v %v", said, rep.Findings)
	}
}

// gateway seal-open, as the run-time login under the start lease, inserts
// its entry after its last seal, naming the seals it appended.
func TestAPostgresSealOpenWritesItsJournalEntryAfterItsSeals(t *testing.T) {
	db, dir, config, _ := pgJournalService(t, true)
	before := pgRegistryOf(t, db)
	var stdout, stderr bytes.Buffer
	if code := cmdSealOpenAt([]string{"--config", config, "--all"}, &stdout, &stderr, fixedStamp(removalStamp)); code != 0 {
		t.Fatalf("seal-open: %d %q", code, stderr.String())
	}
	registry := pgRegistryOf(t, db)
	if !strings.HasPrefix(registry, before) || len(registry) == len(before) {
		t.Fatal("seal-open sealed nothing")
	}
	journal := pgRowsFile(t, db, "journal_records")
	entries, bodies := journalBodiesOf(t, journal)
	if len(entries) != 1 || bodies[0]["kind"] != "seal-open" || bodies[0]["seals"] != float64(1) || bodies[0]["delivered"] != false ||
		bodies[0]["registryFrom"] != float64(len(before)) || bodies[0]["sealDigest"] != sha256Hex([]byte(registry[len(before):])) {
		t.Fatalf("the seal-open entry: %q", journal)
	}
	// a second call seals nothing, and names nothing
	stdout.Reset()
	stderr.Reset()
	if code := cmdSealOpenAt([]string{"--config", config, "--all"}, &stdout, &stderr, fixedStamp(removalStamp)); code != 0 {
		t.Fatalf("the second seal-open: %d %q", code, stderr.String())
	}
	if pgRowsFile(t, db, "journal_records") != journal {
		t.Fatal("a seal-open that sealed nothing wrote an entry")
	}
	rep, _ := pgExportVerdict(t, dir, config, "export-after", "")
	rep.requireJournals([]string{operatorJournal})
	if said := journalSaid(rep); !rep.OK || strings.Join(said, ",") != "journal-from" {
		t.Fatalf("the export's verdict: %v %v", said, rep.Findings)
	}
}

// The export of a database of this kind carries the journal as
// store/journals/operator.jsonl, the rows' bytes exactly, and gateway verify
// reads it as it reads the filesystem kind's file: the journal holds and is
// observed, an altered entry is journal-entry-forged, the journal removed
// is journal-missing under --require-journal, and an export by scope
// carries none.
func TestAPostgresExportCarriesTheJournalAndVerifyReadsItAsTheFilesystemKinds(t *testing.T) {
	db, dir, config, pub := pgJournalService(t, false)
	if code, stdout, stderr, _ := pgJournalRetain(t, db, dir, config, pub, "s-a"); code != 0 {
		t.Fatalf("retain: %d %q %q", code, stdout, stderr)
	}
	journal := pgRowsFile(t, db, "journal_records")
	out := filepath.Join(dir, "export")
	if _, err := exportEngine(config, out, nil, ""); err != nil {
		t.Fatalf("export: %v", err)
	}
	requireExportChecks(t, out)
	path := filepath.Join(out, "store", journalsDir, operatorJournal+".jsonl")
	if got := readFile(t, path); got != journal || journal == "" {
		t.Fatalf("the export's journal %q, the rows %q", got, journal)
	}
	verdict := func() (*report, []string) {
		t.Helper()
		rep, err := verifyWithRegistry(filepath.Join(out, "store"), filepath.Join(out, "registry"), "gateway:test", pub)
		if err != nil {
			t.Fatal(err)
		}
		rep.requireJournals([]string{operatorJournal})
		return rep, journalSaid(rep)
	}
	if rep, said := verdict(); !rep.OK || strings.Join(said, ",") != "journal-from" {
		t.Fatalf("the export's verdict: %v %v", said, rep.Findings)
	}
	altered := strings.Replace(journal, `"by":"operator-1"`, `"by":"operator-2"`, 1)
	if altered == journal {
		t.Fatal("the entry was not altered")
	}
	if err := os.WriteFile(path, []byte(altered), 0o600); err != nil {
		t.Fatal(err)
	}
	if rep, said := verdict(); rep.OK || strings.Join(said, ",") != "journal-entry-forged 0" {
		t.Fatalf("an altered entry: %v", said)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if rep, said := verdict(); rep.OK || strings.Join(said, ",") != "journal-missing" {
		t.Fatalf("the journal removed: %v", said)
	}
	scoped := filepath.Join(dir, "export-scope-a")
	if _, err := exportEngine(config, scoped, nil, "scope-a"); err != nil {
		t.Fatalf("export by scope: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(scoped, "store", journalsDir)); !os.IsNotExist(err) {
		t.Fatalf("an export by scope carries a journal: %v", err)
	}
}
