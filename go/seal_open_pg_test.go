package main

// The seal made after an interruption on the PostgreSQL kind (gateway #466;
// seal_open_pg.go): an instance with sessions open in two scope identifiers
// and in none stops; the next start with sealOpenAtStart, or gateway
// seal-open --config with no instance serving, seals each one, its count the
// receipts the store holds and its head the last one's signature; the
// command is refused while an instance serves; and the export verifies.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// sealOpenPgConfig writes, into dir, a version-24 configuration of the
// PostgreSQL kind on db, named name, with sealOpenAtStart where atStart is
// set; it answers the file's path and the configuration read.
func sealOpenPgConfig(t *testing.T, db *pgTestDB, dir, name string, atStart bool) (string, engineConfig) {
	t.Helper()
	connection := filepath.Join(dir, "connection")
	if err := os.WriteFile(connection, []byte(pgTestURL(db.runtime)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seedPath := filepath.Join(dir, "gateway.seed")
	if err := os.WriteFile(seedPath, []byte(hex.EncodeToString(testSeed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "decisions"), 0o700); err != nil {
		t.Fatal(err)
	}
	extra := ``
	if atStart {
		extra = `,"sealOpenAtStart":true`
	}
	text := `{"engineVersion":"24","authority":"gateway:test","seed":"` + abs(t, seedPath) + `","storage":{"kind":"postgresql","connection":{"file":"` + abs(t, connection) + `"},"connections":2},` +
		`"decisionRecords":"` + abs(t, dir, "decisions") + `","listen":"127.0.0.1:8787","catalog":"` + abs(t, dir, "catalog") + `"` + extra + `,"platforms":{}}`
	config := filepath.Join(dir, name)
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseEngineConfig([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return config, cfg
}

// sealOpenPgSources are sources fixed to scope-a, to scope-b, and to none.
func sealOpenPgSources(t *testing.T) map[string]sourceSpec {
	t.Setenv(envSourceHelper, "1")
	helper := sourceSpec{argv: []string{os.Args[0]}, env: helperEnv}
	scoped := func(scope string) sourceSpec { s := helper; s.scope = scope; return s }
	return map[string]sourceSpec{"screening-a": scoped("scope-a"), "screening-b": scoped("scope-b"), "plain": helper}
}

// sealOpenPgLeaveOpen starts an instance on cfg and has it mint the
// receipts of calls, sealing the sessions of sealed; it answers the instance
// serving and its stop, which a test calls, or the cleanup does.
func sealOpenPgLeaveOpen(t *testing.T, cfg engineConfig, sources map[string]sourceSpec, calls []string, sealed ...string) func() {
	t.Helper()
	var said bytes.Buffer
	first, err := startEngineOnKind(cfg, testSeed, sources, nil, &said)
	if err != nil {
		t.Fatalf("the first start: %v", err)
	}
	server := httptest.NewServer(first.service.handler())
	stop := sync.OnceFunc(func() {
		server.Close()
		first.stop(&said)
	})
	t.Cleanup(stop)
	for _, body := range calls {
		if code, got := post(t, server, "/acquire", body); code != http.StatusOK {
			t.Fatalf("%s: %d %v", body, code, got)
		}
	}
	for _, session := range sealed {
		if code, got := post(t, server, "/seal", `{"session":"`+session+`"}`); code != http.StatusOK {
			t.Fatalf("seal %s: %d %v", session, code, got)
		}
	}
	return stop
}

// sealOpenPgHeads is, for each session of each scope ("" for none), the
// signature of its last receipt and how many it holds, as the store holds
// them.
func sealOpenPgHeads(t *testing.T, db *pgTestDB, sessions map[string]string) map[string]sealOpenTarget {
	t.Helper()
	kind := db.open(t, nil)
	heads := map[string]sealOpenTarget{}
	for session, scope := range sessions {
		view := kind
		if scope != "" {
			var err error
			if view, err = kind.inScope(scope); err != nil {
				t.Fatal(err)
			}
		}
		entries, err := view.receipts().listEntries(session)
		if err != nil || len(entries) == 0 {
			t.Fatalf("session %s of scope %q: %v %v", session, scope, entries, err)
		}
		data, err := view.receipts().getEntry(session, entries[len(entries)-1])
		if err != nil {
			t.Fatal(err)
		}
		signature, ok := topLevelSignature(data)
		if !ok {
			t.Fatalf("session %s's last receipt names no signature", session)
		}
		heads[session] = sealOpenTarget{sessionID: session, count: int64(len(entries)), head: signature}
	}
	return heads
}

// sealOpenPgSeals reads the seals of lines, each after prefix, and holds
// each to §3c's form, sealedVia via, and to heads; it answers the sessions
// sealed, in order.
func sealOpenPgSeals(t *testing.T, lines []string, prefix, via string, heads map[string]sealOpenTarget) []string {
	t.Helper()
	var sessions []string
	for _, line := range lines {
		text, ok := strings.CutPrefix(line, prefix)
		if !ok {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(text), &record); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		session, _ := record["sessionId"].(string)
		want, known := heads[session]
		count, _ := record["finalCount"].(float64)
		if !known || record["kind"] != sealKindInterruption || record["sealedVia"] != via || int64(count) != want.count || record["headSignature"] != want.head || len(record) != 8 {
			t.Fatalf("a seal %s, where the store holds %+v", text, want)
		}
		sessions = append(sessions, session)
	}
	sort.Strings(sessions)
	return sessions
}

// sealOpenPgVerdict exports the store config names and answers the
// verdict on the export.
func sealOpenPgVerdict(t *testing.T, dir, config, name string) []byte {
	t.Helper()
	out := filepath.Join(dir, name)
	if _, err := exportEngine(config, out, nil); err != nil {
		t.Fatalf("export: %v", err)
	}
	requireExportChecks(t, out)
	return restoredVerdict(t, out, "gateway:test", ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))
}

// An instance stops with sessions open in scope-a, in scope-b and in no
// scope, and one sealed; the next start, with sealOpenAtStart, seals each
// open one after the interruption, sealedVia start, its count the receipts
// the store holds and its head the last one's signature, before it serves:
// a call into one is refused as sealed. The export verifies, each session
// observed sealed after an interruption. A start after that seals nothing.
func TestThePostgresStartSealsTheSessionsAStoppedInstanceLeftOpenInEveryScope(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, cfg := sealOpenPgConfig(t, db, dir, "engine.json", false)
	_, atStart := sealOpenPgConfig(t, db, dir, "engine-seal-at-start.json", true)
	sources := sealOpenPgSources(t)
	stop := sealOpenPgLeaveOpen(t, cfg, sources, []string{
		`{"session":"s-a","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`,
		`{"session":"s-a","source":"screening-a","scope":"scope-a","arguments":{"q":"other"}}`,
		`{"session":"s-b","source":"screening-b","scope":"scope-b","arguments":{"q":"acme"}}`,
		`{"session":"s-none","source":"plain","arguments":{"q":"acme"}}`,
		`{"session":"s-closed","source":"plain","arguments":{"q":"acme"}}`,
	}, "s-closed")
	stop()
	heads := sealOpenPgHeads(t, db, map[string]string{"s-a": "scope-a", "s-b": "scope-b", "s-none": ""})
	if heads["s-a"].count != 2 {
		t.Fatalf("s-a holds %d receipts", heads["s-a"].count)
	}

	var said bytes.Buffer
	second, err := startEngineOnKind(atStart, testSeed, sources, nil, &said)
	if err != nil {
		t.Fatalf("the start that seals: %v\n%s", err, said.String())
	}
	stopSecond := sync.OnceFunc(func() { second.stop(&said) })
	t.Cleanup(stopSecond)
	got := sealOpenPgSeals(t, strings.Split(said.String(), "\n"), "start: sealed after an interruption: ", sealedViaStart, heads)
	if strings.Join(got, ",") != "s-a,s-b,s-none" {
		t.Fatalf("the start sealed %v:\n%s", got, said.String())
	}
	server := httptest.NewServer(second.service.handler())
	t.Cleanup(server.Close)
	if code, body := post(t, server, "/acquire", `{"session":"s-a","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`); code != http.StatusBadRequest || body["error"] != "session is sealed in the registry: s-a" {
		t.Fatalf("an acquisition into s-a, sealed at the start: %d %v", code, body)
	}
	server.Close()
	stopSecond()

	t.Chdir(dir)
	verdict := sealOpenPgVerdict(t, dir, config, "export")
	if !bytes.Contains(verdict, []byte(`"ok":true`)) || bytes.Count(verdict, []byte(`"observation":"sealed-after-interruption"`)) != 3 {
		t.Fatalf("the export's verdict: %s", verdict)
	}

	var again bytes.Buffer
	third, err := startEngineOnKind(atStart, testSeed, sources, nil, &again)
	if err != nil {
		t.Fatalf("a start after the seals: %v", err)
	}
	third.stop(&again)
	if strings.Contains(again.String(), "sealed after an interruption") {
		t.Fatalf("a second start sealed again: %s", again.String())
	}
}

// gateway seal-open --config on the PostgreSQL kind is refused,
// start-lease-held, while an instance serves, and appends nothing; once it
// stopped, the command seals each session it left open, of a scope or of
// none, sealedVia command, and releases the lease; a second run seals
// nothing; a session named that is sealed is refused as sealed. The export
// verifies.
func TestThePostgresSealOpenCommandSealsOnlyWhileNoInstanceServes(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, cfg := sealOpenPgConfig(t, db, dir, "engine.json", false)
	sources := sealOpenPgSources(t)
	stop := sealOpenPgLeaveOpen(t, cfg, sources, []string{
		`{"session":"c-a","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`,
		`{"session":"c-b","source":"screening-b","scope":"scope-b","arguments":{"q":"acme"}}`,
		`{"session":"c-b","source":"screening-b","scope":"scope-b","arguments":{"q":"other"}}`,
		`{"session":"c-none","source":"plain","arguments":{"q":"acme"}}`,
	})
	registry := func() string {
		data, err := db.open(t, nil).registry().readLog(0)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	before := registry()
	var stdout, stderr bytes.Buffer
	if code := cmdSealOpenAt([]string{"--config", config, "--all"}, &stdout, &stderr, nowStamp); code != 1 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), "seal-open: start-lease-held: ") || !strings.HasSuffix(stderr.String(), "; stop the gateway, then seal\n") {
		t.Fatalf("seal-open while an instance serves: %d %q %q", code, stdout.String(), stderr.String())
	}
	if registry() != before {
		t.Fatal("seal-open refused while an instance serves appended to the registry")
	}
	stop()
	heads := sealOpenPgHeads(t, db, map[string]string{"c-a": "scope-a", "c-b": "scope-b", "c-none": ""})

	stdout.Reset()
	stderr.Reset()
	if code := cmdSealOpenAt([]string{"--config", config, "--all"}, &stdout, &stderr, nowStamp); code != 0 || stderr.Len() != 0 {
		t.Fatalf("seal-open with no instance serving: %d %q %q", code, stdout.String(), stderr.String())
	}
	got := sealOpenPgSeals(t, strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n"), "", sealedViaCommand, heads)
	if strings.Join(got, ",") != "c-a,c-b,c-none" {
		t.Fatalf("the command sealed %v: %s", got, stdout.String())
	}
	if pgLeaseLive(t, db) {
		t.Fatal("the command left its start lease live")
	}
	sealedOnce := registry()

	stdout.Reset()
	stderr.Reset()
	if code := cmdSealOpenAt([]string{"--config", config, "--all"}, &stdout, &stderr, nowStamp); code != 0 || stdout.Len() != 0 ||
		stderr.String() != "seal-open: no session in the store is left open; nothing was sealed\n" {
		t.Fatalf("a second run: %d %q %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := cmdSealOpenAt([]string{"--config", config, "--session", "c-b"}, &stdout, &stderr, nowStamp); code != 1 || stdout.Len() != 0 ||
		stderr.String() != "seal-open: session c-b is sealed in the registry; it is not sealed again\n" {
		t.Fatalf("a sealed session named: %d %q %q", code, stdout.String(), stderr.String())
	}
	if registry() != sealedOnce {
		t.Fatal("a run that sealed nothing appended to the registry")
	}

	t.Chdir(dir)
	verdict := sealOpenPgVerdict(t, dir, config, "export")
	if !bytes.Contains(verdict, []byte(`"ok":true`)) || bytes.Count(verdict, []byte(`"observation":"sealed-after-interruption"`)) != 3 {
		t.Fatalf("the export's verdict: %s", verdict)
	}
}
