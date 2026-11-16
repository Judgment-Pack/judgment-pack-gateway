package main

// The seal made after an interruption on the PostgreSQL kind (gateway #466;
// seal_open_pg.go): an instance with sessions open in two scope identifiers
// and in none stops; the next start with sealOpenAtStart, or gateway
// seal-open --config with no instance serving, seals each one, its count the
// receipts the store holds and its head the last one's signature; the
// command is refused while an instance serves; and the export verifies.

import (
	"bytes"
	"cmp"
	"context"
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
	"time"
)

// sealOpenPgConfig writes, into dir, a version-24 configuration of the
// PostgreSQL kind on db, named name, with sealOpenAtStart where atStart is
// set -- or, where wait is not "", a version-25 one whose start waits that
// many seconds for the start lease; it answers the file's path and the
// configuration read.
func sealOpenPgConfig(t *testing.T, db *pgTestDB, dir, name string, atStart bool, wait string) (string, engineConfig) {
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
	version, waits := "24", ""
	if wait != "" {
		version, waits = "25", `,"startWaitSeconds":`+wait
	}
	text := `{"engineVersion":"` + version + `","authority":"gateway:test","seed":"` + abs(t, seedPath) + `","storage":{"kind":"postgresql","connection":{"file":"` + abs(t, connection) + `"},"connections":2` + waits + `},` +
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
// signature of its last receipt, how many it holds and its scope, as the
// store holds them.
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
		heads[session] = sealOpenTarget{sessionID: session, count: int64(len(entries)), head: signature, scope: scope}
	}
	return heads
}

// sealOpenPgSeals reads the seals of lines, each after prefix, and holds
// each to §3c's form, sealedVia via, and to heads: a session of a scope
// identifier's seal names it by its digest in the session, of ten members
// (ADR-0036, decision 3), and never by the identifier, and a
// session of none's is §3c's eight; it answers the sessions sealed, in order.
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
		members, scope := 8, any(nil)
		if want.scope != "" {
			members, scope = 10, sealScopeDigest(want.sessionID, want.scope)
			if strings.Contains(text, want.scope) {
				t.Fatalf("a seal %s names the scope identifier", text)
			}
			if record["sealVersion"] != sealVersionScoped {
				t.Fatalf("a seal %s of a session of a scope identifier, of no version 2", text)
			}
		}
		if !known || record["kind"] != sealKindInterruption || record["sealedVia"] != via || int64(count) != want.count || record["headSignature"] != want.head || record["scopeDigest"] != scope || len(record) != members {
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
	config, cfg := sealOpenPgConfig(t, db, dir, "engine.json", false, "")
	_, atStart := sealOpenPgConfig(t, db, dir, "engine-seal-at-start.json", true, "")
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
	config, cfg := sealOpenPgConfig(t, db, dir, "engine.json", false, "")
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

// sealOpenPgPayload is the payload session's first receipt names, as the
// scope of its view holds the session.
func sealOpenPgPayload(t *testing.T, view *pgKind, session string) string {
	t.Helper()
	data, err := view.receipts().getEntry(session, "0")
	if err != nil {
		t.Fatal(err)
	}
	hexSum, ok := namedPayload(data)
	if !ok {
		t.Fatalf("session %s's receipt names no payload: %s", session, data)
	}
	return hexSum
}

// Each session is judged by the payloads its own scope holds, never by what
// another scope holds under the same name, and a session not whole, or a
// series no session id names, is named and the rest sealed, as on the
// filesystem kind (gateway #466). Scope-a holds, under the name of each
// payload the sessions of scope-b and of no scope name, the bytes that name
// is of; scope-b's own copy is made to differ from its name, and no scope's
// copy is removed; a second session of no scope is torn; and scope-b holds a
// series named "bad/name". gateway seal-open --config --all seals the
// sessions of scope-a, and names the four others, exit 1.
func TestThePostgresSealOpenJudgesEachSessionByItsOwnScopesPayloads(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, cfg := sealOpenPgConfig(t, db, dir, "engine.json", false, "")
	stop := sealOpenPgLeaveOpen(t, cfg, sealOpenPgSources(t), []string{
		`{"session":"p-a","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`,
		`{"session":"p-a-other","source":"screening-a","scope":"scope-a","arguments":{"q":"other"}}`,
		`{"session":"p-b-damaged","source":"screening-b","scope":"scope-b","arguments":{"q":"acme"}}`,
		`{"session":"m-none","source":"plain","arguments":{"q":"acme"}}`,
		`{"session":"t-none","source":"plain","arguments":{"q":"acme"}}`,
	})
	stop()
	kind := db.open(t, nil)
	scopeA, err := kind.inScope("scope-a")
	if err != nil {
		t.Fatal(err)
	}
	scopeB, err := kind.inScope("scope-b")
	if err != nil {
		t.Fatal(err)
	}
	damaged, missing := sealOpenPgPayload(t, scopeB, "p-b-damaged"), sealOpenPgPayload(t, kind, "m-none")
	copies := []string{"SELECT pg_catalog.set_config('gateway.scope', 'scope:scope-a', true)"}
	for _, held := range []struct {
		view *pgKind
		name string
	}{{scopeB, damaged}, {kind, missing}} {
		data, err := held.view.artifacts().getBlob("sha256:" + held.name)
		if err != nil || digestOfBytes(data) != held.name {
			t.Fatalf("payload %s of scope %s: %v", held.name, held.view.row, err)
		}
		copies = append(copies, "INSERT INTO gateway.blobs (scope, name, data) VALUES ('scope:scope-a', 'sha256:"+held.name+"', pg_catalog.decode('"+hex.EncodeToString(data)+"', 'hex')) ON CONFLICT DO NOTHING")
	}
	db.asOwner(t, copies...)
	for _, name := range []string{damaged, missing} {
		if data, err := scopeA.artifacts().getBlob("sha256:" + name); err != nil || digestOfBytes(data) != name {
			t.Fatalf("scope-a does not hold payload %s: %v", name, err)
		}
	}
	db.asOwner(t, "SELECT pg_catalog.set_config('gateway.scope', 'scope:scope-b', true)",
		"UPDATE gateway.blobs SET data = pg_catalog.convert_to('not the payload', 'UTF8') WHERE scope = 'scope:scope-b' AND name = 'sha256:"+damaged+"'",
		"INSERT INTO gateway.series (scope, name) VALUES ('scope:scope-b', 'bad/name')")
	db.asOwner(t, "SELECT pg_catalog.set_config('gateway.scope', 'none', true)",
		"DELETE FROM gateway.blobs WHERE scope = 'none' AND name = 'sha256:"+missing+"'",
		"UPDATE gateway.entries SET data = pg_catalog.convert_to('{not json', 'UTF8') WHERE scope = 'none' AND series = 't-none' AND name = '0'")
	heads := sealOpenPgHeads(t, db, map[string]string{"p-a": "scope-a", "p-a-other": "scope-a"})

	var stdout, stderr bytes.Buffer
	code := cmdSealOpenAt([]string{"--config", config, "--all"}, &stdout, &stderr, nowStamp)
	got := sealOpenPgSeals(t, strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n"), "", sealedViaCommand, heads)
	want := strings.Join([]string{
		"seal-open: session m-none is not whole, so it is not sealed: receipt 0 artifact-missing; gateway verify reports what it finds of it, and nothing is changed or deleted",
		"seal-open: session t-none is not whole, so it is not sealed: file 0.json malformed; gateway verify reports what it finds of it, and nothing is changed or deleted",
		`seal-open: the store's series "bad/name" is not named as a session is (SPEC.md §3a); it is not sealed`,
		"seal-open: session p-b-damaged is not whole, so it is not sealed: receipt 0 artifact-mismatch; gateway verify reports what it finds of it, and nothing is changed or deleted",
	}, "\n") + "\n"
	if code != 1 || strings.Join(got, ",") != "p-a,p-a-other" || stderr.String() != want {
		t.Fatalf("seal-open --all: exit %d, sealed %v\nstderr %q\nwant   %q", code, got, stderr.String(), want)
	}
}

// An instance that ends without releasing the start lease -- killed -- holds
// it until it expires: gateway seal-open --config is refused,
// start-lease-held, and appends nothing; a start with sealOpenAtStart and
// storage.startWaitSeconds waits for the lease to expire, takes it, and
// seals what the killed instance left open, sealedVia start, before it
// serves.
func TestThePostgresStartWaitsOutAKilledInstancesLeaseAndSealsWhatItLeftOpen(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, cfg := sealOpenPgConfig(t, db, dir, "engine.json", false, "")
	_, waits := sealOpenPgConfig(t, db, dir, "engine-wait.json", true, "30")
	sources := sealOpenPgSources(t)
	var said bytes.Buffer
	first, err := startEngineOnKind(cfg, testSeed, sources, nil, &said)
	if err != nil {
		t.Fatalf("the first start: %v", err)
	}
	server := httptest.NewServer(first.service.handler())
	for _, body := range []string{
		`{"session":"k-a","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`,
		`{"session":"k-none","source":"plain","arguments":{"q":"acme"}}`,
	} {
		if code, got := post(t, server, "/acquire", body); code != http.StatusOK {
			t.Fatalf("%s: %d %v", body, code, got)
		}
	}
	// killed: the renewal ends and the connections close, and the lease is
	// never released
	server.Close()
	first.endRenewal()
	<-first.renewed
	first.lease.closeOwn()
	first.kind.close()
	if !pgLeaseLive(t, db) {
		t.Fatal("the killed instance's lease is not live")
	}
	before, err := db.open(t, nil).registry().readLog(0)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := cmdSealOpenAt([]string{"--config", config, "--all"}, &stdout, &stderr, nowStamp); code != 1 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), "seal-open: start-lease-held: ") {
		t.Fatalf("seal-open while the killed instance's lease is live: %d %q %q", code, stdout.String(), stderr.String())
	}
	if after, err := db.open(t, nil).registry().readLog(0); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("seal-open refused appended to the registry: %v", err)
	}
	heads := sealOpenPgHeads(t, db, map[string]string{"k-a": "scope-a", "k-none": ""})
	// the lease's expiry brought near, as the period's end would bring it
	db.asOwner(t, "UPDATE gateway.start_lease SET expires = pg_catalog.clock_timestamp() + interval '3 seconds'")

	var waited bytes.Buffer
	second, err := startOnKind(waits, testSeed, sources, nil, kindRun{period: pgStartLeasePeriod, every: 500 * time.Millisecond, stopped: context.Background(), said: &waited})
	if err != nil {
		t.Fatalf("the start that waits: %v\n%s", err, waited.String())
	}
	defer second.stop(&waited)
	if !strings.Contains(waited.String(), "start: the start lease was released or expired, and this instance took it after waiting") {
		t.Fatalf("the start did not wait for the lease: %s", waited.String())
	}
	got := sealOpenPgSeals(t, strings.Split(waited.String(), "\n"), "start: sealed after an interruption: ", sealedViaStart, heads)
	if strings.Join(got, ",") != "k-a,k-none" {
		t.Fatalf("the start sealed %v:\n%s", got, waited.String())
	}
}

// A lease the release could not reach is said to be left to expire under
// the name of what held it: "seal-open" for the command, "stop" for a
// start, whose line it was before the command took the lease.
func TestALeaseLeftToExpireIsSaidUnderTheNameOfWhatHeldIt(t *testing.T) {
	for _, as := range []string{"seal-open", ""} {
		// a database that answers nothing: port 1 of the loopback host
		kind := &pgKind{pool: newPgPool(pgDSN{host: "127.0.0.1", port: "1", connectTimeout: time.Second}, 1)}
		held := &kindStart{kind: kind, lease: &pgStartLease{kind: kind, holder: "a-holder", bound: time.Second}, as: as}
		var said bytes.Buffer
		held.stop(&said)
		want := cmp.Or(as, "stop") + ": the start lease is left to expire within " + pgStartLeasePeriod.String() + ": "
		if !strings.HasPrefix(said.String(), want) {
			t.Fatalf("as %q: %q, where %q begins", as, said.String(), want)
		}
	}
}
