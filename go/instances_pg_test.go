package main

// Several instances on one PostgreSQL database (storage.instances
// "several"; docs/adr/0035-several-instances-on-one-postgresql-database.md,
// option C): each session held by the instance that admitted its first call.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// instancesPgConfig is sealOpenPgConfig's engine configuration at version 26
// with storage.instances "several".
func instancesPgConfig(t *testing.T, db *pgTestDB, dir, name string, atStart bool) (string, engineConfig) {
	t.Helper()
	path, _ := sealOpenPgConfig(t, db, dir, name, atStart, "")
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text = bytes.Replace(text, []byte(`{"engineVersion":"24"`), []byte(`{"engineVersion":"26"`), 1)
	text = bytes.Replace(text, []byte(`"connections":2`), []byte(`"connections":2,"instances":"several"`), 1)
	if err := os.WriteFile(path, text, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseEngineConfig(text)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.storage.several {
		t.Fatal("the configuration is not of the several-instances mode")
	}
	return path, cfg
}

// asOwnerIn runs one statement as the owner role, in a transaction whose
// gateway.scope is row ("none" for the rows of no scope), and answers its
// rows.
func asOwnerIn(t *testing.T, db *pgTestDB, row, query string, args ...any) pgRows {
	t.Helper()
	c, err := pgConnect(db.migrator, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	if err := c.script("BEGIN; SET LOCAL ROLE " + db.roles.owner); err != nil {
		t.Fatal(err)
	}
	if _, err := c.exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, row); err != nil {
		t.Fatal(err)
	}
	rows, err := c.exec(query, args...)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	if err := c.script("COMMIT"); err != nil {
		t.Fatal(err)
	}
	return rows
}

// severalKind is a kind on db in the several-instances mode under seed,
// holding a row of the lease for period, not renewed.
func severalKind(t *testing.T, db *pgTestDB, seed []byte, period time.Duration) (*pgKind, *pgStartLease) {
	t.Helper()
	kind := db.open(t, nil)
	kind.instance = instanceFor(&storageSpec{several: true}, seed, "gateway:test")
	return kind, pgTakeForTest(t, kind, period, pgStartLeaseRenewal)
}

// killInstance ends a started instance as a crash would: the renewal ends,
// the connections close, and its row is never released.
func killInstance(s *kindStart, server *httptest.Server) {
	server.Close()
	s.endRenewal()
	<-s.renewed
	s.lease.closeOwn()
	s.kind.close()
}

// Two instances serve one database at once, each its own sessions; a call
// into, or a seal of, a session the other holds is answered 409 by a fixed
// sentence that names no instance, before the source runs; a session's
// series is made, with its holder, at the admission of its first call,
// before the source runs.
func TestTwoPostgresInstancesServeTheirOwnSessionsAndRefuseTheOthers(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	_, cfg := instancesPgConfig(t, db, dir, "engine.json", false)
	sources := sealOpenPgSources(t)
	var said bytes.Buffer
	a, err := startEngineOnKind(cfg, testSeed, sources, nil, &said)
	if err != nil {
		t.Fatalf("instance a: %v", err)
	}
	defer a.stop(&said)
	b, err := startEngineOnKind(cfg, testSeed, sources, nil, &said)
	if err != nil {
		t.Fatalf("instance b beside a: %v\n%s", err, said.String())
	}
	defer b.stop(&said)
	serverA := httptest.NewServer(a.service.handler())
	defer serverA.Close()
	serverB := httptest.NewServer(b.service.handler())
	defer serverB.Close()

	var wg sync.WaitGroup
	failed := make(chan string, 16)
	for _, call := range []struct {
		server *httptest.Server
		body   string
	}{
		{serverA, `{"session":"a-1","source":"plain","arguments":{"q":"x"}}`},
		{serverA, `{"session":"a-2","source":"screening-a","scope":"scope-a","arguments":{"q":"x"}}`},
		{serverB, `{"session":"b-1","source":"plain","arguments":{"q":"x"}}`},
		{serverB, `{"session":"b-2","source":"screening-a","scope":"scope-a","arguments":{"q":"x"}}`},
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 3 {
				if code, got := post(t, call.server, "/acquire", call.body); code != http.StatusOK {
					failed <- fmt.Sprintf("%s: %d %v", call.body, code, got)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(failed)
	for f := range failed {
		t.Fatal(f)
	}

	startedA, startedB := a.service.started.Load(), b.service.started.Load()
	for _, tc := range []struct {
		server        *httptest.Server
		path, body, s string
	}{
		{serverB, "/acquire", `{"session":"a-1","source":"plain","arguments":{"q":"x"}}`, "a-1"},
		{serverB, "/acquire", `{"session":"a-2","source":"screening-a","scope":"scope-a","arguments":{"q":"x"}}`, "a-2"},
		{serverB, "/seal", `{"session":"a-1"}`, "a-1"},
		{serverA, "/acquire", `{"session":"b-1","source":"plain","arguments":{"q":"x"}}`, "b-1"},
		{serverA, "/seal", `{"session":"b-2"}`, "b-2"},
	} {
		code, got := post(t, tc.server, tc.path, tc.body)
		if code != http.StatusConflict || got["error"] != fmt.Sprintf(refusalHeldElsewhere, tc.s) {
			t.Fatalf("%s %s on the other instance: %d %v", tc.path, tc.body, code, got)
		}
		if strings.Contains(fmt.Sprint(got["error"]), "instance-") {
			t.Fatalf("the refusal names an instance: %v", got["error"])
		}
	}
	if a.service.started.Load() != startedA || b.service.started.Load() != startedB {
		t.Fatal("a source ran for a session the other instance holds")
	}

	// the series is made, holding its instance, before the source runs: a
	// first call whose source fails leaves it held, and the other instance
	// refuses it, its source not run
	t.Setenv(envSourceFail, "1")
	if code, _ := post(t, serverA, "/acquire", `{"session":"a-failed","source":"plain","arguments":{"q":"x"}}`); code == http.StatusOK {
		t.Fatal("the failing source answered")
	}
	t.Setenv(envSourceFail, "")
	rows := asOwnerIn(t, db, pgNoScope, `SELECT holder FROM gateway.series WHERE name = 'a-failed'`)
	if len(rows.rows) != 1 || string(rows.rows[0][0]) != a.kind.fence {
		t.Fatalf("the series of a first call is not made holding its instance: %v", rows.rows)
	}
	startedB = b.service.started.Load()
	if code, got := post(t, serverB, "/acquire", `{"session":"a-failed","source":"plain","arguments":{"q":"x"}}`); code != http.StatusConflict || got["error"] != fmt.Sprintf(refusalHeldElsewhere, "a-failed") {
		t.Fatalf("a session a holds with no receipt, from b: %d %v", code, got)
	}
	if b.service.started.Load() != startedB {
		t.Fatal("a source ran for a session the other instance holds")
	}
	// its own instance goes on in it, and in its others
	for _, body := range []string{
		`{"session":"a-failed","source":"plain","arguments":{"q":"x"}}`,
		`{"session":"a-1","source":"plain","arguments":{"q":"x"}}`,
	} {
		if code, got := post(t, serverA, "/acquire", body); code != http.StatusOK {
			t.Fatalf("%s on its own instance: %d %v", body, code, got)
		}
	}
	if code, got := post(t, serverA, "/seal", `{"session":"a-1"}`); code != http.StatusOK || got["finalCount"] != float64(4) {
		t.Fatalf("a seals its own session: %d %v", code, got)
	}
}

// A stopping instance of the several-instances mode says what another
// instance serves of the call sent again: not a session that holds
// receipts.
func TestAStoppingPostgresInstanceOfSeveralSaysWhatAnotherServes(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	_, cfg := instancesPgConfig(t, db, dir, "engine.json", false)
	var said bytes.Buffer
	a, err := startEngineOnKind(cfg, testSeed, sealOpenPgSources(t), nil, &said)
	if err != nil {
		t.Fatal(err)
	}
	defer a.stop(&said)
	server := httptest.NewServer(a.service.handler())
	defer server.Close()
	a.service.closeForStop(10)
	code, got := post(t, server, "/acquire", `{"session":"s-1","source":"plain","arguments":{"q":"x"}}`)
	if code != http.StatusServiceUnavailable || got["error"] != (gateStopped{several: true}).Error() {
		t.Fatalf("a stopping instance of several: %d %v", code, got)
	}
	if strings.Contains(fmt.Sprint(got["error"]), "the instance that takes over serves it") {
		t.Fatalf("the refusal promises a hand-over of the session: %v", got["error"])
	}
}

// A session that holds no receipt is taken up by another instance only once
// its holder's row has expired, recorded at the series' next turn, and by
// one instance where two take it up at once; one that holds a receipt is
// never taken up.
func TestAPostgresSessionWithNoReceiptIsTakenUpOnlyOnceItsHoldersRowExpired(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	a, leaseA := severalKind(t, db, testSeed, pgStartLeasePeriod)
	b, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
	claim := func(k *pgKind, name string, want seriesClaim) {
		t.Helper()
		if got, err := k.claimSeries(name, ""); err != nil || got != want {
			t.Fatalf("claim %s: %v %v, want %v", name, got, err, want)
		}
	}
	claim(a, "empty-1", seriesHeldHere)
	claim(a, "empty-1", seriesHeldHere)
	claim(b, "empty-1", seriesHeldElsewhere)
	claim(a, "used-1", seriesHeldHere)
	if err := (pgIndexed{a}).createIndexed("used-1", 0, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	claim(b, "used-1", seriesHeldElsewhere)
	if got, err := b.seriesHolding("empty-1"); err != nil || got != seriesHeldElsewhere {
		t.Fatalf("seriesHolding while a is live: %v %v", got, err)
	}

	if err := leaseA.release(); err != nil {
		t.Fatal(err)
	}
	claim(b, "used-1", seriesLeftOpen)
	claim(b, "empty-1", seriesHeldHere)
	rows := asOwnerIn(t, db, pgNoScope, `SELECT turn, holder FROM gateway.series_holders WHERE series = 'empty-1'`)
	if len(rows.rows) != 1 || string(rows.rows[0][1]) != b.fence {
		t.Fatalf("the take-up is not recorded at turn 1: %v", rows.rows)
	}
	// the expired instance writes nothing more: its writes fail at its fence
	if _, err := a.claimSeries("empty-2", ""); err == nil {
		t.Fatal("an instance whose row expired made a series")
	}
	c, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
	claim(c, "empty-1", seriesHeldElsewhere)

	// two instances that take one series up at once: one holds it
	for round := range 5 {
		name := fmt.Sprintf("race-%d", round)
		e, leaseE := severalKind(t, db, testSeed, pgStartLeasePeriod)
		claim(e, name, seriesHeldHere)
		if err := leaseE.release(); err != nil {
			t.Fatal(err)
		}
		x, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
		y, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
		var wg sync.WaitGroup
		got := make([]seriesClaim, 2)
		errs := make([]error, 2)
		for i, k := range []*pgKind{x, y} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got[i], errs[i] = k.claimSeries(name, "")
			}()
		}
		wg.Wait()
		if errs[0] != nil || errs[1] != nil {
			t.Fatalf("round %d: %v %v", round, errs[0], errs[1])
		}
		slices.Sort(got)
		if got[0] != seriesHeldHere || got[1] != seriesHeldElsewhere {
			t.Fatalf("round %d: two take-ups at once answered %v", round, got)
		}
	}
}

// A claim that no scope answers -- the session's name taken by a series of
// a scope the record of scope identifiers does not hold -- is refused, as a
// session that could not be read, and never admitted here.
func TestAPostgresClaimNoScopeAnswersIsRefused(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	a, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
	unrecorded, err := a.inScope("unrecorded")
	if err != nil {
		t.Fatal(err)
	}
	if made, err := (pgIndexed{unrecorded}).makeSeries("orphan-1"); err != nil || !made {
		t.Fatalf("the series of a scope not recorded: %v %v", made, err)
	}
	got, err := a.claimSeries("orphan-1", "")
	if err == nil || faultOf(err) != faultUnreadable {
		t.Fatalf("a claim no scope answered: %v %v", got, err)
	}
}

// A seal appended by two instances at once is appended once: the registry's
// check that the session is unsealed is made in the append's transaction,
// under its lock. The first append is held between its judgment and its
// append while the second runs.
func TestPostgresInstancesSealingOneSessionAtOnceAppendOneSeal(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	a, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
	b, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
	if err := a.registry().createLog(); err != nil {
		t.Fatal(err)
	}
	history := func() (bool, error) { return true, nil }
	writerA, err := newRegistryWriterOn(a.registry(), pgRegistryName, testSeed, history)
	if err != nil {
		t.Fatal(err)
	}
	writerB, err := newRegistryWriterOn(b.registry(), pgRegistryName, testSeed, history)
	if err != nil {
		t.Fatal(err)
	}
	for round := range 3 {
		session := fmt.Sprintf("sealed-%d", round)
		judged := make(chan struct{})
		var once sync.Once
		afterSealJudged = func() {
			once.Do(func() {
				close(judged)
				// the other append starts and is given time to run as far
				// as it can
				time.Sleep(400 * time.Millisecond)
			})
		}
		results := make(chan error, 2)
		go func() {
			_, err := writerA.seal(session, 1, nowStamp())
			results <- err
		}()
		<-judged
		go func() {
			_, err := writerB.seal(session, 2, nowStamp())
			results <- err
		}()
		first, second := <-results, <-results
		afterSealJudged = nil
		if first != nil || !errors.Is(second, errSessionAlreadySealed) {
			t.Fatalf("round %d: %v, %v", round, first, second)
		}
	}
	data, err := a.registry().readLog(0)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(data, []byte("\n")); n != 3 {
		t.Fatalf("the registry holds %d records:\n%s", n, data)
	}
	walk, err := engineWalk(data, ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))
	if err != nil || len(walk.seals) != 3 {
		t.Fatalf("the registry's seals: %v %v", walk, err)
	}
	// the seals of many sessions from both at once: one each
	var wg sync.WaitGroup
	for _, w := range []*registryWriter{writerA, writerB} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 10 {
				if _, err := w.seal(fmt.Sprintf("many-%d", i), 1, nowStamp()); err != nil && !errors.Is(err, errSessionAlreadySealed) {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if data, err = a.registry().readLog(0); err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(data, []byte("\n")); n != 13 {
		t.Fatalf("the registry holds %d records, not one seal for each session", n)
	}
}

// pgSealLine is a seal of today's form of session, signed under seed, as a
// registry line without its newline.
func pgSealLine(seed []byte, session string, count int64, sealedAt string) string {
	priv := ed25519.NewKeyFromSeed(seed)
	keyID := keyIDFor(priv.Public().(ed25519.PublicKey))
	record := newObject()
	record.set("sessionId", vString(session))
	record.set("finalCount", vInt(count))
	record.set("sealedAt", vString(sealedAt))
	record.set("keyId", vString(keyID))
	record.set("signature", vString(hex.EncodeToString(ed25519.Sign(priv, sealSigningInput(session, count, sealedAt, keyID)))))
	return string(canon(record))
}

// pgFillRegistry appends n seals of sessions bulk-<i> to the registry, one
// record each, as the owner, in one statement.
func pgFillRegistry(t *testing.T, db *pgTestDB, seed []byte, n int) {
	t.Helper()
	lines := make([]string, n)
	for i := range n {
		lines[i] = pgSealLine(seed, fmt.Sprintf("bulk-%06d", i), int64(i%7+1), "2026-11-15T00:00:00Z")
	}
	asOwnerIn(t, db, pgNoScope, `INSERT INTO gateway.log_records (log, start, data)
		SELECT 'registry', COALESCE(pg_catalog.sum(pg_catalog.octet_length(l.data)) OVER (ORDER BY l.n ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING), 0), l.data
		FROM (SELECT t.n, pg_catalog.convert_to(t.line || E'\n', 'UTF8') AS data
			FROM pg_catalog.string_to_table($1, E'\n') WITH ORDINALITY AS t(line, n)) l
		ORDER BY l.n`, strings.Join(lines, "\n"))
}

// A seal on a registry of 100,000 seals reads and walks, in the append's
// transaction, only what was appended since its writer last read the
// registry: each stays far within the transaction's idle bound, shortened
// here to 2 seconds, which reading and walking the whole registry there
// outlasts. What the writer read at its open, and a seal another writer
// appended since, each still refuse a second seal of their session.
func TestAPostgresSealOnALargeRegistryReadsOnlyWhatWasAppendedSince(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	a, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
	if err := a.registry().createLog(); err != nil {
		t.Fatal(err)
	}
	const n = 100000
	pgFillRegistry(t, db, testSeed, n)
	a.idle = 2 * time.Second
	writer, err := newRegistryWriterOn(a.registry(), pgRegistryName, testSeed, func() (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	seal := func(session string) error {
		t.Helper()
		began := time.Now()
		_, err := writer.seal(session, 1, nowStamp())
		if took := time.Since(began); took >= a.idle {
			t.Fatalf("the seal of %s took %s on a registry of %d seals", session, took, n)
		}
		return err
	}
	if err := seal("fresh-0"); err != nil {
		t.Fatalf("a seal on a registry of %d seals: %v", n, err)
	}
	if err := seal("bulk-042424"); !errors.Is(err, errSessionAlreadySealed) {
		t.Fatalf("a session the registry sealed before the writer opened: %v", err)
	}
	// The other instance starts here, after the fill: filling the registry can
	// outlast a start lease on a slow host.
	b, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
	if _, err := b.registry().appendRecord([]byte(pgSealLine(testSeed, "other-0", 3, nowStamp()) + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := seal("other-0"); !errors.Is(err, errSessionAlreadySealed) {
		t.Fatalf("a session another writer sealed since: %v", err)
	}
	for i := 1; i <= 5; i++ {
		if err := seal(fmt.Sprintf("fresh-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	data, err := a.registry().readLog(0)
	if err != nil {
		t.Fatal(err)
	}
	if got := bytes.Count(data, []byte("\n")); got != n+7 {
		t.Fatalf("the registry holds %d lines, not %d", got, n+7)
	}
}

// A writer whose registry is no longer the one it read -- its last record
// gone and another in its place, of the same length, as a database that
// lost its last commits to a failover may hold -- reads the registry whole
// again before it seals, and refuses a session the record in that place
// seals.
func TestAPostgresSealRereadsARegistryThatIsNotTheOneItRead(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	a, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
	if err := a.registry().createLog(); err != nil {
		t.Fatal(err)
	}
	writer, err := newRegistryWriterOn(a.registry(), pgRegistryName, testSeed, func() (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range []string{"seal-a", "seal-b"} {
		if _, err := writer.seal(session, 1, "2026-11-15T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	// a seal before the writer's last reading, so it holds a cursor past
	// seal-b's record
	if _, err := writer.seal("seal-b", 1, nowStamp()); !errors.Is(err, errSessionAlreadySealed) {
		t.Fatalf("seal-b again: %v", err)
	}
	replaced := pgSealLine(testSeed, "seal-c", 1, "2026-11-15T00:00:00Z") + "\n"
	rows := asOwnerIn(t, db, pgNoScope, `DELETE FROM gateway.log_records WHERE log = 'registry'
		AND stop = (SELECT pg_catalog.max(stop) FROM gateway.log_records WHERE log = 'registry') RETURNING start, pg_catalog.octet_length(data)::int8`)
	if len(rows.rows) != 1 {
		t.Fatalf("the record replaced: %v", rows.rows)
	}
	start, _ := pgInt8(rows.rows[0][0])
	if size, _ := pgInt8(rows.rows[0][1]); size != int64(len(replaced)) {
		t.Fatalf("the record replaced is of %d bytes, its replacement of %d", size, len(replaced))
	}
	asOwnerIn(t, db, pgNoScope, `INSERT INTO gateway.log_records (log, start, data) VALUES ('registry', $1, $2)`, start, []byte(replaced))
	if _, err := writer.seal("seal-c", 2, nowStamp()); !errors.Is(err, errSessionAlreadySealed) {
		t.Fatalf("a session the record now in the last one's place seals: %v", err)
	}
	if _, err := writer.seal("seal-b", 2, nowStamp()); err != nil {
		t.Fatalf("seal-b, whose record is gone: %v", err)
	}
}

// A start that finds the registry made since its read goes on with it.
func TestAPostgresStartFindingTheRegistryMadeSinceItsReadGoesOn(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	a, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
	b, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
	// another instance makes the registry between this one's read and its
	// make
	history := func() (bool, error) { return false, b.registry().createLog() }
	if _, err := newRegistryWriterOn(a.registry(), pgRegistryName, testSeed, history); err != nil {
		t.Fatalf("the start that found the registry made: %v", err)
	}
}

// A start whose read found no registry, and whose store holds a session by
// the time it asks -- another instance's start made the registry and
// admitted a session in between -- reads the registry again and goes on
// with it, sealing as one that found it; it makes nothing.
func TestAPostgresStartFindingASessionAdmittedSinceItsReadReadsTheRegistryAgain(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	a, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
	b, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
	history := func() (bool, error) { return true, b.registry().createLog() }
	writer, err := newRegistryWriterOn(a.registry(), pgRegistryName, testSeed, history)
	if err != nil {
		t.Fatalf("the start that found a session admitted since its read: %v", err)
	}
	if _, err := writer.seal("since-read", 1, nowStamp()); err != nil {
		t.Fatalf("a seal by the start that read the registry again: %v", err)
	}
	if rows := pgTestQuery(t, db.runtime, "SELECT count(*) FROM gateway.logs"); len(rows.rows) != 1 {
		t.Fatal("the registry's logs could not be counted")
	} else if n, _ := pgInt8(rows.rows[0][0]); n != 1 {
		t.Fatalf("%d registries", n)
	}
}

// An instance killed: the other refuses its sessions until its row has
// expired -- seal-open passes over them, or refuses one named -- and then
// a start, two at once, seals each once.
func TestAKilledPostgresInstancesSessionsWaitForItsRowToExpireThenAreSealed(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, cfg := instancesPgConfig(t, db, dir, "engine.json", false)
	_, atStart := instancesPgConfig(t, db, dir, "engine-at-start.json", true)
	sources := sealOpenPgSources(t)
	var said bytes.Buffer
	a, err := startEngineOnKind(cfg, testSeed, sources, nil, &said)
	if err != nil {
		t.Fatal(err)
	}
	serverA := httptest.NewServer(a.service.handler())
	b, err := startEngineOnKind(cfg, testSeed, sources, nil, &said)
	if err != nil {
		t.Fatal(err)
	}
	defer b.stop(&said)
	serverB := httptest.NewServer(b.service.handler())
	defer serverB.Close()
	for _, call := range []struct {
		server *httptest.Server
		body   string
	}{
		{serverA, `{"session":"k-1","source":"plain","arguments":{"q":"x"}}`},
		{serverA, `{"session":"k-1","source":"plain","arguments":{"q":"y"}}`},
		{serverA, `{"session":"k-2","source":"screening-a","scope":"scope-a","arguments":{"q":"x"}}`},
		{serverB, `{"session":"live-1","source":"plain","arguments":{"q":"x"}}`},
	} {
		if code, got := post(t, call.server, "/acquire", call.body); code != http.StatusOK {
			t.Fatalf("%s: %d %v", call.body, code, got)
		}
	}
	holderA := a.kind.fence
	killInstance(a, serverA)

	started := b.service.started.Load()
	for _, call := range []struct{ path, body string }{
		{"/acquire", `{"session":"k-1","source":"plain","arguments":{"q":"z"}}`},
		{"/seal", `{"session":"k-2"}`},
	} {
		if code, got := post(t, serverB, call.path, call.body); code != http.StatusConflict {
			t.Fatalf("%s while the killed instance's row is live: %d %v", call.path, code, got)
		}
	}
	if b.service.started.Load() != started {
		t.Fatal("a source ran for a session the killed instance holds")
	}
	before, err := db.open(t, nil).registry().readLog(0)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := cmdSealOpenAt([]string{"--config", config, "--all"}, &stdout, &stderr, nowStamp); code != 0 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), "nothing was sealed") {
		t.Fatalf("seal-open --all while the killed instance's row is live: %d %q %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := cmdSealOpenAt([]string{"--config", config, "--session", "k-1"}, &stdout, &stderr, nowStamp); code != 1 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), fmt.Sprintf(refusalSealHeldElsewhere, "k-1")) {
		t.Fatalf("seal-open of a session the killed instance holds: %d %q %q", code, stdout.String(), stderr.String())
	}
	if after, err := db.open(t, nil).registry().readLog(0); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("seal-open appended while the holder's row was live: %v", err)
	}
	heads := sealOpenPgHeads(t, db, map[string]string{"k-1": "", "k-2": "scope-a"})

	// the row expires
	asOwnerIn(t, db, pgNoScope, `UPDATE gateway.start_lease SET renewed = pg_catalog.clock_timestamp() - interval '1 minute',
		expires = pg_catalog.clock_timestamp() - interval '1 second' WHERE holder = $1`, holderA)
	if code, got := post(t, serverB, "/acquire", `{"session":"k-1","source":"plain","arguments":{"q":"z"}}`); code != http.StatusBadRequest || got["error"] != fmt.Sprintf(refusalLeftOpen, "k-1") {
		t.Fatalf("a session with receipts whose holder expired: %d %v", code, got)
	}
	if b.service.started.Load() != started {
		t.Fatal("a source ran for a session left open")
	}
	// two starts at once seal each session once, and not b's
	outs := make([]bytes.Buffer, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := startOnKind(atStart, testSeed, sources, nil, kindRun{period: pgStartLeasePeriod, every: pgStartLeaseRenewal, stopped: context.Background(), said: &outs[i]})
			errs[i] = err
			if err == nil {
				t.Cleanup(func() { s.stop(&bytes.Buffer{}) })
			}
		}()
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("two starts at once: %v %v\n%s\n%s", errs[0], errs[1], outs[0].String(), outs[1].String())
	}
	var lines []string
	for i := range outs {
		lines = append(lines, strings.Split(outs[i].String(), "\n")...)
	}
	if got := sealOpenPgSeals(t, lines, "start: sealed after an interruption: ", sealedViaStart, heads); strings.Join(got, ",") != "k-1,k-2" {
		t.Fatalf("the starts sealed %v:\n%s\n%s", got, outs[0].String(), outs[1].String())
	}
	data, err := db.open(t, nil).registry().readLog(0)
	if err != nil {
		t.Fatal(err)
	}
	walk, err := engineWalk(data, ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))
	if err != nil || len(walk.seals) != 2 || bytes.Count(data, []byte("\n")) != 2 {
		t.Fatalf("the registry after the starts: %v %v\n%s", walk, err, data)
	}
	if _, sealed := walk.seals["live-1"]; sealed {
		t.Fatal("a session a live instance holds was sealed")
	}
	if code, got := post(t, serverB, "/acquire", `{"session":"live-1","source":"plain","arguments":{"q":"x"}}`); code != http.StatusOK {
		t.Fatalf("b goes on in its own session: %d %v", code, got)
	}
}

// One-instance and several-instances starts refuse each other, both ways; a
// several-instances start under another key id, or naming another
// authority, is refused; a start whose schema is not the database's is
// refused; gateway store remove-scope and migrate hold every row, refused
// while any row is live.
func TestPostgresInstancesRefuseAnotherModeKeyOrAuthorityAndHoldersOfEveryRow(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	take := func(as pgInstance) (*pgKind, *pgStartLease, error) {
		kind := db.open(t, nil)
		kind.instance = as
		lease, err := kind.takeStartLease(newTestLeaseHolder(t), pgStartLeasePeriod, pgStartLeaseRenewal)
		if err == nil {
			t.Cleanup(lease.closeOwn)
		}
		return kind, lease, err
	}
	one := instanceFor(&storageSpec{}, testSeed, "gateway:test")
	several := instanceFor(&storageSpec{several: true}, testSeed, "gateway:test")
	otherSeed := bytes.Repeat([]byte{7}, seedBytes)

	_, leaseOne, err := take(one)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := take(several); !errors.Is(err, errStartLeaseHeld) || !strings.Contains(err.Error(), "an instance in the several-instances mode does not start beside it") {
		t.Fatalf("several beside one: %v", err)
	}
	if _, _, err := take(one); !errors.Is(err, errStartLeaseHeld) || !strings.Contains(err.Error(), "one instance serves a database") {
		t.Fatalf("one beside one: %v", err)
	}
	if err := leaseOne.release(); err != nil {
		t.Fatal(err)
	}
	_, leaseSeveral, err := take(several)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := take(one); !errors.Is(err, errStartLeaseHeld) || !strings.Contains(err.Error(), "an instance in the one-instance mode does not start beside it") {
		t.Fatalf("one beside several: %v", err)
	}
	if _, _, err := take(instanceFor(&storageSpec{several: true}, otherSeed, "gateway:test")); !errors.Is(err, errInstanceMismatch) || !strings.Contains(err.Error(), "every instance serving one database at once signs with one key") {
		t.Fatalf("another key id beside several: %v", err)
	}
	if _, _, err := take(instanceFor(&storageSpec{several: true}, testSeed, "gateway:other")); !errors.Is(err, errInstanceMismatch) || !strings.Contains(err.Error(), "every instance serving one database at once names one authority") {
		t.Fatalf("another authority beside several: %v", err)
	}
	if _, _, err := take(several); err != nil {
		t.Fatalf("several beside several: %v", err)
	}

	// a removal, and a migration, hold every row: refused while one is live
	hold := func() error {
		c, err := pgConnect(db.runtime, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		defer c.close()
		if _, err := c.exec("BEGIN"); err != nil {
			t.Fatal(err)
		}
		defer c.exec("ROLLBACK")
		return pgHoldEveryInstance(c, "remove")
	}
	if err := hold(); !errors.Is(err, errStartLeaseHeld) || !strings.Contains(err.Error(), "(2 in all)") {
		t.Fatalf("hold while two rows are live: %v", err)
	}
	if err := leaseSeveral.release(); err != nil {
		t.Fatal(err)
	}
	if err := hold(); !errors.Is(err, errStartLeaseHeld) || !strings.Contains(err.Error(), "(1 in all)") {
		t.Fatalf("hold while one row of three is live: %v", err)
	}
	asOwnerIn(t, db, pgNoScope, `UPDATE gateway.start_lease SET renewed = pg_catalog.clock_timestamp() - interval '1 minute', expires = pg_catalog.clock_timestamp() - interval '1 second'`)
	if err := hold(); err != nil {
		t.Fatalf("hold with every row expired: %v", err)
	}
	connection := writeConnection(t, db.migrator)
	seed := filepath.Join(tempDirAt(t, 0o700), "gateway.seed")
	if err := os.WriteFile(seed, []byte(hex.EncodeToString(testSeed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, live, err := take(several)
	if err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runStoreRemoveScope("--connection-file", connection, "--owner", db.roles.owner, "--runtime", db.roles.runtime,
		"--seed", seed, "--scope", "scope-a", "--by", "operator-1", "--timeout", "60")
	if code != 1 || !strings.Contains(stderr, "start-lease-held: a gateway instance serves the database by a start lease that is live (1 in all); stop the gateway, then remove") {
		t.Fatalf("remove-scope while an instance of several is live: %d %q", code, stderr)
	}
	_ = live

	// a start whose schema is not the database's
	kind := db.open(t, nil)
	kind.instance = several
	asOwnerIn(t, db, pgNoScope, `UPDATE gateway.schema_migrations SET version = version + 100 WHERE version = (SELECT pg_catalog.max(version) FROM gateway.schema_migrations)`)
	if _, err := kind.takeStartLease(newTestLeaseHolder(t), pgStartLeasePeriod, pgStartLeaseRenewal); err == nil || !strings.Contains(err.Error(), "it was migrated as this instance started") {
		t.Fatalf("a start whose schema is not the database's: %v", err)
	}
}

// A store at the schema version before this one (5) migrates to version 6
// with every instance stopped: its series kept, holding no holder, and the
// start lease made again, empty. While its instance's lease is live the
// migration is refused, and nothing changes.
func TestAPostgresStoreAtSchemaFiveMigratesToRowsOfEachInstance(t *testing.T) {
	db := newPgTestDB(t)
	set := pgShippedMigrations()
	if len(set.versions) != 7 || set.versions[5].name != "0006_instances.sql" {
		t.Fatalf("the shipped schema has %d versions: the test names version 6 as the instances'", len(set.versions))
	}
	older := pgMigrationSet{versions: set.versions[:5], grants: pgGrantsOfVersion(t, set.grants, 5)}
	if applied, err := migratePostgres(db.migrator, older, db.roles, time.Minute); err != nil || len(applied) != 5 {
		t.Fatalf("schema version 5: %v %v", applied, err)
	}
	holder := newTestLeaseHolder(t)
	asOwnerIn(t, db, pgNoScope, `INSERT INTO gateway.series (scope, name) VALUES ('none', 'before-6')`)
	asOwnerIn(t, db, pgNoScope, `INSERT INTO gateway.start_lease (holder, renewed, expires)
		SELECT $1, n.now, n.now + interval '30 seconds' FROM (SELECT pg_catalog.clock_timestamp() AS now) n`, holder)
	before := db.fingerprint(t)
	if _, err := migratePostgres(db.migrator, set, db.roles, time.Minute); !errors.Is(err, errStartLeaseHeld) {
		t.Fatalf("the migration while the lease is live: %v", err)
	}
	if db.fingerprint(t) != before {
		t.Fatal("a refused migration changed the database")
	}
	asOwnerIn(t, db, pgNoScope, `UPDATE gateway.start_lease SET renewed = pg_catalog.clock_timestamp() - interval '1 minute', expires = pg_catalog.clock_timestamp() - interval '1 second'`)
	if applied, err := migratePostgres(db.migrator, set, db.roles, time.Minute); err != nil || !slices.Equal(applied, []int{6, 7}) {
		t.Fatalf("the migration with the instance stopped: %v %v", applied, err)
	}
	if rows := asOwnerIn(t, db, pgNoScope, `SELECT holder FROM gateway.series WHERE name = 'before-6'`); len(rows.rows) != 1 || rows.rows[0][0] != nil {
		t.Fatalf("the series before version 6: %v", rows.rows)
	}
	if rows := pgTestQuery(t, db.runtime, `SELECT holder FROM gateway.start_lease`); len(rows.rows) != 0 {
		t.Fatalf("the start lease after the migration: %v", rows.rows)
	}
	// a start takes it
	a, _ := severalKind(t, db, testSeed, pgStartLeasePeriod)
	if got, err := a.claimSeries("before-6", ""); err != nil || got != seriesHeldHere {
		t.Fatalf("a series of no holder, with no receipt: %v %v", got, err)
	}
}
