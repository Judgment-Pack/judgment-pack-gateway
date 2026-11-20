package main

// The key history on the PostgreSQL kind (SPEC.md §3e; ADR-0052): every
// instance of one registry answers the same, and a store rotation carries
// the history across in the one row of gateway.key_history
// (store_rotate_pg.go), written with the new database's registry, read by
// every instance on it, held to the digest the continuation names, and
// never the run-time role's to change.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// On the PostgreSQL kind, every instance serving one database answers the
// key history of the one registry they share, read at each request: a store
// that has not rotated answers the seed's key alone, in force, with seals
// in the registry passed over, and the two instances answer the same bytes.
func TestAPostgresKeyHistoryIsServedByEveryInstanceOfOneRegistry(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	_, cfg := instancesPgConfig(t, db, dir, "engine.json", false)
	sources := sealOpenPgSources(t)
	var said bytes.Buffer
	run := kindRun{period: pgStartLeasePeriod, every: pgStartLeaseRenewal, stopped: context.Background(), said: &said}
	a, err := startOnKind(cfg, testSeed, sources, nil, run)
	if err != nil {
		t.Fatalf("instance a: %v\n%s", err, said.String())
	}
	defer a.stop(&said)
	b, err := startOnKind(cfg, testSeed, sources, nil, run)
	if err != nil {
		t.Fatalf("instance b: %v\n%s", err, said.String())
	}
	defer b.stop(&said)
	if _, err := a.service.acquire("pg-history", "plain", vString("pg-history"), nil); err != nil {
		t.Fatal(err)
	}
	mustSeal(t, a.service, "pg-history")
	seedKey := ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)
	entriesA, bodyA := historyPinned(t, a.service, seedKey)
	wantKeys(t, entriesA, []ed25519.PublicKey{seedKey}, nil)
	_, bodyB := historyPinned(t, b.service, seedKey)
	if !bytes.Equal(bodyA, bodyB) {
		t.Fatalf("two instances of one registry answer two histories:\n%s\n%s", bodyA, bodyB)
	}
	if code, _ := askKeyHistory(t, b.service); code != http.StatusOK {
		t.Fatalf("instance b: %d", code)
	}
}

// pgKeyHistoryUnreadable is the fixed answer to a key history that cannot be
// read.
const pgKeyHistoryUnreadable = `{"error":"the key history could not be read; the gateway says why on its stderr"}`

// pgServeWith starts an instance on cfg under seed, writing seed as the
// configuration's seed file in dir, so that a store rotation of cfg signs
// with it too; it answers the instance and its stop.
func pgServeWith(t *testing.T, cfg engineConfig, dir string, seed []byte) (*gatewayService, func()) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "gateway.seed"), []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var said bytes.Buffer
	s, err := startEngineOnKind(cfg, seed, sealOpenPgSources(t), nil, &said)
	if err != nil {
		t.Fatalf("the start: %v\n%s", err, said.String())
	}
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			s.stop(&said)
		}
	}
	t.Cleanup(stop)
	return s.service, stop
}

// pgCarriedRow is the key history db carries, as the run-time role reads
// it, and whether there is one.
func pgCarriedRow(t *testing.T, db *pgTestDB) ([]byte, bool) {
	t.Helper()
	rows := pgTestQuery(t, db.runtime, `SELECT history FROM gateway.key_history`)
	if len(rows.rows) == 0 {
		return nil, false
	}
	return rows.rows[0][0], true
}

// pgRotateStopped appends to db's registry, every instance stopped, the
// record of a rotation from the key of seed to the key of next, at at, as
// ADR-0050 has a rotation made on the PostgreSQL kind: every instance
// stopped, and all started again under the next key.
func pgRotateStopped(t *testing.T, db *pgTestDB, seed, next []byte, at string) {
	t.Helper()
	kind := db.open(t, nil)
	t.Cleanup(kind.close)
	existing, err := kind.registry().readLog(0)
	if err != nil {
		t.Fatal(err)
	}
	walk, err := engineWalk(existing, seedKeyOf(seed))
	if err != nil {
		t.Fatal(err)
	}
	record, err := rotationRecordSigned(existing, walk.followed()+1, at, newSigningKey(newSeedSigner(seed)), newSigningKey(newSeedSigner(next)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kind.registry().appendRecord(record); err != nil {
		t.Fatal(err)
	}
}

// A store rotation on the PostgreSQL kind carries the old database's key
// history into the new one: an instance there answers it whole, the bytes
// the old database answered; a second rotation carries the whole history
// on, spanning both; and the run-time role reads the row and can neither
// change, remove nor double it.
func TestAPostgresStoreRotationCarriesTheKeyHistoryAcrossTwoRotations(t *testing.T) {
	seed2, seed3 := historySeed("2"), historySeed("3")
	keys := []ed25519.PublicKey{seedKeyOf(testSeed), seedKeyOf(seed2), seedKeyOf(seed3)}
	at := []string{"2026-11-19T00:00:00Z", "2026-11-19T00:00:02Z"}
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, cfg := sealOpenPgConfig(t, db, dir, "engine.json", false, "")
	_, stop := pgServeWith(t, cfg, dir, testSeed)
	stop()
	pgRotateStopped(t, db, testSeed, seed2, at[0])
	g, stop := pgServeWith(t, cfg, dir, seed2)
	_, before := historyPinned(t, g, keys[0])
	stop()

	target := pgTestDBBeside(t, db)
	code, stdout, stderr := rotatePg(t, config, target, dir)
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	if carried, present := pgCarriedRow(t, target); !present || !bytes.Equal(carried, before) {
		t.Fatalf("the history carried is not the old database's answer:\n%s\n%s", carried, before)
	}
	if a, b := pgRuntimeGrants(t, db), pgRuntimeGrants(t, target); strings.Join(b["key_history"], ",") != "SELECT" || strings.Join(a["key_history"], ",") != "SELECT" {
		t.Fatalf("the run-time role holds %v on the new database's key history and %v on the old's", b["key_history"], a["key_history"])
	}
	for _, change := range []string{
		`UPDATE gateway.key_history SET history = '\x7b7d'`,
		`DELETE FROM gateway.key_history`,
		`TRUNCATE gateway.key_history`,
		`INSERT INTO gateway.key_history (singleton, history) VALUES (false, '\x7b7d')`,
	} {
		if _, err := pgTestQueryErr(target.runtime, change); err == nil || !strings.Contains(err.Error(), "SQLSTATE 42501") {
			t.Fatalf("the run-time role's %q: %v", change, err)
		}
	}

	newDir := tempDirAt(t, 0o700)
	newConfig, newCfg := sealOpenPgConfig(t, target, newDir, "engine.json", false, "")
	g2, stop2 := pgServeWith(t, newCfg, newDir, seed2)
	entries, answered := historyPinned(t, g2, keys[0])
	if !bytes.Equal(answered, before) {
		t.Fatalf("the new database's history is not the old database's answer:\n%s\n%s", answered, before)
	}
	wantKeys(t, entries, keys[:2], at[:1])
	stop2()
	pgRotateStopped(t, target, seed2, seed3, at[1])
	g2, stop2 = pgServeWith(t, newCfg, newDir, seed3)
	_, after := historyPinned(t, g2, keys[0])
	stop2()

	third := pgTestDBBeside(t, db)
	if code, stdout, stderr := rotatePg(t, newConfig, third, newDir); code != 0 || stderr != "" {
		t.Fatalf("the second rotation: exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	thirdDir := tempDirAt(t, 0o700)
	_, thirdCfg := sealOpenPgConfig(t, third, thirdDir, "engine.json", false, "")
	g3, _ := pgServeWith(t, thirdCfg, thirdDir, seed3)
	entries, whole := historyPinned(t, g3, keys[0])
	if !bytes.Equal(whole, after) {
		t.Fatalf("the second rotation did not carry the whole history:\n%s\n%s", whole, after)
	}
	wantKeys(t, entries, keys, at)
}

// A rerun into a database that holds the continuation alone and a row that
// is not the bytes named is refused with nothing changed or marked, and one
// whose row is missing writes it again from the same bytes; a continued
// database whose carried history the owner removed or changed answers 500
// with the fixed sentence, never a shorter history, and the history named
// once it is back.
func TestAPostgresCarriedKeyHistoryIsHeldToTheDigestTheContinuationNames(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, cfg := sealOpenPgConfig(t, db, dir, "engine.json", false, "")
	g, stop := pgServeWith(t, cfg, dir, testSeed)
	_, before := historyPinned(t, g, seedKeyOf(testSeed))
	stop()
	target := pgTestDBBeside(t, db)
	code, stdout, stderr := rotatePg(t, config, target, dir)
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	line := stdout
	newRegistry := pgRegistryOf(t, target)

	// a rerun, while the new database holds the continuation alone, with
	// the old database's mark removed as only the owner can
	altered := bytes.Replace(before, []byte(`"keyId":"`), []byte(`"keyId":"0`), 1)
	asOwnerIn(t, db, pgNoScope, `DELETE FROM gateway.rotated`)
	asOwnerIn(t, target, pgNoScope, `UPDATE gateway.key_history SET history = $1`, altered)
	code, stdout, stderr = rotatePg(t, config, target, dir)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "the key history it carries is "+keyHistoryDigestOf(altered)+", not the history "+keyHistoryDigestOf(before)) ||
		!strings.Contains(stderr, "nothing was changed in it, and the old one is not marked rotated") {
		t.Fatalf("a rerun over a changed history: %d %q %q", code, stdout, stderr)
	}
	if carried, _ := pgCarriedRow(t, target); !bytes.Equal(carried, altered) || pgRegistryOf(t, target) != newRegistry {
		t.Fatal("a refused rerun changed the new database")
	}
	if rows := pgTestQuery(t, db.runtime, `SELECT continuation FROM gateway.rotated`); len(rows.rows) != 0 {
		t.Fatalf("a refused rerun marked the old database: %v", rows.rows)
	}

	asOwnerIn(t, target, pgNoScope, `DELETE FROM gateway.key_history`)
	code, stdout, stderr = rotatePg(t, config, target, dir)
	if code != 0 || stderr != "" || stdout != line {
		t.Fatalf("a rerun over a missing history: %d %q %q", code, stdout, stderr)
	}
	if carried, present := pgCarriedRow(t, target); !present || !bytes.Equal(carried, before) {
		t.Fatalf("the rerun carried another history:\n%s\n%s", carried, before)
	}
	if rows := pgTestQuery(t, db.runtime, `SELECT continuation FROM gateway.rotated`); len(rows.rows) != 1 {
		t.Fatalf("the rerun did not mark the old database: %v", rows.rows)
	}

	// an instance on the new database answers the history carried, 500
	// once the owner changes or removes it, and the history named once it
	// is back
	newDir := tempDirAt(t, 0o700)
	_, newCfg := sealOpenPgConfig(t, target, newDir, "engine.json", false, "")
	g2, _ := pgServeWith(t, newCfg, newDir, testSeed)
	if _, answered := historyPinned(t, g2, seedKeyOf(testSeed)); !bytes.Equal(answered, before) {
		t.Fatalf("the new database's history:\n%s\n%s", answered, before)
	}
	asOwnerIn(t, target, pgNoScope, `UPDATE gateway.key_history SET history = $1`, altered)
	if code, body := askKeyHistory(t, g2); code != http.StatusInternalServerError || string(body) != pgKeyHistoryUnreadable {
		t.Fatalf("a carried history changed by the owner: %d %s", code, body)
	}
	asOwnerIn(t, target, pgNoScope, `DELETE FROM gateway.key_history`)
	if code, body := askKeyHistory(t, g2); code != http.StatusInternalServerError || string(body) != pgKeyHistoryUnreadable {
		t.Fatalf("a carried history removed by the owner: %d %s", code, body)
	}
	asOwnerIn(t, target, pgNoScope, `INSERT INTO gateway.key_history (history) VALUES ($1)`, before)
	if _, back := historyPinned(t, g2, seedKeyOf(testSeed)); !bytes.Equal(back, before) {
		t.Fatalf("the history named, back in the database, is not answered:\n%s", back)
	}
}
