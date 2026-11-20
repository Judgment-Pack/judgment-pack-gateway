package main

// gateway store retain: what it refuses on the PostgreSQL kind, by name,
// the database unchanged (store_retain.go).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// An acknowledgment of an open session of a scope identifier, and one of a
// sealed session while a receipt of another session, left in the database,
// names it, refuse the call by name, and the database does not change; so
// does a database rotated away from, by the rotation's sentence.
func TestAPostgresStoreRetainRefusesWhatItCannotRemoveWhole(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	t.Setenv(envSourceHelper, "1")
	helper := sourceSpec{argv: []string{os.Args[0]}, env: helperEnv}
	scoped := helper
	scoped.scope = "scope-a"
	config, started, server := scopedServiceStart(t, db, dir, map[string]sourceSpec{"screening-a": scoped, "plain": helper})
	for _, body := range []string{
		`{"session":"s-a","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`,
		`{"session":"s-a-open","source":"screening-a","scope":"scope-a","arguments":{"q":"other"}}`,
		`{"session":"s-c","source":"plain","arguments":{"q":"third"}}`,
	} {
		if code, got := post(t, server, "/acquire", body); code != http.StatusOK {
			t.Fatalf("%s: %d %v", body, code, got)
		}
	}
	if code, got := post(t, server, "/seal", `{"session":"s-a"}`); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, got)
	}
	var said bytes.Buffer
	started.stop(&said)
	server.Close()

	t.Chdir(dir)
	before := filepath.Join(dir, "before")
	if _, err := exportEngine(config, before, nil, ""); err != nil {
		t.Fatalf("export: %v", err)
	}
	sa := sealOf(t, filepath.Join(before, "registry"), started.service.publicKey, "s-a")
	now := sealTime(t, sa).Add(31 * 24 * time.Hour)
	text := readFile(t, config)
	text = strings.Replace(text, `"engineVersion":"24"`, `"engineVersion":"`+retentionVersion+`"`, 1)
	text = strings.TrimSuffix(strings.TrimSpace(text), "}") + `,"retention":{"window":30,"acknowledgedBy":["` + hex.EncodeToString(retentionAckKey.Public().(ed25519.PublicKey)) + `"]}}`
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	// a receipt of another session, left in the database, whose bytes name s-a
	asOwnerIn(t, db, pgNoScope, `INSERT INTO gateway.entries (scope, series, name, data)
		VALUES ('none', 's-c', 'cites-s-a', pg_catalog.convert_to('{"cites":[{"sessionId":"s-a"}]}', 'UTF8'))`)
	connection := writeConnection(t, db.migrator)
	at := stampOf(sealTime(t, sa).Add(time.Hour))
	print := db.fingerprint(t)
	for _, tc := range []struct{ name, session, want string }{
		{"an open session", "s-a-open", "store retain: acknowledgment line 1 names session s-a-open, which is open; an open session is never removed\n"},
		{"a receipt of another session naming it", "s-a", "store retain: a receipt of session s-c names session s-a, which the call would remove; its citation would no longer resolve\n"},
	} {
		var stdout, stderr bytes.Buffer
		code := cmdStoreRetainAt([]string{"--connection-file", connection, "--owner", db.roles.owner, "--runtime", db.roles.runtime,
			"--config", config, "--acknowledgments", writeAcks(t, retentionAckLine(retentionAckKey, tc.session, sa.signature, sa.finalCount, at)), "--by", "operator-1", "--timeout", "60"},
			&stdout, &stderr, fixedStamp(removalStamp), func() time.Time { return now })
		if code != 1 || stdout.String() != "" || !strings.Contains(stderr.String(), tc.want) || !strings.Contains(stderr.String(), "store retain: nothing was removed\n") {
			t.Errorf("%s: %d %q %q", tc.name, code, stdout.String(), stderr.String())
		}
		if db.fingerprint(t) != print {
			t.Fatalf("%s: a refused call changed the database", tc.name)
		}
	}

	// a database rotated away from is refused by the rotation's sentence,
	// with the citing receipt gone so that the line would otherwise remove
	// s-a, and no removal record is kept
	asOwnerIn(t, db, pgNoScope, `DELETE FROM gateway.entries WHERE series = 's-c' AND name = 'cites-s-a'`)
	mark := strings.Repeat("cd", 32)
	asOwnerIn(t, db, pgNoScope, `INSERT INTO gateway.rotated (continuation, rotated_at) VALUES ($1, now())`, mark)
	var stdout, stderr bytes.Buffer
	code := cmdStoreRetainAt([]string{"--connection-file", connection, "--owner", db.roles.owner, "--runtime", db.roles.runtime,
		"--config", config, "--acknowledgments", writeAcks(t, retentionAckLine(retentionAckKey, "s-a", sa.signature, sa.finalCount, at)), "--by", "operator-1", "--timeout", "60"},
		&stdout, &stderr, fixedStamp(removalStamp), func() time.Time { return now })
	if code != 1 || stdout.String() != "" || !strings.Contains(stderr.String(), "the store was rotated away from ("+rotatedMarkPrefix+mark+")") {
		t.Fatalf("a database rotated away from: %d %q %q", code, stdout.String(), stderr.String())
	}
	if rows := asOwnerIn(t, db, pgNoScope, `SELECT 1 FROM gateway.removal_records`); len(rows.rows) != 0 {
		t.Fatal("a removal record was kept on a database rotated away from")
	}
	if rows := asOwnerIn(t, db, pgRowScope("scope-a"), `SELECT 1 FROM gateway.series WHERE name = 's-a'`); len(rows.rows) != 1 {
		t.Fatal("s-a was removed from a database rotated away from")
	}
}

// A session of no scope identifier that a session-removal record names under
// a scope identifier, its rows still there, is not finished by retain: its
// receipts carry no scope to hold the record to, so the call is refused by
// name and the database does not change.
func TestAPostgresStoreRetainRefusesToFinishASessionOfNoScope(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	t.Setenv(envSourceHelper, "1")
	helper := sourceSpec{argv: []string{os.Args[0]}, env: helperEnv}
	config, started, server := scopedServiceStart(t, db, dir, map[string]sourceSpec{"plain": helper})
	if code, got := post(t, server, "/acquire", `{"session":"s-none","source":"plain","arguments":{"q":"acme"}}`); code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, got)
	}
	if code, got := post(t, server, "/seal", `{"session":"s-none"}`); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, got)
	}
	var said bytes.Buffer
	started.stop(&said)
	server.Close()

	t.Chdir(dir)
	before := filepath.Join(dir, "before")
	if _, err := exportEngine(config, before, nil, ""); err != nil {
		t.Fatalf("export: %v", err)
	}
	pub := started.service.publicKey
	key := newSigningKey(newSeedSigner(testSeed))
	if !bytes.Equal(key.public, pub) {
		t.Fatal("the service does not sign under the test seed")
	}
	walk, err := engineWalk([]byte(readFile(t, filepath.Join(before, "registry"))), pub)
	if err != nil {
		t.Fatal(err)
	}
	s := walk.seals["s-none"]
	_, line, err := signedSessionRemoval(key, walk.keys, "s-none", s, "scope-a", "", "operator-1", removalStamp)
	if err != nil {
		t.Fatal(err)
	}
	asOwnerIn(t, db, pgNoScope, `INSERT INTO gateway.removal_records (scope, ordinal, line) VALUES ('none', 0, $1)`, bytes.TrimSuffix(line, []byte{'\n'}))

	text := readFile(t, config)
	text = strings.Replace(text, `"engineVersion":"24"`, `"engineVersion":"`+retentionVersion+`"`, 1)
	text = strings.TrimSuffix(strings.TrimSpace(text), "}") + `,"retention":{"window":30,"acknowledgedBy":["` + hex.EncodeToString(retentionAckKey.Public().(ed25519.PublicKey)) + `"]}}`
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	connection := writeConnection(t, db.migrator)
	sealed, err := time.Parse(time.RFC3339, s.sealedAt)
	if err != nil {
		t.Fatal(err)
	}
	print := db.fingerprint(t)
	var stdout, stderr bytes.Buffer
	code := cmdStoreRetainAt([]string{"--connection-file", connection, "--owner", db.roles.owner, "--runtime", db.roles.runtime,
		"--config", config, "--acknowledgments", writeAcks(t, retentionAckLine(retentionAckKey, "s-none", s.signature, s.finalCount, stampOf(sealed))), "--by", "operator-1", "--timeout", "60"},
		&stdout, &stderr, fixedStamp(removalStamp), func() time.Time { return sealed.Add(31 * 24 * time.Hour) })
	want := "store retain: acknowledgment line 1 names session s-none, recorded as removed already under a scope identifier, whose receipts are of none; the session is left whole\n"
	if code != 1 || stdout.String() != "" || !strings.Contains(stderr.String(), want) || !strings.Contains(stderr.String(), "store retain: nothing was removed\n") {
		t.Fatalf("a finish of no scope: %d %q %q", code, stdout.String(), stderr.String())
	}
	if db.fingerprint(t) != print {
		t.Fatal("a refused call changed the database")
	}
}
