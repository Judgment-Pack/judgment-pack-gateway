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
// names it, refuse the call by name, and the database does not change.
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
}
