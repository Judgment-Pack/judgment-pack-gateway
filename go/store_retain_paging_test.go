package main

// gateway store retain reads the receipt rows a page at a time
// (retainPageRows): the same refusals and the same removal, with pages of
// one row, over several sessions of two scope identifiers and of none.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAPostgresStoreRetainReadsTheReceiptsAPageAtATime(t *testing.T) {
	saved := retainPageRows
	t.Cleanup(func() { retainPageRows = saved })
	retainPageRows = 1

	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	t.Setenv(envSourceHelper, "1")
	t.Setenv(envSourceEchoStdin, "1") // a payload of its arguments, one per q
	helper := sourceSpec{argv: []string{os.Args[0]}, env: helperEnv}
	scoped := func(scope string) sourceSpec { s := helper; s.scope = scope; return s }
	sources := map[string]sourceSpec{"screening-a": scoped("scope-a"), "screening-b": scoped("scope-b"), "plain": helper}
	config, started, server := scopedServiceStart(t, db, dir, sources)
	for _, body := range []string{
		`{"session":"s-a","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`,
		`{"session":"s-a","source":"screening-a","scope":"scope-a","arguments":{"q":"one"}}`,
		`{"session":"s-a","source":"screening-a","scope":"scope-a","arguments":{"q":"once"}}`,
		`{"session":"s-a2","source":"screening-a","scope":"scope-a","arguments":{"q":"one"}}`,
		`{"session":"s-a2","source":"screening-a","scope":"scope-a","arguments":{"q":"two"}}`,
		`{"session":"s-a-open","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`,
		`{"session":"s-b","source":"screening-b","scope":"scope-b","arguments":{"q":"acme"}}`,
		`{"session":"s-b","source":"screening-b","scope":"scope-b","arguments":{"q":"two"}}`,
		`{"session":"s-none","source":"plain","arguments":{"q":"acme"}}`,
	} {
		if code, got := post(t, server, "/acquire", body); code != http.StatusOK {
			t.Fatalf("%s: %d %v", body, code, got)
		}
	}
	for _, session := range []string{"s-a", "s-a2", "s-b", "s-none"} {
		if code, got := post(t, server, "/seal", `{"session":"`+session+`"}`); code != http.StatusOK {
			t.Fatalf("seal %s: %d %v", session, code, got)
		}
	}
	var said bytes.Buffer
	started.stop(&said)
	server.Close()
	pub := started.service.publicKey

	t.Chdir(dir)
	before := filepath.Join(dir, "before")
	if _, err := exportEngine(config, before, nil, ""); err != nil {
		t.Fatalf("export: %v", err)
	}
	sa := sealOf(t, filepath.Join(before, "registry"), pub, "s-a")
	sa2 := sealOf(t, filepath.Join(before, "registry"), pub, "s-a2")
	now := sealTime(t, sa2).Add(31 * 24 * time.Hour)
	text := readFile(t, config)
	text = strings.Replace(text, `"engineVersion":"24"`, `"engineVersion":"`+retentionVersion+`"`, 1)
	text = strings.TrimSuffix(strings.TrimSpace(text), "}") + `,"retention":{"window":30,"acknowledgedBy":["` + hex.EncodeToString(retentionAckKey.Public().(ed25519.PublicKey)) + `"]}}`
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	connection := writeConnection(t, db.migrator)
	acks := writeAcks(t,
		retentionAckLine(retentionAckKey, "s-a", sa.signature, sa.finalCount, stampOf(sealTime(t, sa).Add(time.Hour))),
		retentionAckLine(retentionAckKey, "s-a2", sa2.signature, sa2.finalCount, stampOf(sealTime(t, sa2).Add(time.Hour))))
	run := func() (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := cmdStoreRetainAt([]string{"--connection-file", connection, "--owner", db.roles.owner, "--runtime", db.roles.runtime,
			"--config", config, "--acknowledgments", acks, "--by", "operator-1", "--timeout", "60"},
			&stdout, &stderr, fixedStamp(removalStamp), func() time.Time { return now })
		return code, stdout.String(), stderr.String()
	}

	// two receipts left in the database, past the first pages of their
	// scopes, that name the sessions the call would remove: each refuses,
	// in the order the rows stand, and the database does not change
	asOwnerIn(t, db, pgNoScope, `INSERT INTO gateway.entries (scope, series, name, data)
		VALUES ('none', 's-none', 'zz-cites-s-a2', pg_catalog.convert_to('{"cites":[{"sessionId":"s-a2"}]}', 'UTF8'))`)
	asOwnerIn(t, db, pgRowScope("scope-b"), `INSERT INTO gateway.entries (scope, series, name, data)
		VALUES ($1, 's-b', 'zz-cites-s-a', pg_catalog.convert_to('{"cites":[{"sessionId":"s-a"},{"sessionId":"s-a2"}]}', 'UTF8'))`, pgRowScope("scope-b"))
	print := db.fingerprint(t)
	code, stdout, stderr := run()
	want := "store retain: a receipt of session s-none names session s-a2, which the call would remove; its citation would no longer resolve\n" +
		"store retain: a receipt of session s-b names session s-a, which the call would remove; its citation would no longer resolve\n"
	if code != 1 || stdout != "" || !strings.Contains(stderr, want) || !strings.Contains(stderr, "store retain: nothing was removed\n") {
		t.Fatalf("the citing receipts: %d %q %q", code, stdout, stderr)
	}
	if db.fingerprint(t) != print {
		t.Fatal("a refused call changed the database")
	}
	asOwnerIn(t, db, pgNoScope, `DELETE FROM gateway.entries WHERE name LIKE 'zz-cites-%'`)
	asOwnerIn(t, db, pgRowScope("scope-b"), `DELETE FROM gateway.entries WHERE name LIKE 'zz-cites-%'`)

	// s-a and s-a2 removed, five receipts; of their payloads, acme stays
	// (s-a-open names it), one goes once both sessions are gone, and once
	// and two go (s-b's two is of another scope)
	code, stdout, stderr = run()
	if code != 0 || !strings.Contains(stderr, "store retain: removed 2 session(s), holding 5 receipt(s), and 3 payload(s)") {
		t.Fatalf("the removal: %d %q %q", code, stdout, stderr)
	}
	if lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n"); len(lines) != 2 || !strings.Contains(lines[0], `"sessionId":"s-a"`) || !strings.Contains(lines[1], `"sessionId":"s-a2"`) {
		t.Fatalf("the records printed: %q", stdout)
	}
	c := db.runtimeConn(t)
	for row, want := range map[string][]string{pgRowScope("scope-a"): {"s-a-open"}, pgRowScope("scope-b"): {"s-b"}, pgNoScope: {"s-none"}} {
		pgInScopeOn(t, c, row, func() {
			if got := pgColumn(t, c, `SELECT name FROM gateway.series ORDER BY name`); !slices.Equal(got, want) {
				t.Errorf("%s holds the sessions %v", row, got)
			}
		})
	}
	pgInScopeOn(t, c, pgRowScope("scope-a"), func() {
		if got := pgColumn(t, c, `SELECT name FROM gateway.blobs ORDER BY name`); len(got) != 1 {
			t.Errorf("scope-a keeps the payloads %v; want acme's alone", got)
		}
	})
}
