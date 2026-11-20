package main

// gateway store retain (store_retain.go): retention by acknowledgment on the
// PostgreSQL kind.

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

// A stopped service of two scope identifiers and of none: an acknowledged
// sealed session past the window loses its rows, and keeps a session-removal
// record alone; the open session of its scope, the other scope's session and
// the session of no scope keep theirs. An acknowledgment of the session of
// no scope refuses the call, and the database does not change.
func TestAPostgresStoreRetainRemovesAnAcknowledgedSession(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	t.Setenv(envSourceHelper, "1")
	helper := sourceSpec{argv: []string{os.Args[0]}, env: helperEnv}
	scoped := func(scope string) sourceSpec { s := helper; s.scope = scope; return s }
	sources := map[string]sourceSpec{"screening-a": scoped("scope-a"), "screening-b": scoped("scope-b"), "plain": helper}
	config, started, server := scopedServiceStart(t, db, dir, sources)
	for _, body := range []string{
		`{"session":"s-a","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`,
		`{"session":"s-a","source":"screening-a","scope":"scope-a","arguments":{"q":"other"}}`,
		`{"session":"s-a-open","source":"screening-a","scope":"scope-a","arguments":{"q":"third"}}`,
		`{"session":"s-b","source":"screening-b","scope":"scope-b","arguments":{"q":"acme"}}`,
		`{"session":"s-none","source":"plain","arguments":{"q":"acme"}}`,
	} {
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
	pub := started.service.publicKey

	// the seals, as an export's registry holds them
	t.Chdir(dir)
	before := filepath.Join(dir, "before")
	if _, err := exportEngine(config, before, nil, ""); err != nil {
		t.Fatalf("export: %v", err)
	}
	sa := sealOf(t, filepath.Join(before, "registry"), pub, "s-a")
	sn := sealOf(t, filepath.Join(before, "registry"), pub, "s-none")
	now := sealTime(t, sa).Add(31 * 24 * time.Hour)

	text := readFile(t, config)
	text = strings.Replace(text, `"engineVersion":"24"`, `"engineVersion":"`+retentionVersion+`"`, 1)
	text = strings.TrimSuffix(strings.TrimSpace(text), "}") + `,"retention":{"window":30,"acknowledgedBy":["` + hex.EncodeToString(retentionAckKey.Public().(ed25519.PublicKey)) + `"]}}`
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	connection := writeConnection(t, db.migrator)
	run := func(lines ...[]byte) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := cmdStoreRetainAt([]string{"--connection-file", connection, "--owner", db.roles.owner, "--runtime", db.roles.runtime,
			"--config", config, "--acknowledgments", writeAcks(t, lines...), "--by", "operator-1", "--timeout", "60"},
			&stdout, &stderr, fixedStamp(removalStamp), func() time.Time { return now })
		return code, stdout.String(), stderr.String()
	}

	print := db.fingerprint(t)
	code, stdout, stderr := run(retentionAckLine(retentionAckKey, "s-none", sn.signature, sn.finalCount, stampOf(sealTime(t, sn))))
	if code != 1 || stdout != "" || !strings.Contains(stderr, "store retain: acknowledgment line 1 names session s-none, which is of no scope identifier; it goes only with its whole store\n") ||
		!strings.Contains(stderr, "store retain: nothing was removed\n") {
		t.Fatalf("no scope: %d %q %q", code, stdout, stderr)
	}
	if db.fingerprint(t) != print {
		t.Fatal("a refused call changed the database")
	}

	code, stdout, stderr = run(retentionAckLine(retentionAckKey, "s-a", sa.signature, sa.finalCount, stampOf(sealTime(t, sa).Add(time.Hour))))
	if code != 0 || !strings.Contains(stderr, "store retain: removed 1 session(s), holding 2 receipt(s)") || !strings.Contains(stderr, "under the acknowledgments sha256:") {
		t.Fatalf("the removal: %d %q %q", code, stdout, stderr)
	}
	if lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n"); len(lines) != 1 || !strings.Contains(lines[0], `"kind":"session-removal"`) || !strings.Contains(lines[0], `"sessionId":"s-a"`) {
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
	pgInScopeOn(t, c, pgNoScope, func() {
		if got := pgColumn(t, c, `SELECT line FROM gateway.removal_records ORDER BY ordinal`); strings.Join(got, "\n")+"\n" != stdout {
			t.Errorf("the records kept: %q", got)
		}
	})

	after := filepath.Join(dir, "after")
	if _, err := exportEngine(config, after, nil, ""); err != nil {
		t.Fatalf("export: %v", err)
	}
	rep, err := verifyWithRegistry(filepath.Join(after, "store"), filepath.Join(after, "registry"), "gateway:test", pub)
	if err != nil {
		t.Fatal(err)
	}
	var observed []string
	for _, o := range rep.Observations {
		observed = append(observed, o["sessionId"].(string)+" "+o["observation"].(string))
	}
	if !slices.Contains(observed, "s-a "+observationSessionRemoved) {
		t.Fatalf("the verdict's observations: %v, findings %v", observed, rep.Findings)
	}
}
