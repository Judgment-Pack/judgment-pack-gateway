package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// On the PostgreSQL kind under a key service, gateway store retain signs
// its records under the key version the configuration names (ADR-0050), as
// gateway retain does: the seed over the service's store is refused before
// anything is written, and with the key version named the record is under
// the service's key and the exported store verifies.
func TestAPostgresStoreRetainSignsThroughTheKeyService(t *testing.T) {
	standIn := standInKeyService(t)
	one := mustKeyServiceSigner(t, ksVersion1)
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, cfg := ksPgConfig(t, db, dir, ksVersion1, one.publicKey())
	var said bytes.Buffer
	a, err := startOnKind(cfg, testSeed, sealOpenPgSources(t), nil, kindRun{period: pgStartLeasePeriod, every: pgStartLeaseRenewal, stopped: context.Background(), said: &said, signer: one})
	if err != nil {
		t.Fatalf("the instance: %v\n%s", err, said.String())
	}
	server := httptest.NewServer(a.service.handler())
	if code, got := post(t, server, "/acquire", `{"session":"ks-r","source":"screening-a","scope":"scope-a","arguments":{"q":"x"}}`); code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, got)
	}
	if code, got := post(t, server, "/seal", `{"session":"ks-r"}`); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, got)
	}
	server.Close()
	a.stop(&said)

	t.Chdir(dir)
	before := filepath.Join(dir, "before")
	if _, err := exportEngine(config, before, nil, ""); err != nil {
		t.Fatalf("export: %v", err)
	}
	s := sealOf(t, filepath.Join(before, "registry"), one.publicKey(), "ks-r")
	now := sealTime(t, s).Add(31 * 24 * time.Hour)
	acks := writeAcks(t, retentionAckLine(retentionAckKey, "ks-r", s.signature, s.finalCount, stampOf(sealTime(t, s))))
	keyed := readFile(t, config)
	keyed = strings.Replace(keyed, `"engineVersion":"36"`, `"engineVersion":"`+retentionVersion+`"`, 1)
	keyed = strings.TrimSuffix(strings.TrimSpace(keyed), "}") + `,"retention":{"window":30,"acknowledgedBy":["` + hex.EncodeToString(retentionAckKey.Public().(ed25519.PublicKey)) + `"]}}`
	pinned := `"signingKeyVersion":"` + ksVersion1 + `","signingPublicKey":"` + hex.EncodeToString(one.publicKey()) + `",`
	if !strings.Contains(keyed, pinned) {
		t.Fatalf("the configuration does not name the key version: %s", keyed)
	}
	connection := writeConnection(t, db.migrator)
	run := func(text string) (int, string, string) {
		if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := cmdStoreRetainAt([]string{"--connection-file", connection, "--owner", db.roles.owner, "--runtime", db.roles.runtime,
			"--config", config, "--acknowledgments", acks, "--by", "operator-1", "--timeout", "60"},
			&stdout, &stderr, fixedStamp(removalStamp), func() time.Time { return now })
		return code, stdout.String(), stderr.String()
	}

	print := db.fingerprint(t)
	if code, stdout, stderr := run(strings.Replace(keyed, pinned, "", 1)); code != 1 || stdout != "" || !strings.Contains(stderr, "no rotation in the registry leads from it") {
		t.Fatalf("the seed over a key service's store: %d %q %q", code, stdout, stderr)
	}
	if db.fingerprint(t) != print {
		t.Fatal("the seed's refusal changed the database")
	}

	asked := standIn.requests
	code, stdout, stderr := run(keyed)
	if code != 0 || strings.Count(stdout, `"kind":"session-removal"`) != 1 || standIn.requests <= asked {
		t.Fatalf("store retain through the key service: %d %q %q, %d requests after %d", code, stdout, stderr, standIn.requests, asked)
	}
	if !strings.Contains(stdout, `"keyId":"`+keyIDFor(one.publicKey())+`"`) {
		t.Fatalf("the removal record is not under the key service's key: %s", stdout)
	}
	if !strings.Contains(stderr, "holding 1 receipt(s), and 1 payload(s)") {
		t.Fatalf("the session's payload was not removed: %q", stderr)
	}
	c := db.runtimeConn(t)
	pgInScopeOn(t, c, pgRowScope("scope-a"), func() {
		if got := pgColumn(t, c, `SELECT name FROM gateway.blobs`); len(got) != 0 {
			t.Errorf("scope-a still holds the payloads %v", got)
		}
	})
	after := filepath.Join(dir, "after")
	if _, err := exportEngine(config, after, nil, ""); err != nil {
		t.Fatalf("export: %v", err)
	}
	if rep, err := verifyWithRegistry(filepath.Join(after, "store"), filepath.Join(after, "registry"), "gateway:test", one.publicKey()); err != nil || !rep.OK {
		t.Fatalf("the store after store retain: %v %+v", err, rep)
	}
}
