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
)

// On the PostgreSQL kind under a key service, gateway store rotate seals
// what is open and signs the continuation under the key version the
// configuration names (ADR-0050): the seed alone is refused and the old
// registry does not change, and with the key version named the old
// store's last seal and the new database's continuation are under the
// service's key, the new registry links to the old one, and the old store
// verifies.
func TestAPostgresStoreRotateSignsThroughTheKeyService(t *testing.T) {
	standIn := standInKeyService(t)
	one := mustKeyServiceSigner(t, ksVersion1)
	serviceKey := keyIDFor(one.publicKey())
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
	if code, got := post(t, server, "/acquire", `{"session":"ks-left","source":"screening-a","scope":"scope-a","arguments":{"q":"x"}}`); code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, got)
	}
	if code, got := post(t, server, "/acquire", `{"session":"ks-done","source":"plain","arguments":{"q":"x"}}`); code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, got)
	}
	if code, got := post(t, server, "/seal", `{"session":"ks-done"}`); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, got)
	}
	server.Close()
	a.stop(&said)
	target := pgTestDBBeside(t, db)
	keyed := readFile(t, config)
	pinned := `"signingKeyVersion":"` + ksVersion1 + `","signingPublicKey":"` + hex.EncodeToString(one.publicKey()) + `",`
	if !strings.Contains(keyed, pinned) {
		t.Fatalf("the configuration does not name the key version: %s", keyed)
	}

	before := pgRegistryOf(t, db)
	if err := os.WriteFile(config, []byte(strings.Replace(keyed, pinned, "", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := rotatePg(t, config, target, dir); code != 1 || stdout != "" || !strings.Contains(stderr, "no rotation in the registry leads from it") {
		t.Fatalf("the seed over a key service's store: %d %q %q", code, stdout, stderr)
	}
	if pgRegistryOf(t, db) != before {
		t.Fatal("the seed's refusal changed the old registry")
	}

	if err := os.WriteFile(config, []byte(keyed), 0o600); err != nil {
		t.Fatal(err)
	}
	asked := standIn.requests
	code, stdout, stderr := rotatePg(t, config, target, dir)
	if code != 0 || stderr != "" || standIn.requests <= asked {
		t.Fatalf("store rotate through the key service: %d %q %q, %d requests after %d", code, stdout, stderr, standIn.requests, asked)
	}
	out := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(out) != 2 || !strings.Contains(out[0], `"sessionId":"ks-left"`) || !strings.Contains(out[0], `"keyId":"`+serviceKey+`"`) {
		t.Fatalf("the seal of the session left open is not under the service's key: %q", stdout)
	}
	old := pgRegistryOf(t, db)
	if !strings.HasSuffix(old, out[0]+"\n") {
		t.Fatal("the old registry does not end in the seal printed")
	}
	if got := pgRegistryOf(t, target); got != out[1]+"\n" || !strings.Contains(got, `"keyId":"`+serviceKey+`"`) {
		t.Fatalf("the continuation is not under the service's key: %q", got)
	}
	if strings.Contains(old+out[1], `"keyId":"`+keyIDFor(ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))+`"`) {
		t.Fatal("something was signed under the seed's key")
	}
	files := t.TempDir()
	oldPath, newPath := filepath.Join(files, "old.jsonl"), filepath.Join(files, "new.jsonl")
	if err := os.WriteFile(oldPath, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte(out[1]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if f := linkOfUnder(t, newPath, oldPath, one.publicKey()); len(f) != 0 {
		t.Fatalf("the link to the old registry: %v", f)
	}

	// the old store, exported with its mark removed as the owner can,
	// verifies under the service's key
	asOwnerIn(t, db, pgNoScope, `DELETE FROM gateway.rotated`)
	t.Chdir(dir)
	exported := filepath.Join(dir, "export-old")
	if _, err := exportEngine(config, exported, nil, ""); err != nil {
		t.Fatalf("export: %v", err)
	}
	if rep, err := verifyWithRegistry(filepath.Join(exported, "store"), filepath.Join(exported, "registry"), "gateway:test", one.publicKey()); err != nil || !rep.OK {
		t.Fatalf("the old store after the rotation: %v %+v", err, rep)
	}
}

// On the PostgreSQL kind, a store holding receipts under a key no rotation
// leads from to the key in force is refused before anything is sealed: the
// session left open under the key in force stays open, the old registry is
// the same bytes, the old database is not marked rotated, and the new
// database holds no registry.
func TestAPostgresStoreRotateRefusesReceiptsUnderAnUnreachedKeyBeforeSealing(t *testing.T) {
	standInKeyService(t)
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
	for _, body := range []string{
		`{"session":"ks-left","source":"screening-a","scope":"scope-a","arguments":{"q":"x"}}`,
		`{"session":"ks-done","source":"plain","arguments":{"q":"x"}}`,
	} {
		if code, got := post(t, server, "/acquire", body); code != http.StatusOK {
			t.Fatalf("acquire: %d %v", code, got)
		}
	}
	code, seal := post(t, server, "/seal", `{"session":"ks-done"}`)
	if code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, seal)
	}
	server.Close()
	a.stop(&said)

	// a session left open whose receipts are under a key no rotation
	// reaches, planted beside the one under the service's key: the
	// registry holds nothing under that key, so the store's receipts are
	// what the rotation is held to
	_, other, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	unreached := keyIDFor(other.Public().(ed25519.PublicKey))
	serviceKey := keyIDFor(one.publicKey())
	receipts := db.open(t, nil).receipts()
	entries, err := receipts.listEntries("ks-done")
	if err != nil || len(entries) == 0 {
		t.Fatalf("the sealed session's receipts: %v %v", entries, err)
	}
	first, err := receipts.getEntry("ks-done", entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(first, []byte(`"keyId":"`+serviceKey+`"`)) {
		t.Fatalf("the receipt is not under the service's key: %s", first)
	}
	foreign := bytes.Replace(first, []byte(`"keyId":"`+serviceKey+`"`), []byte(`"keyId":"`+unreached+`"`), 1)
	foreign = bytes.ReplaceAll(foreign, []byte(`"ks-done"`), []byte(`"ks-foreign"`))
	if _, err := receipts.makeSeries("ks-foreign"); err != nil {
		t.Fatal(err)
	}
	if err := receipts.createIndexed("ks-foreign", 0, foreign); err != nil {
		t.Fatal(err)
	}
	before := pgRegistryOf(t, db)

	target := pgTestDBBeside(t, db)
	code, stdout, stderr := rotatePg(t, config, target, dir)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "under key id "+unreached+", and no rotation in the registry leads from it") {
		t.Fatalf("a record under an unreached key: %d %q %q", code, stdout, stderr)
	}
	if got := pgRegistryOf(t, db); got != before {
		t.Fatalf("the refusal sealed what was open:\n%s", strings.TrimPrefix(got, before))
	}
	if rows := asOwnerIn(t, db, pgNoScope, `SELECT 1 FROM gateway.rotated`); len(rows.rows) != 0 {
		t.Fatal("the old database is marked rotated")
	}
	if pgHasSchema(t, target) {
		if got := pgRegistryOf(t, target); got != "" {
			t.Fatalf("the new database holds a registry: %q", got)
		}
	}
}
