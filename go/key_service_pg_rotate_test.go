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
