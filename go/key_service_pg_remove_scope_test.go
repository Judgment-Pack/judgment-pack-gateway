package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// On the PostgreSQL kind under a key service, gateway store remove-scope
// given --config signs its records under the key version the configuration
// names (ADR-0050): given the seed alone it is refused before anything is
// written, and given the configuration the records are under the service's
// key and the exported store verifies.
func TestAPostgresStoreRemoveScopeSignsThroughTheKeyService(t *testing.T) {
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
	for _, call := range [][2]string{
		{"/acquire", `{"session":"ks-gone","source":"screening-a","scope":"scope-a","arguments":{"q":"x"}}`},
		{"/seal", `{"session":"ks-gone"}`},
		{"/acquire", `{"session":"ks-kept","source":"plain","arguments":{"q":"x"}}`},
		{"/seal", `{"session":"ks-kept"}`},
	} {
		if code, got := post(t, server, call[0], call[1]); code != http.StatusOK {
			t.Fatalf("%s %s: %d %v", call[0], call[1], code, got)
		}
	}
	server.Close()
	a.stop(&said)

	connection := writeConnection(t, db.migrator)
	run := func(signing ...string) (int, string, string) {
		args := append([]string{"--connection-file", connection, "--owner", db.roles.owner, "--runtime", db.roles.runtime}, signing...)
		return runStoreRemoveScope(append(args, "--scope", "scope-a", "--by", "operator-1", "--timeout", "60")...)
	}
	print := db.fingerprint(t)
	if code, stdout, stderr := run("--seed", cfg.seed); code != 1 || stdout != "" || !strings.Contains(stderr, "no rotation in the registry leads from it") {
		t.Fatalf("the seed over a key service's store: %d %q %q", code, stdout, stderr)
	}
	if db.fingerprint(t) != print {
		t.Fatal("the seed's refusal changed the database")
	}

	asked := standIn.requests
	code, stdout, stderr := run("--config", config)
	if code != 0 || strings.Count(stdout, `"kind":"session-removal"`) != 1 || strings.Count(stdout, `"kind":"scope-removal"`) != 1 || standIn.requests <= asked {
		t.Fatalf("store remove-scope through the key service: %d %q %q, %d requests after %d", code, stdout, stderr, standIn.requests, asked)
	}
	if strings.Count(stdout, `"keyId":"`+keyIDFor(one.publicKey())+`"`) != 2 {
		t.Fatalf("the removal records are not under the key service's key: %s", stdout)
	}
	t.Chdir(dir)
	after := filepath.Join(dir, "after")
	if _, err := exportEngine(config, after, nil, ""); err != nil {
		t.Fatalf("export: %v", err)
	}
	if rep, err := verifyWithRegistry(filepath.Join(after, "store"), filepath.Join(after, "registry"), "gateway:test", one.publicKey()); err != nil || !rep.OK {
		t.Fatalf("the store after store remove-scope: %v %+v", err, rep)
	}
}
