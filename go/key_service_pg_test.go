package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ksPgConfig is the several-instances configuration of db at engine version
// 36, naming the key service's version and its public key.
func ksPgConfig(t *testing.T, db *pgTestDB, dir string, version string, public ed25519.PublicKey) (string, engineConfig) {
	t.Helper()
	path, _ := instancesPgConfig(t, db, dir, "engine.json", false)
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text = bytes.Replace(text, []byte(`{"engineVersion":"26"`), []byte(`{"engineVersion":"36"`), 1)
	text = bytes.Replace(text, []byte(`"platforms":{}`), []byte(`"signingKeyVersion":"`+version+`","signingPublicKey":"`+hex.EncodeToString(public)+`","platforms":{}`), 1)
	if err := os.WriteFile(path, text, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseEngineConfig(text)
	if err != nil {
		t.Fatal(err)
	}
	return path, cfg
}

// On one PostgreSQL database under a key service, an instance on the key
// version the instances serving sign under is admitted beside them, and one
// on another key version is refused by name, the sentence naming the
// rolling deploy; what the instances store is signed under the service's
// key, not the seed's. Then, every instance stopped, seal-open seals the
// sessions left open under the service's key too: a restart's path.
func TestAPostgresKeyServiceInstanceIsAdmittedOnlyBesideItsKeyVersion(t *testing.T) {
	standInKeyService(t)
	one, two := mustKeyServiceSigner(t, ksVersion1), mustKeyServiceSigner(t, ksVersion2)
	serviceKey := keyIDFor(one.publicKey())
	seedKey := keyIDFor(ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, cfg := ksPgConfig(t, db, dir, ksVersion1, one.publicKey())
	sources := sealOpenPgSources(t)
	var said bytes.Buffer
	run := func(s signer) kindRun {
		return kindRun{period: pgStartLeasePeriod, every: pgStartLeaseRenewal, stopped: context.Background(), said: &said, signer: s}
	}

	a, err := startOnKind(cfg, testSeed, sources, nil, run(one))
	if err != nil {
		t.Fatalf("instance a: %v\n%s", err, said.String())
	}
	stopA := func() { a.stop(&said) }
	b, err := startOnKind(cfg, testSeed, sources, nil, run(one))
	if err != nil {
		stopA()
		t.Fatalf("instance b on the same key version: %v\n%s", err, said.String())
	}
	stopB := func() { b.stop(&said) }
	if c, err := startOnKind(cfg, testSeed, sources, nil, run(two)); err == nil {
		c.stop(&said)
		stopA()
		stopB()
		t.Fatal("an instance on another key version was admitted beside the instances serving")
	} else if !errors.Is(err, errInstanceMismatch) || !strings.Contains(err.Error(), "a rolling deploy that moves the instances to another key version") {
		stopA()
		stopB()
		t.Fatalf("another key version: %v", err)
	}

	serverA := httptest.NewServer(a.service.handler())
	serverB := httptest.NewServer(b.service.handler())
	for _, call := range []struct {
		server *httptest.Server
		body   string
	}{
		{serverA, `{"session":"ks-a","source":"plain","arguments":{"q":"x"}}`},
		{serverB, `{"session":"ks-b","source":"screening-a","scope":"scope-a","arguments":{"q":"x"}}`},
		{serverA, `{"session":"ks-open","source":"plain","arguments":{"q":"x"}}`},
	} {
		code, got := post(t, call.server, "/acquire", call.body)
		if code != http.StatusOK {
			t.Fatalf("%s: %d %v", call.body, code, got)
		}
		if receipt, _ := got["receipt"].(map[string]any); receipt["keyId"] != serviceKey {
			t.Fatalf("%s: the receipt names key id %v, not the service's", call.body, receipt["keyId"])
		}
	}
	if code, got := post(t, serverA, "/seal", `{"session":"ks-a"}`); code != http.StatusOK || got["keyId"] != serviceKey {
		t.Fatalf("the seal: %d %v", code, got)
	}
	serverA.Close()
	serverB.Close()
	stopA()
	stopB()

	var stdout, stderr bytes.Buffer
	if code := cmdSealOpenAt([]string{"--config", config, "--all"}, &stdout, &stderr, nowStamp); code != 0 || stderr.Len() != 0 {
		t.Fatalf("seal-open under the key service: %d %q %q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "ks-b") || !strings.Contains(stdout.String(), "ks-open") || strings.Contains(stdout.String(), "ks-a") {
		t.Fatalf("seal-open sealed: %s", stdout.String())
	}
	log, err := db.open(t, nil).registry().readLog(0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), seedKey) || strings.Count(string(log), serviceKey) < 3 {
		t.Fatalf("the registry is not signed under the service's key alone:\n%s", log)
	}
}
