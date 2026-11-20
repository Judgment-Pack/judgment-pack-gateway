package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// On the PostgreSQL kind, a start holds every scope's series to the key as
// it holds the rows of no scope (ADR-0050): a series of a scope whose first
// receipt is under a key no rotation leads from refuses the start, naming
// the scope and the key.
func TestAPostgresStartHoldsEachScopesSeriesToTheKey(t *testing.T) {
	standInKeyService(t)
	one := mustKeyServiceSigner(t, ksVersion1)
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	_, cfg := ksPgConfig(t, db, dir, ksVersion1, one.publicKey())
	start := func() (*kindStart, error, string) {
		var said bytes.Buffer
		a, err := startOnKind(cfg, testSeed, sealOpenPgSources(t), nil, kindRun{period: pgStartLeasePeriod, every: pgStartLeaseRenewal, stopped: context.Background(), said: &said, signer: one})
		return a, err, said.String()
	}
	a, err, said := start()
	if err != nil {
		t.Fatalf("the instance: %v\n%s", err, said)
	}
	server := httptest.NewServer(a.service.handler())
	for _, call := range [][2]string{
		{"/acquire", `{"session":"ks-scoped","source":"screening-a","scope":"scope-a","arguments":{"q":"x"}}`},
		{"/seal", `{"session":"ks-scoped"}`},
	} {
		if code, got := post(t, server, call[0], call[1]); code != http.StatusOK {
			t.Fatalf("%s %s: %d %v", call[0], call[1], code, got)
		}
	}
	server.Close()
	var stopped bytes.Buffer
	a.stop(&stopped)

	_, other, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	unreached := keyIDFor(other.Public().(ed25519.PublicKey))
	view, err := db.open(t, nil).inScope("scope-a")
	if err != nil {
		t.Fatal(err)
	}
	receipts := view.receipts()
	entries, err := receipts.listEntries("ks-scoped")
	if err != nil || len(entries) == 0 {
		t.Fatalf("the scoped session's receipts: %v %v", entries, err)
	}
	first, err := receipts.getEntry("ks-scoped", entries[0])
	if err != nil {
		t.Fatal(err)
	}
	serviceKey := keyIDFor(one.publicKey())
	if !bytes.Contains(first, []byte(`"keyId":"`+serviceKey+`"`)) {
		t.Fatalf("the receipt is not under the service's key: %s", first)
	}
	foreign := bytes.Replace(first, []byte(`"keyId":"`+serviceKey+`"`), []byte(`"keyId":"`+unreached+`"`), 1)
	foreign = bytes.ReplaceAll(foreign, []byte(`"ks-scoped"`), []byte(`"ks-foreign"`))
	if _, err := receipts.makeSeries("ks-foreign"); err != nil {
		t.Fatal(err)
	}
	if err := receipts.createIndexed("ks-foreign", 0, foreign); err != nil {
		t.Fatal(err)
	}

	a, err, said = start()
	if err == nil {
		a.stop(&stopped)
		t.Fatalf("a start over a scope's series under an unreached key was admitted\n%s", said)
	}
	if !strings.Contains(err.Error(), "scope scope-a: the store holds a receipt that is under key id "+unreached+", and no rotation in the registry leads from it") {
		t.Fatalf("the refusal does not name the scope and the key: %v", err)
	}
}
