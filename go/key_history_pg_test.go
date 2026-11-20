package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"
)

// On the PostgreSQL kind, every instance serving one database answers the
// key history of the one registry they share, read at each request: a store
// that has not rotated answers the seed's key alone, in force, with seals
// in the registry passed over, and the two instances answer the same bytes.
func TestAPostgresKeyHistoryIsServedByEveryInstanceOfOneRegistry(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	_, cfg := instancesPgConfig(t, db, dir, "engine.json", false)
	sources := sealOpenPgSources(t)
	var said bytes.Buffer
	run := kindRun{period: pgStartLeasePeriod, every: pgStartLeaseRenewal, stopped: context.Background(), said: &said}
	a, err := startOnKind(cfg, testSeed, sources, nil, run)
	if err != nil {
		t.Fatalf("instance a: %v\n%s", err, said.String())
	}
	defer a.stop(&said)
	b, err := startOnKind(cfg, testSeed, sources, nil, run)
	if err != nil {
		t.Fatalf("instance b: %v\n%s", err, said.String())
	}
	defer b.stop(&said)
	if _, err := a.service.acquire("pg-history", "plain", vString("pg-history"), nil); err != nil {
		t.Fatal(err)
	}
	mustSeal(t, a.service, "pg-history")
	seedKey := ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)
	entriesA, bodyA := historyPinned(t, a.service, seedKey)
	wantKeys(t, entriesA, []ed25519.PublicKey{seedKey}, nil)
	_, bodyB := historyPinned(t, b.service, seedKey)
	if !bytes.Equal(bodyA, bodyB) {
		t.Fatalf("two instances of one registry answer two histories:\n%s\n%s", bodyA, bodyB)
	}
	if code, _ := askKeyHistory(t, b.service); code != http.StatusOK {
		t.Fatalf("instance b: %d", code)
	}
}
