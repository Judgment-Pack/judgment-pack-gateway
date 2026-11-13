package main

// The start lease (store_pg_lease.go): one instance serves a database.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestLeaseHolder(t *testing.T) string {
	t.Helper()
	holder, err := newStartLeaseHolder()
	if err != nil {
		t.Fatal(err)
	}
	return holder
}

// pgWriteOne is a write of the store contract: a blob of its own.
func pgWriteOne(k *pgKind, text string) error {
	_, err := k.artifacts().putBlob([]byte(text))
	return err
}

func pgBlobHeld(t *testing.T, k *pgKind, text string) bool {
	t.Helper()
	names, err := k.artifacts().listBlobs()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(text))
	return contains(names, "sha256:"+hex.EncodeToString(sum[:]))
}

// A second instance is refused the lease, by name and naming the holder,
// while the first's is live; a released lease is taken at once; and the
// instance that released it writes nothing more.
func TestThePostgresStartLeaseAdmitsOneInstanceAtATime(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	first, second := db.open(t, nil), db.open(t, nil)
	one, two := newTestLeaseHolder(t), newTestLeaseHolder(t)
	lease, err := first.takeStartLease(one, pgStartLeasePeriod, pgStartLeaseRenewal)
	if err != nil {
		t.Fatalf("the first take: %v", err)
	}
	if err := pgWriteOne(first, "held"); err != nil {
		t.Fatalf("a write under the lease: %v", err)
	}
	_, err = second.takeStartLease(two, pgStartLeasePeriod, pgStartLeaseRenewal)
	if !errors.Is(err, errStartLeaseHeld) || !strings.Contains(err.Error(), one) || !strings.Contains(err.Error(), "One instance per database") {
		t.Fatalf("a second take while the first's lease lives: %v", err)
	}
	if err := lease.renew(); err != nil {
		t.Fatalf("a renewal of a live lease: %v", err)
	}
	if err := lease.release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := second.takeStartLease(two, pgStartLeasePeriod, pgStartLeaseRenewal); err != nil {
		t.Fatalf("a take once the first released its lease: %v", err)
	}
	if err := pgWriteOne(first, "after"); !errors.Is(err, errStartLeaseLost) {
		t.Fatalf("a write of the instance that released its lease: %v", err)
	}
	if pgBlobHeld(t, second, "after") || !pgBlobHeld(t, second, "held") {
		t.Fatal("the fenced write landed, or the one under the lease did not")
	}
	if err := lease.renew(); !errors.Is(err, errStartLeaseLost) {
		t.Fatalf("a renewal of a lease another instance holds: %v", err)
	}
	if err := pgWriteOne(second, "second"); err != nil {
		t.Fatalf("a write of the instance that holds the lease: %v", err)
	}
}

// A crashed instance's lease -- never renewed nor released -- expires by
// the database's clock, and the next instance takes it; the crashed
// instance's writes and renewals are refused from then on.
func TestThePostgresStartLeaseOfACrashedInstanceExpires(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	first, second := db.open(t, nil), db.open(t, nil)
	one, two := newTestLeaseHolder(t), newTestLeaseHolder(t)
	period := 1500 * time.Millisecond
	lease, err := first.takeStartLease(one, period, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	taken := time.Now()
	if _, err := second.takeStartLease(two, period, 500*time.Millisecond); !errors.Is(err, errStartLeaseHeld) {
		t.Fatalf("a take while the lease lives: %v", err)
	}
	time.Sleep(time.Until(taken.Add(period + 300*time.Millisecond)))
	if _, err := second.takeStartLease(two, pgStartLeasePeriod, pgStartLeaseRenewal); err != nil {
		t.Fatalf("a take once the lease expired: %v", err)
	}
	if err := lease.renew(); !errors.Is(err, errStartLeaseLost) {
		t.Fatalf("a renewal of an expired lease: %v", err)
	}
	if err := pgWriteOne(first, "late"); !errors.Is(err, errStartLeaseLost) {
		t.Fatalf("a write of the instance whose lease expired: %v", err)
	}
	// an expired lease, not yet taken, refuses its holder's writes too
	third := db.open(t, nil)
	db.asOwner(t, "DELETE FROM gateway.start_lease")
	expired, err := third.takeStartLease(newTestLeaseHolder(t), period, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(period + 300*time.Millisecond)
	if err := pgWriteOne(third, "expired"); !errors.Is(err, errStartLeaseLost) {
		t.Fatalf("a write after the lease expired: %v", err)
	}
	if err := expired.renew(); !errors.Is(err, errStartLeaseLost) {
		t.Fatalf("a renewal after the lease expired: %v", err)
	}
}

// A loss the lease's keeper reports stops the service, which exits 1.
func TestALostStartLeaseStopsTheService(t *testing.T) {
	service, err := newGatewayServiceOn(newMemoryKind(nil), testSeed, "gateway:test", map[string]sourceSpec{})
	if err != nil {
		t.Fatal(err)
	}
	keep := func(ctx context.Context, lost func(error)) {
		select {
		case <-time.After(200 * time.Millisecond):
			lost(fmt.Errorf("%w: gone", errStartLeaseLost))
		case <-ctx.Done():
		}
	}
	code := make(chan int, 1)
	go func() { code <- serveEngineService(service, engineConfig{listen: "127.0.0.1:0"}, nil, keep) }()
	select {
	case got := <-code:
		if got != 1 {
			t.Fatalf("a service whose lease was lost exits %d", got)
		}
	case <-time.After(10 * time.Second):
		service.cancel()
		<-code
		t.Fatal("a service whose lease was lost keeps serving")
	}
}

// A takeover waits for a write that holds the lease to end, so no write of
// the old holder lands after the new holder's start; a renewal waits for
// none of the instance's own writes.
func TestThePostgresTakeoverWaitsForAWriteThatHoldsTheLease(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	first, second := db.open(t, nil), db.open(t, nil)
	period := 1500 * time.Millisecond
	lease, err := first.takeStartLease(newTestLeaseHolder(t), period, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	entered, hold, wrote := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		wrote <- first.transact(pgWriteCommitted, func(tx pgTx) error {
			close(entered)
			<-hold
			return nil
		})
	}()
	<-entered
	start := time.Now()
	if err := lease.renew(); err != nil || time.Since(start) > time.Second {
		t.Fatalf("a renewal beside the instance's own write: %v after %s", err, time.Since(start))
	}
	// the renewal moved the expiry: wait it out from there
	time.Sleep(time.Until(start.Add(period + 300*time.Millisecond)))
	took := make(chan error, 1)
	go func() {
		_, err := second.takeStartLease(newTestLeaseHolder(t), pgStartLeasePeriod, pgStartLeaseRenewal)
		took <- err
	}()
	select {
	case err := <-took:
		close(hold)
		t.Fatalf("a takeover beside a write that holds the lease did not wait: %v", err)
	case <-time.After(700 * time.Millisecond):
	}
	close(hold)
	if err := <-wrote; err != nil {
		t.Fatalf("the write that held the lease: %v", err)
	}
	if err := <-took; err != nil {
		t.Fatalf("the takeover once the write ended: %v", err)
	}
	if err := pgWriteOne(first, "late"); !errors.Is(err, errStartLeaseLost) {
		t.Fatalf("a write after the takeover: %v", err)
	}
}

// keep reports a lease another instance took, and a lease it cannot renew
// before less than one interval of it is certainly left: while the
// database still holds it for this instance.
func TestThePostgresStartLeaseKeepStopsBeforeTheLeaseIsGone(t *testing.T) {
	t.Run("taken by another", func(t *testing.T) {
		db := newPgTestDB(t)
		db.migrate(t)
		kind := db.open(t, nil)
		lease, err := kind.takeStartLease(newTestLeaseHolder(t), 5*time.Second, 200*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		lost := make(chan error, 1)
		go lease.keep(t.Context(), func(err error) { lost <- err })
		time.Sleep(500 * time.Millisecond)
		select {
		case err := <-lost:
			t.Fatalf("a live lease reported lost: %v", err)
		default:
		}
		pgTestQuery(t, db.runtime, "UPDATE gateway.start_lease SET holder = $1", newTestLeaseHolder(t))
		select {
		case err := <-lost:
			if !errors.Is(err, errStartLeaseLost) {
				t.Fatalf("the loss: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("a lease another instance took is not reported")
		}
	})
	t.Run("not renewed", func(t *testing.T) {
		db := newPgTestDB(t)
		db.migrate(t)
		kind := db.open(t, nil)
		period, every := 2*time.Second, 500*time.Millisecond
		sent := time.Now()
		lease, err := kind.takeStartLease(newTestLeaseHolder(t), period, every)
		if err != nil {
			t.Fatal(err)
		}
		// the renewal fails as a database refusing it would, while the row
		// is still this instance's
		db.asOwner(t, "REVOKE UPDATE ON gateway.start_lease FROM "+db.roles.runtime)
		lost := make(chan error, 1)
		go lease.keep(t.Context(), func(err error) { lost <- err })
		select {
		case err := <-lost:
			at := time.Now()
			if !errors.Is(err, errStartLeaseLost) || !strings.Contains(err.Error(), "could not be renewed") {
				t.Fatalf("the loss: %v", err)
			}
			if !at.Before(sent.Add(period)) {
				t.Fatalf("the loss is reported %s after the take, when the lease may already be another's", at.Sub(sent))
			}
			if at.Before(sent.Add(period - every - every/2)) {
				t.Fatalf("the loss is reported %s after the take, while more than one interval of the lease is left", at.Sub(sent))
			}
		case <-time.After(period + 2*time.Second):
			t.Fatal("a lease that cannot be renewed is not reported")
		}
	})
}

// pgEngineStart is serve --config's configuration on the PostgreSQL kind,
// the run-time login's connection string in a file.
func pgEngineStart(t *testing.T, db *pgTestDB) engineConfig {
	t.Helper()
	dir := tempDirAt(t, 0o700)
	connection := filepath.Join(dir, "connection")
	if err := os.WriteFile(connection, []byte(pgTestURL(db.runtime)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	records := filepath.Join(dir, "decisions")
	if err := os.Mkdir(records, 0o700); err != nil {
		t.Fatal(err)
	}
	text := `{"engineVersion":"24","authority":"gateway:test","seed":"` + abs(t, dir, "gateway.seed") + `","storage":{"kind":"postgresql","connection":{"file":"` + abs(t, connection) + `"},"connections":2},` +
		`"decisionRecords":"` + abs(t, records) + `","listen":"127.0.0.1:8787","catalog":"` + abs(t, dir, "catalog") + `","platforms":{}}`
	cfg, err := parseEngineConfig([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// serve --config's start on the PostgreSQL kind is refused, by name, while
// another instance serves the database, and is admitted once that instance
// stopped cleanly; neither names the connection string.
func TestThePostgresSecondInstanceIsRefusedItsStartUntilTheFirstStops(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	cfg := pgEngineStart(t, db)
	var said bytes.Buffer
	first, err := startEngineOnKind(cfg, testSeed, map[string]sourceSpec{}, nil, &said)
	if err != nil {
		t.Fatalf("the first start: %v", err)
	}
	if !strings.Contains(said.String(), "holds the start lease, which runs 30s from each renewal by the database's clock and is renewed every 10s") {
		t.Fatalf("the start names no lease: %s", said.String())
	}
	if _, err := startEngineOnKind(cfg, testSeed, map[string]sourceSpec{}, nil, &said); !errors.Is(err, errStartLeaseHeld) {
		first.stop(&said)
		t.Fatalf("a second start while the first serves: %v", err)
	} else {
		said.WriteString(err.Error())
	}
	first.stop(&said)
	again, err := startEngineOnKind(cfg, testSeed, map[string]sourceSpec{}, nil, &said)
	if err != nil {
		t.Fatalf("a start once the first stopped: %v", err)
	}
	again.stop(&said)
	if strings.Contains(said.String(), db.runtime.password) || strings.Contains(said.String(), hex.EncodeToString(testSeed)) {
		t.Fatalf("the start names a secret: %s", said.String())
	}
	if rows := pgTestQuery(t, db.runtime, "SELECT holder FROM gateway.start_lease"); len(rows.rows) != 0 {
		t.Fatal("a clean stop left its lease")
	}
}
