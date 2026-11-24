package main

// Session labels on the PostgreSQL kind (ADR-0051; session_labels_pg.go;
// migration 0009).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// labelsPgConfig writes, into dir, a configuration of the PostgreSQL kind on
// db at version, in the several-instances mode where several is set, with
// extra appended to its members; it answers the file's path and the
// configuration read.
func labelsPgConfig(t *testing.T, db *pgTestDB, dir, version string, several bool, extra string) (string, engineConfig) {
	t.Helper()
	connection := filepath.Join(dir, "connection")
	if err := os.WriteFile(connection, []byte(pgTestURL(db.runtime)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seedPath := filepath.Join(dir, "gateway.seed")
	if err := os.WriteFile(seedPath, []byte(hex.EncodeToString(testSeed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "decisions"), 0o700); err != nil {
		t.Fatal(err)
	}
	mode := ``
	if several {
		mode = `,"instances":"several"`
	}
	text := `{"engineVersion":"` + version + `","authority":"gateway:test","seed":"` + abs(t, seedPath) + `","storage":{"kind":"postgresql","connection":{"file":"` + abs(t, connection) + `"},"connections":2` + mode + `},` +
		`"decisionRecords":"` + abs(t, dir, "decisions") + `","listen":"127.0.0.1:8787","catalog":"` + abs(t, dir, "catalog") + `","platforms":{}` + extra + `}`
	config := filepath.Join(dir, "engine-"+version+".json")
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseEngineConfig([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return config, cfg
}

// labelsPgServe starts an instance on cfg and serves it; stop ends both,
// once, and the cleanup does where the test did not.
func labelsPgServe(t *testing.T, cfg engineConfig, sources map[string]sourceSpec) (*kindStart, *httptest.Server, func()) {
	t.Helper()
	var said bytes.Buffer
	started, err := startEngineOnKind(cfg, testSeed, sources, nil, &said)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	server := httptest.NewServer(started.service.handler())
	stop := sync.OnceFunc(func() {
		server.Close()
		started.stop(&said)
	})
	t.Cleanup(stop)
	return started, server, stop
}

// pgLabelRowsIn is the series of every label row a transaction of row sees.
func pgLabelRowsIn(t *testing.T, db *pgTestDB, row string) []string {
	t.Helper()
	var got []string
	for _, r := range asOwnerIn(t, db, row, `SELECT series FROM gateway.session_labels ORDER BY label`).rows {
		got = append(got, string(r[0]))
	}
	return got
}

// Two instances on one database, racing on a label's first use in one
// namespace, agree on one id: every record answers the id the row holds,
// and the namespace holds one row.
func TestAPostgresTwoInstancesRacingOnALabelAgreeOnOneID(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	kinds := []*pgKind{db.open(t, nil), db.open(t, nil)}
	const writers = 8
	ids := make([]string, writers)
	errs := make([]error, writers)
	var start, done sync.WaitGroup
	start.Add(1)
	for i := 0; i < writers; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			fresh, err := mintSessionID()
			if err != nil {
				errs[i] = err
				return
			}
			start.Wait()
			ids[i], errs[i] = pgLabels{k: kinds[i%2]}.recordLabel("scope-a", "nightly", fresh)
		}(i)
	}
	start.Done()
	done.Wait()
	for i := range ids {
		if errs[i] != nil || ids[i] != ids[0] || !mintedSessionPattern.MatchString(ids[i]) {
			t.Fatalf("writer %d: %q %v, the first %q", i, ids[i], errs[i], ids[0])
		}
	}
	for _, k := range kinds {
		if got, err := (pgLabels{k: k}).labelSession("scope-a", "nightly"); err != nil || got != ids[0] {
			t.Fatalf("the label read back: %q %v", got, err)
		}
	}
	if got := pgLabelRowsIn(t, db, pgRowScope("scope-a")); !slices.Equal(got, []string{ids[0]}) {
		t.Fatalf("the namespace's rows: %v", got)
	}
}

// An instance that reads sessions by label is refused beside one that reads
// them by id, and the other way round, by name (errInstanceMismatch), by a
// sentence that says to stop every instance and seal first; instances that
// read them one way serve beside one another.
func TestAPostgresInstanceReadingSessionsAnotherWayIsRefusedByName(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	sources := sealOpenPgSources(t)
	_, labelled := labelsPgConfig(t, db, tempDirAt(t, 0o700), labelsVersion, true, "")
	_, named := labelsPgConfig(t, db, tempDirAt(t, 0o700), retentionVersion, true, "")
	start := func(cfg engineConfig) (*kindStart, error) {
		var said bytes.Buffer
		s, err := startEngineOnKind(cfg, testSeed, sources, nil, &said)
		if err == nil {
			t.Cleanup(func() { s.stop(&said) })
		}
		return s, err
	}
	refused := func(err error, way string) {
		t.Helper()
		if !errors.Is(err, errInstanceMismatch) || !strings.Contains(err.Error(), "and this instance "+way) ||
			!strings.Contains(err.Error(), "stop every instance, seal what is open (gateway seal-open --all), and start them all at the one version (ADR-0051)") {
			t.Fatalf("refused: %v", err)
		}
	}
	first, err := start(labelled)
	if err != nil {
		t.Fatal(err)
	}
	_, err = start(named)
	refused(err, "reading the session a request names as its id")
	second, err := start(labelled)
	if err != nil {
		t.Fatalf("labels beside labels: %v", err)
	}
	var said bytes.Buffer
	first.stop(&said)
	second.stop(&said)
	if _, err := start(named); err != nil {
		t.Fatalf("by id, once the instances by label stopped: %v", err)
	}
	_, err = start(labelled)
	refused(err, "reading the session a request names as a label in its scope")
}

// One label in two scopes and in none is three sessions; a transaction of
// one scope reads, and writes, its own namespace's labels alone, even where
// a statement names another; a label not in the namespace /seal names is
// no such session.
func TestAPostgresTwoScopesUseOneLabelAndRowSecurityHoldsTheirLabelsApart(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	_, cfg := labelsPgConfig(t, db, tempDirAt(t, 0o700), labelsVersion, false, "")
	_, server, _ := labelsPgServe(t, cfg, sealOpenPgSources(t))
	ofA, _ := labelAcquire(t, server, "job", "screening-a", "scope-a")
	ofB, _ := labelAcquire(t, server, "job", "screening-b", "scope-b")
	ofNone, _ := labelAcquire(t, server, "job", "plain", "")
	if ofA == ofB || ofA == ofNone || ofB == ofNone {
		t.Fatalf("one label, three namespaces: %s %s %s", ofA, ofB, ofNone)
	}
	if again, index := labelAcquire(t, server, "job", "screening-a", "scope-a"); again != ofA || index != 1 {
		t.Fatalf("the label again in its scope: %s at %v", again, index)
	}
	rows := map[string]string{pgRowScope("scope-a"): ofA, pgRowScope("scope-b"): ofB, pgNoScope: ofNone}
	c := db.runtimeConn(t)
	for row, want := range rows {
		pgInScopeOn(t, c, row, func() {
			if got := pgColumn(t, c, `SELECT series FROM gateway.session_labels`); !slices.Equal(got, []string{want}) {
				t.Errorf("%s reads the labels %v", row, got)
			}
			for other := range rows {
				if other == row {
					continue
				}
				if got := pgColumn(t, c, `SELECT series FROM gateway.session_labels WHERE scope = $1`, other); len(got) != 0 {
					t.Errorf("%s reads %s's labels %v", row, other, got)
				}
			}
		})
	}
	pgInScopeOn(t, c, pgRowScope("scope-a"), func() {
		if _, err := c.exec(`INSERT INTO gateway.session_labels (scope, label, series) VALUES ($1, 'planted', $2)`, pgRowScope("scope-b"), strings.Repeat("a", 32)); err == nil {
			t.Error("a transaction of scope-a wrote a label of scope-b")
		}
	})
	if code, raw := labelSeal(t, server, "job", "scope-b"); code != http.StatusOK || !strings.Contains(string(raw), ofB) {
		t.Fatalf("seal in scope-b: %d %s", code, raw)
	}
	if code, raw := labelSeal(t, server, "elsewhere", "scope-a"); code != http.StatusBadRequest || !strings.Contains(string(raw), "no such session: elsewhere") {
		t.Fatalf("a label not in the namespace: %d %s", code, raw)
	}
}

// gateway sessions reads a namespace's labels on this kind through the
// run-time login, with the gateway serving.
func TestAPostgresGatewaySessionsPrintsANamespacesLabels(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	config, cfg := labelsPgConfig(t, db, tempDirAt(t, 0o700), labelsVersion, false, "")
	_, server, _ := labelsPgServe(t, cfg, sealOpenPgSources(t))
	ofA, _ := labelAcquire(t, server, "job", "screening-a", "scope-a")
	ofA2, _ := labelAcquire(t, server, "audit", "screening-a", "scope-a")
	ofNone, _ := labelAcquire(t, server, "job", "plain", "")
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := cmdSessions(append([]string{"--config", config}, args...), &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, out, errs := run("--scope", "scope-a"); code != 0 || out != "audit "+ofA2+"\njob "+ofA+"\n" {
		t.Fatalf("scope-a: %d %q %q", code, out, errs)
	}
	if code, out, errs := run("--no-scope"); code != 0 || out != "job "+ofNone+"\n" {
		t.Fatalf("no scope: %d %q %q", code, out, errs)
	}
	if code, out, errs := run("--scope", "scope-b"); code != 0 || out != "" {
		t.Fatalf("scope-b: %d %q %q", code, out, errs)
	}
	if code, out, errs := run("--scope", "scope-a", "--label", "job"); code != 0 || out != "job "+ofA+"\n" {
		t.Fatalf("one label: %d %q %q", code, out, errs)
	}
	if code, out, errs := run("--scope", "scope-b", "--label", "job"); code != 1 || out != "" || !strings.Contains(errs, "no label job in the namespace") {
		t.Fatalf("a label of another namespace: %d %q %q", code, out, errs)
	}
}

// gateway store remove-scope takes the scope's labels with its sessions,
// and those of a scope that holds labels and no session, as a label minted
// for a source that failed leaves; a label removed is free, and its next use
// mints a new id. Another scope's label stays.
func TestAPostgresStoreRemoveScopeFreesTheScopesLabels(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	_, cfg := labelsPgConfig(t, db, dir, labelsVersion, false, "")
	sources := sealOpenPgSources(t)
	_, server, stop := labelsPgServe(t, cfg, sources)
	removed, _ := labelAcquire(t, server, "job", "screening-a", "scope-a")
	kept, _ := labelAcquire(t, server, "job", "screening-b", "scope-b")
	if code, raw := labelSeal(t, server, "job", "scope-a"); code != http.StatusOK {
		t.Fatalf("seal: %d %s", code, raw)
	}
	stop()
	connection := writeConnection(t, db.migrator)
	remove := func() (int, string, string) {
		return runStoreRemoveScope("--connection-file", connection, "--owner", db.roles.owner, "--runtime", db.roles.runtime,
			"--seed", filepath.Join(dir, "gateway.seed"), "--scope", "scope-a", "--by", "operator-1", "--timeout", "60")
	}
	if code, stdout, stderr := remove(); code != 0 || !strings.Contains(stderr, "removed 1 session(s), 1 sealed") {
		t.Fatalf("remove-scope: %d %q %q", code, stdout, stderr)
	}
	if got := pgLabelRowsIn(t, db, pgRowScope("scope-a")); len(got) != 0 {
		t.Fatalf("scope-a's labels after the removal: %v", got)
	}
	if got := pgLabelRowsIn(t, db, pgRowScope("scope-b")); !slices.Equal(got, []string{kept}) {
		t.Fatalf("scope-b's labels after the removal: %v", got)
	}

	// a label of a scope that holds no session
	orphan, err := mintSessionID()
	if err != nil {
		t.Fatal(err)
	}
	asOwnerIn(t, db, pgRowScope("scope-a"), `INSERT INTO gateway.session_labels (scope, label, series) VALUES ($1, 'failed-run', $2)`, pgRowScope("scope-a"), orphan)
	if code, stdout, stderr := remove(); code != 0 || !strings.Contains(stderr, "its 1 session label(s), naming no session, are removed") {
		t.Fatalf("remove-scope of labels alone: %d %q %q", code, stdout, stderr)
	}
	if got := pgLabelRowsIn(t, db, pgRowScope("scope-a")); len(got) != 0 {
		t.Fatalf("scope-a's labels after the second removal: %v", got)
	}

	_, server, _ = labelsPgServe(t, cfg, sources)
	if again, index := labelAcquire(t, server, "job", "screening-a", "scope-a"); again == removed || index != 0 {
		t.Fatalf("the label after the removal: %s at %v, the removed session %s", again, index, removed)
	}
	if got := pgLabelRowsIn(t, db, pgRowScope("scope-b")); !slices.Equal(got, []string{kept}) {
		t.Fatalf("the other scope's label moved: %v, not %s", got, kept)
	}
}

// gateway store retain takes a session's label with it; the label is free,
// and its next use mints a new id.
func TestAPostgresStoreRetainFreesTheSessionsLabel(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, cfg := labelsPgConfig(t, db, dir, labelsVersion, false,
		`,"retention":{"window":30,"acknowledgedBy":["`+hex.EncodeToString(retentionAckKey.Public().(ed25519.PublicKey))+`"]}`)
	sources := sealOpenPgSources(t)
	started, server, stop := labelsPgServe(t, cfg, sources)
	removed, _ := labelAcquire(t, server, "job", "screening-a", "scope-a")
	open, _ := labelAcquire(t, server, "open-job", "screening-a", "scope-a")
	if code, raw := labelSeal(t, server, "job", "scope-a"); code != http.StatusOK {
		t.Fatalf("seal: %d %s", code, raw)
	}
	stop()
	pub := started.service.publicKey
	t.Chdir(dir)
	before := filepath.Join(dir, "before")
	if _, err := exportEngine(config, before, nil, ""); err != nil {
		t.Fatalf("export: %v", err)
	}
	s := sealOf(t, filepath.Join(before, "registry"), pub, removed)
	now := sealTime(t, s).Add(31 * 24 * time.Hour)
	var stdout, stderr bytes.Buffer
	code := cmdStoreRetainAt([]string{"--connection-file", writeConnection(t, db.migrator), "--owner", db.roles.owner, "--runtime", db.roles.runtime,
		"--config", config, "--acknowledgments", writeAcks(t, retentionAckLine(retentionAckKey, removed, s.signature, s.finalCount, stampOf(sealTime(t, s).Add(time.Hour)))),
		"--by", "operator-1", "--timeout", "60"}, &stdout, &stderr, fixedStamp(removalStamp), func() time.Time { return now })
	if code != 0 || !strings.Contains(stderr.String(), "removed 1 session(s)") {
		t.Fatalf("retain: %d %q %q", code, stdout.String(), stderr.String())
	}
	if got := pgLabelRowsIn(t, db, pgRowScope("scope-a")); !slices.Equal(got, []string{open}) {
		t.Fatalf("scope-a's labels after retain: %v, the open session %s", got, open)
	}
	_, server, _ = labelsPgServe(t, cfg, sources)
	if again, index := labelAcquire(t, server, "job", "screening-a", "scope-a"); again == removed || index != 0 {
		t.Fatalf("the label after retain: %s at %v, the removed session %s", again, index, removed)
	}
}

// A store remove-scope cut off between the labels and the receipts removes
// nothing: the one transaction rolls back whole, so no label is left naming
// a removed session and no session is left without its label; the rerun
// removes both.
func TestAPostgresARemovalCutOffAfterTheLabelsRollsBackWhole(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	_, cfg := labelsPgConfig(t, db, dir, labelsVersion, false, "")
	sources := sealOpenPgSources(t)
	_, server, stop := labelsPgServe(t, cfg, sources)
	open, _ := labelAcquire(t, server, "open-job", "screening-a", "scope-a")
	stop()
	connection := writeConnection(t, db.migrator)
	remove := func() (int, string, string) {
		return runStoreRemoveScope("--connection-file", connection, "--owner", db.roles.owner, "--runtime", db.roles.runtime,
			"--seed", filepath.Join(dir, "gateway.seed"), "--scope", "scope-a", "--by", "operator-1", "--timeout", "60")
	}
	removalCutOff = func() error { return errors.New("cut off") }
	t.Cleanup(func() { removalCutOff = nil })
	code, stdout, stderr := remove()
	removalCutOff = nil
	if code == 0 || !strings.Contains(stderr, "cut off; nothing was removed") {
		t.Fatalf("the run cut off: %d %q %q", code, stdout, stderr)
	}
	if got := pgLabelRowsIn(t, db, pgRowScope("scope-a")); !slices.Equal(got, []string{open}) {
		t.Fatalf("the labels after a run cut off: %v", got)
	}
	if rows := asOwnerIn(t, db, pgRowScope("scope-a"), `SELECT name FROM gateway.series`); len(rows.rows) != 1 || string(rows.rows[0][0]) != open {
		t.Fatalf("the sessions after a run cut off: %v", rows.rows)
	}
	if code, stdout, stderr := remove(); code != 0 {
		t.Fatalf("the rerun: %d %q %q", code, stdout, stderr)
	}
	if got := pgLabelRowsIn(t, db, pgRowScope("scope-a")); len(got) != 0 {
		t.Fatalf("the labels after the rerun: %v", got)
	}
	_, server, _ = labelsPgServe(t, cfg, sources)
	if again, index := labelAcquire(t, server, "open-job", "screening-a", "scope-a"); again == open || index != 0 {
		t.Fatalf("the label after the rerun: %s at %v, the removed session %s", again, index, open)
	}
}

// The start at labelsVersion on this kind refuses while a session named
// before it is open, naming gateway seal-open --all; once it is sealed the
// start goes on, and a session a labelled instance left open does not
// refuse the next start.
func TestAPostgresTheStartAtLabelsVersionRefusesAnUnlabelledOpenSession(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	olderPath, older := labelsPgConfig(t, db, dir, retentionVersion, false, "")
	_, labelled := labelsPgConfig(t, db, dir, labelsVersion, false, "")
	sources := sealOpenPgSources(t)
	_, server, stop := labelsPgServe(t, older, sources)
	if code, got := post(t, server, "/acquire", `{"session":"before-labels","source":"screening-a","scope":"scope-a","arguments":{"q":"x"}}`); code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, got)
	}
	stop()
	var said bytes.Buffer
	if s, err := startEngineOnKind(labelled, testSeed, sources, nil, &said); err == nil {
		s.stop(&said)
		t.Fatal("the start at labelsVersion went on beside a session open from before it")
	} else if !strings.Contains(err.Error(), "run gateway seal-open --all") || !strings.Contains(err.Error(), "(before-labels)") {
		t.Fatalf("the start's refusal: %v", err)
	}
	// the upgrade: the gateway stopped, gateway seal-open --all, and the
	// start at the new version
	var stdout, stderr bytes.Buffer
	if code := cmdSealOpen([]string{"--config", olderPath, "--all"}, &stdout, &stderr); code != 0 {
		t.Fatalf("seal-open --all: %d %q %q", code, stdout.String(), stderr.String())
	}
	_, server, stop = labelsPgServe(t, labelled, sources)
	labelAcquire(t, server, "left-open", "screening-a", "scope-a")
	stop()
	_, _, stop = labelsPgServe(t, labelled, sources)
	stop()
}

// Migration 9 applies on a database at schema version 8 with every
// instance stopped: a row of the lease from before reads labels false, and
// the kind opens on it and keeps labels.
func TestAPostgresStoreAtSchemaEightMigratesToSessionLabels(t *testing.T) {
	db := newPgTestDB(t)
	set := pgShippedMigrations()
	if len(set.versions) < 9 || set.versions[8].name != "0009_session_labels.sql" {
		t.Fatalf("the shipped schema has %d versions: the test names version 9 as the session labels'", len(set.versions))
	}
	older := pgMigrationSet{versions: set.versions[:8], grants: pgGrantsOfVersion(t, set.grants, 8)}
	if applied, err := migratePostgres(db.migrator, older, db.roles, time.Minute); err != nil || len(applied) != 8 {
		t.Fatalf("schema version 8: %v %v", applied, err)
	}
	asOwnerIn(t, db, pgNoScope, `INSERT INTO gateway.start_lease (holder, several, key_id, authority, renewed, expires)
		SELECT $1, true, $2, 'gateway:test', n.now - interval '1 minute', n.now - interval '1 second' FROM (SELECT pg_catalog.clock_timestamp() AS now) n`,
		newTestLeaseHolder(t), strings.Repeat("a", 32))
	if applied, err := migratePostgres(db.migrator, set, db.roles, time.Minute); err != nil || !slices.Equal(applied, pgShippedFrom(9)) {
		t.Fatalf("the migration from version 8: %v %v", applied, err)
	}
	rows := pgTestQuery(t, db.runtime, `SELECT labels FROM gateway.start_lease`)
	if len(rows.rows) != 1 {
		t.Fatalf("the lease's rows: %v", rows.rows)
	}
	if labels, ok := pgBool(rows.rows[0][0]); !ok || labels {
		t.Fatalf("a row from before reads labels %q", rows.rows[0][0])
	}
	kind := db.open(t, nil)
	fresh, err := mintSessionID()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := (pgLabels{k: kind}).recordLabel("", "job", fresh); err != nil || got != fresh {
		t.Fatalf("a label on the migrated database: %q %v", got, err)
	}
}

// An acquisition refused at its admission -- the signer's gate closed --
// leaves no label; the label's use once admission reopens mints its
// session.
func TestAPostgresARefusedAcquisitionLeavesNoLabel(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	_, cfg := labelsPgConfig(t, db, tempDirAt(t, 0o700), labelsVersion, false, "")
	started, server, _ := labelsPgServe(t, cfg, sealOpenPgSources(t))
	started.service.closeAdmission()
	if code, got := post(t, server, "/acquire", `{"session":"refused-job","source":"screening-a","scope":"scope-a","arguments":{"q":"x"}}`); code == http.StatusOK {
		t.Fatalf("an acquisition through a closed gate: %d %v", code, got)
	}
	if got := pgLabelRowsIn(t, db, pgRowScope("scope-a")); len(got) != 0 {
		t.Fatalf("a refused acquisition left the labels %v", got)
	}
	started.service.openAdmission()
	if _, index := labelAcquire(t, server, "refused-job", "screening-a", "scope-a"); index != 0 {
		t.Fatalf("the label once admitted: at %v", index)
	}
}

// A minted id that a label of the namespace already names, whose session
// holds no receipt yet, is minted again on the PostgreSQL kind too: two
// labels never name one session.
func TestAPostgresAMintedIDALabelNamesAlreadyIsMintedAgain(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	_, cfg := labelsPgConfig(t, db, tempDirAt(t, 0o700), labelsVersion, false, "")
	started, server, _ := labelsPgServe(t, cfg, sealOpenPgSources(t))
	taken, err := mintSessionID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := started.service.labels.recordLabel("scope-a", "first", taken); err != nil {
		t.Fatal(err)
	}
	ids := []string{taken}
	started.service.mintID = func() (string, error) {
		if len(ids) > 0 {
			id := ids[0]
			ids = ids[1:]
			return id, nil
		}
		return mintSessionID()
	}
	if id, _ := labelAcquire(t, server, "second", "screening-a", "scope-a"); id == taken {
		t.Fatalf("the second label names the first label's session %s", id)
	}
	if got := pgLabelRowsIn(t, db, pgRowScope("scope-a")); len(got) != 2 {
		t.Fatalf("the labels kept: %v", got)
	}
}
