package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rkStore is a store on a test database whose rotations the tests make: the
// seed's configuration, and one naming each key version of the stand-in
// key service.
type rkStore struct {
	db         *pgTestDB
	dir        string
	connection string // the migration login's
	seed       string
	versions   map[string]string // a key version -> its configuration
	cfgs       map[string]engineConfig
	sources    map[string]sourceSpec
	said       bytes.Buffer
}

func newRkStore(t *testing.T) *rkStore {
	t.Helper()
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	s := &rkStore{db: db, dir: dir, versions: map[string]string{}, cfgs: map[string]engineConfig{}, sources: sealOpenPgSources(t)}
	var cfg engineConfig
	s.seed, cfg = instancesPgConfig(t, db, dir, "engine.json", false)
	s.cfgs[""] = cfg
	text, err := os.ReadFile(s.seed)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{ksVersion1, ksVersion2} {
		public := mustKeyServiceSigner(t, version).publicKey()
		keyed := bytes.Replace(text, []byte(`{"engineVersion":"26"`), []byte(`{"engineVersion":"36"`), 1)
		keyed = bytes.Replace(keyed, []byte(`"platforms":{}`), []byte(`"signingKeyVersion":"`+version+`","signingPublicKey":"`+hex.EncodeToString(public)+`","platforms":{}`), 1)
		path := filepath.Join(dir, "engine-"+version[strings.LastIndex(version, "/")+1:]+".json")
		if err := os.WriteFile(path, keyed, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := parseEngineConfig(keyed)
		if err != nil {
			t.Fatal(err)
		}
		s.versions[version], s.cfgs[version] = path, cfg
	}
	s.connection = writeConnection(t, db.migrator)
	return s
}

// rotate runs gateway store rotate-key under the configuration naming
// version, with extra arguments.
func (s *rkStore) rotate(t *testing.T, version string, extra ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	args := append([]string{"--connection-file", s.connection, "--owner", s.db.roles.owner, "--runtime", s.db.roles.runtime,
		"--config", s.versions[version], "--timeout", "60"}, extra...)
	code := cmdStoreRotateKeyAt(args, &stdout, &stderr, nowStamp)
	return code, stdout.String(), stderr.String()
}

// rotateAt is rotate stamped at.
func (s *rkStore) rotateAt(t *testing.T, at, version string, extra ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	args := append([]string{"--connection-file", s.connection, "--owner", s.db.roles.owner, "--runtime", s.db.roles.runtime,
		"--config", s.versions[version], "--timeout", "60"}, extra...)
	code := cmdStoreRotateKeyAt(args, &stdout, &stderr, func() string { return at })
	return code, stdout.String(), stderr.String()
}

// from names a key version as the key rotated from.
func rkFrom(t *testing.T, version string) []string {
	return []string{"--from-key-version", version, "--from-public-key", hex.EncodeToString(mustKeyServiceSigner(t, version).publicKey())}
}

func (s *rkStore) registry(t *testing.T) []byte {
	t.Helper()
	data, err := s.db.open(t, nil).registry().readLog(0)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// start starts an instance under the configuration naming version ("" the
// seed's), signing through sig (nil, the seed).
func (s *rkStore) start(t *testing.T, version string, sig signer) *kindStart {
	t.Helper()
	k, err := startOnKind(s.cfgs[version], testSeed, s.sources, nil, kindRun{period: pgStartLeasePeriod, every: pgStartLeaseRenewal, stopped: context.Background(), said: &s.said, signer: sig})
	if err != nil {
		t.Fatalf("the start under %q: %v\n%s", version, err, s.said.String())
	}
	return k
}

// call acquires into session, sealing it where seal is set, and answers
// the receipt's keyId.
func rkCall(t *testing.T, server *httptest.Server, session, source string, seal bool) string {
	t.Helper()
	body := `{"session":"` + session + `","source":"` + source + `","arguments":{"q":"x"}}`
	if source == "screening-a" {
		body = `{"session":"` + session + `","source":"screening-a","scope":"scope-a","arguments":{"q":"x"}}`
	}
	code, got := post(t, server, "/acquire", body)
	if code != http.StatusOK {
		t.Fatalf("%s: %d %v", body, code, got)
	}
	if seal {
		if code, got := post(t, server, "/seal", `{"session":"`+session+`"}`); code != http.StatusOK {
			t.Fatalf("seal %s: %d %v", session, code, got)
		}
	}
	receipt, _ := got["receipt"].(map[string]any)
	keyID, _ := receipt["keyId"].(string)
	return keyID
}

// history is the key ids /publickey/history lists, the history checked
// from the seed's key.
func rkHistory(t *testing.T, server *httptest.Server) []string {
	t.Helper()
	resp, err := http.Get(server.URL + keyHistoryRoute)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	doc, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d %s", keyHistoryRoute, resp.StatusCode, doc)
	}
	entries, err := checkKeyHistory(doc, edPin(ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatalf("the key history does not hold: %v\n%s", err, doc)
	}
	var ids []string
	for _, e := range entries {
		ids = append(ids, e.keyID)
	}
	return ids
}

// verifies exports the store under the configuration naming version and
// verifies it from the seed's key, the first key.
func (s *rkStore) verifies(t *testing.T, version, name string) {
	t.Helper()
	out := filepath.Join(s.dir, name)
	t.Chdir(s.dir)
	if _, err := exportEngine(s.versions[version], out, nil, ""); err != nil {
		t.Fatalf("export: %v", err)
	}
	rep, err := verifyWithRegistry(filepath.Join(out, "store"), filepath.Join(out, "registry"), "gateway:test", ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))
	if err != nil || !rep.OK {
		t.Fatalf("the store does not verify from the seed's key: %v %+v", err, rep)
	}
}

// refused holds a run to its refusal, sentence and all, with the registry
// as it was.
func (s *rkStore) refused(t *testing.T, what, want string, code int, stdout, stderr string, before []byte) {
	t.Helper()
	if code != 1 || stdout != "" || !strings.Contains(stderr, want) || !strings.Contains(stderr, "nothing was changed") {
		t.Fatalf("%s: %d %q %q", what, code, stdout, stderr)
	}
	if !bytes.Equal(s.registry(t), before) {
		t.Fatalf("%s: the registry changed", what)
	}
}

// On the PostgreSQL kind, gateway store rotate-key moves a store from the
// seed to a key service's key version, and from that version to the next
// (SPEC.md §3b; ADR-0050, decision 3(a)). It refuses while a session
// holding a receipt is open, a key rotated from that is not the key in
// force, a next key that is the key in force, a signature that does not
// verify, and a record that would not walk to the next key, the registry
// unchanged each time. After each rotation every instance starts under the
// next key, two beside one another; /publickey/history lists every key;
// and the store verifies from the seed's key.
func TestAPostgresStoreRotateKeyMovesTheSeedToAKeyServiceAndOn(t *testing.T) {
	standIn := standInKeyService(t)
	one, two := mustKeyServiceSigner(t, ksVersion1), mustKeyServiceSigner(t, ksVersion2)
	seedKey := keyIDFor(ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))
	oneKey, twoKey := keyIDFor(one.publicKey()), keyIDFor(two.publicKey())
	s := newRkStore(t)

	a := s.start(t, "", nil)
	server := httptest.NewServer(a.service.handler())
	if got := rkCall(t, server, "rk-sealed", "plain", true); got != seedKey {
		t.Fatalf("the seed's receipt names %s", got)
	}
	rkCall(t, server, "rk-open", "screening-a", false)
	server.Close()
	a.stop(&s.said)

	before := s.registry(t)
	code, stdout, stderr := s.rotate(t, ksVersion1)
	s.refused(t, "an open session", "session rk-open holds a receipt and is not sealed", code, stdout, stderr, before)
	// a key version named as the key rotated from that the store's history
	// is not under
	code, stdout, stderr = s.rotate(t, ksVersion1, rkFrom(t, ksVersion2)...)
	s.refused(t, "the key rotated from is another key version", "no rotation in the registry leads from it", code, stdout, stderr, before)

	var sealOut, sealErr bytes.Buffer
	if code := cmdSealOpenAt([]string{"--config", s.seed, "--all"}, &sealOut, &sealErr, nowStamp); code != 0 || !strings.Contains(sealOut.String(), "rk-open") {
		t.Fatalf("seal-open under the seed: %d %q %q", code, sealOut.String(), sealErr.String())
	}
	before = s.registry(t)
	standIn.set(func(k *keyServiceStandIn) { k.signBy = ksKey("another") })
	code, stdout, stderr = s.rotate(t, ksVersion1)
	s.refused(t, "a key-continuation signature that does not verify", "does not verify under the gateway's key", code, stdout, stderr, before)
	standIn.set(func(k *keyServiceStandIn) { k.signBy = nil })

	// the seed to key version 1
	code, stdout, stderr = s.rotate(t, ksVersion1)
	if code != 0 || strings.Count(stdout, "\n") != 2 || !strings.Contains(stdout, `"kind":"key-rotation"`) || !strings.Contains(stdout, `"kind":"key-continuation"`) ||
		!strings.Contains(stderr, "rotation 1: key "+seedKey+" rotated to key "+oneKey) {
		t.Fatalf("the seed to key version 1: %d %q %q", code, stdout, stderr)
	}
	if got := s.registry(t); !bytes.Equal(got, append(bytes.Clone(before), stdout...)) {
		t.Fatalf("the registry is not the one before with the record printed at its end:\n%s", got)
	}
	rotated := s.registry(t)
	if _, err := engineWalk(rotated, edKey(one.publicKey())); err != nil {
		t.Fatalf("the registry does not walk to key version 1: %v", err)
	}
	// run again, it finds the rotation made
	if code, stdout, stderr := s.rotate(t, ksVersion1); code != 0 || stdout != "" || !strings.Contains(stderr, "the registry's walk already ends at this rotation, rotation 1 from key "+seedKey+" to key "+oneKey+", which may be an earlier run's: nothing was changed") || !bytes.Equal(s.registry(t), rotated) {
		t.Fatalf("a second run: %d %q %q", code, stdout, stderr)
	}
	code, stdout, stderr = s.rotate(t, ksVersion1, rkFrom(t, ksVersion1)...)
	s.refused(t, "the next key is the key in force", "the next key, key id "+oneKey+", is the key in force already", code, stdout, stderr, rotated)
	// the seed's configuration is refused now: the walk ends at version 1
	if _, err := startOnKind(s.cfgs[""], testSeed, s.sources, nil, kindRun{period: pgStartLeasePeriod, every: pgStartLeaseRenewal, stopped: context.Background(), said: &s.said}); err == nil {
		t.Fatal("the seed started after the rotation from it")
	}

	// every instance starts under version 1, two beside one another
	b, c := s.start(t, ksVersion1, one), s.start(t, ksVersion1, one)
	server = httptest.NewServer(b.service.handler())
	if got := rkCall(t, server, "rk-one", "plain", true); got != oneKey {
		t.Fatalf("the receipt under version 1 names %s", got)
	}
	if got := strings.Join(rkHistory(t, server), " "); got != seedKey+" "+oneKey {
		t.Fatalf("the key history after the first rotation: %s", got)
	}
	server.Close()
	b.stop(&s.said)
	c.stop(&s.said)
	s.verifies(t, ksVersion1, "after-one")

	// version 1 to version 2
	before = s.registry(t)
	code, stdout, stderr = s.rotate(t, ksVersion2)
	s.refused(t, "the seed named as the key rotated from", "the registry's walk ends at key id "+oneKey+", not at the key rotated from, key id "+seedKey, code, stdout, stderr, before)
	code, stdout, stderr = s.rotate(t, ksVersion2, rkFrom(t, ksVersion1)...)
	if code != 0 || !strings.Contains(stderr, "rotation 2: key "+oneKey+" rotated to key "+twoKey) || !bytes.Equal(s.registry(t), append(bytes.Clone(before), stdout...)) {
		t.Fatalf("version 1 to version 2: %d %q %q", code, stdout, stderr)
	}
	rotated = s.registry(t)
	// the seed named again as the key rotated from: version 2 is in force,
	// rotated to from version 1, not from the seed
	code, stdout, stderr = s.rotate(t, ksVersion2)
	s.refused(t, "the next key is the key in force, rotated to from another", "the next key, key id "+twoKey+", is the key in force already", code, stdout, stderr, rotated)
	// back to a key the registry rotated from: the record does not walk
	code, stdout, stderr = s.rotate(t, ksVersion1, rkFrom(t, ksVersion2)...)
	s.refused(t, "a rotation back to version 1", "the rotation's record would not walk to the next key", code, stdout, stderr, rotated)

	d := s.start(t, ksVersion2, two)
	server = httptest.NewServer(d.service.handler())
	if got := rkCall(t, server, "rk-two", "screening-a", true); got != twoKey {
		t.Fatalf("the receipt under version 2 names %s", got)
	}
	if got := strings.Join(rkHistory(t, server), " "); got != seedKey+" "+oneKey+" "+twoKey {
		t.Fatalf("the key history after the second rotation: %s", got)
	}
	server.Close()
	d.stop(&s.said)
	s.verifies(t, ksVersion2, "after-two")
}

// gateway store rotate-key is refused while an instance's start lease is
// live, by the sentence every command that holds every row of the lease
// says, and writes nothing.
func TestAPostgresStoreRotateKeyIsRefusedWhileAnInstanceServes(t *testing.T) {
	standInKeyService(t)
	s := newRkStore(t)
	a := s.start(t, "", nil)
	server := httptest.NewServer(a.service.handler())
	rkCall(t, server, "rk-sealed", "plain", true)
	server.Close()
	before := s.registry(t)
	code, stdout, stderr := s.rotate(t, ksVersion1)
	a.stop(&s.said)
	if !strings.Contains(stderr, "start-lease-held") {
		t.Fatalf("not the lease's refusal: %q", stderr)
	}
	s.refused(t, "an instance serving", "stop the gateway, then rotate-key", code, stdout, stderr, before)
}

// A rotation stamped before the key history's last rotation, a host whose
// clock is behind, is refused before the COMMIT, the registry unchanged:
// the registry is append-only, and /publickey/history would refuse the
// history for good (SPEC.md §3e). A key rotated from named by a well-formed
// public key that is not its version's is refused the same way.
func TestAPostgresStoreRotateKeyRefusesARotationBeforeTheHistorysLast(t *testing.T) {
	standInKeyService(t)
	s := newRkStore(t)
	a := s.start(t, "", nil)
	server := httptest.NewServer(a.service.handler())
	rkCall(t, server, "rk-sealed", "plain", true)
	server.Close()
	a.stop(&s.said)
	if code, stdout, stderr := s.rotateAt(t, "2026-12-01T12:00:00Z", ksVersion1); code != 0 {
		t.Fatalf("the seed to key version 1: %d %q %q", code, stdout, stderr)
	}
	before := s.registry(t)
	code, stdout, stderr := s.rotateAt(t, "2026-12-01T11:59:59Z", ksVersion2, rkFrom(t, ksVersion1)...)
	want := "the rotation's rotatedAt 2026-12-01T11:59:59Z is before the key history's last rotation 2026-12-01T12:00:00Z; correct this host's clock and run again; nothing was written"
	if code != 1 || stdout != "" || !strings.Contains(stderr, want) || !bytes.Equal(s.registry(t), before) {
		t.Fatalf("a rotation stamped before the last: %d %q %q", code, stdout, stderr)
	}
	wrong := []string{"--from-key-version", ksVersion1, "--from-public-key", hex.EncodeToString(mustKeyServiceSigner(t, ksVersion2).publicKey())}
	code, stdout, stderr = s.rotateAt(t, "2026-12-01T12:00:01Z", ksVersion2, wrong...)
	if code != 1 || stdout != "" || !bytes.Equal(s.registry(t), before) {
		t.Fatalf("a key rotated from under another public key: %d %q %q", code, stdout, stderr)
	}
	if code, stdout, stderr := s.rotateAt(t, "2026-12-01T12:00:00Z", ksVersion2, rkFrom(t, ksVersion1)...); code != 0 {
		t.Fatalf("a rotation in the same second as the last: %d %q %q", code, stdout, stderr)
	}
}

// A COMMIT whose answer did not arrive is settled by a rerun: where it did
// not commit, the rerun rotates; where it did, the rerun finds the record
// whole and changes nothing.
func TestAPostgresStoreRotateKeyRerunSettlesAnUncertainCommit(t *testing.T) {
	standInKeyService(t)
	s := newRkStore(t)
	a := s.start(t, "", nil)
	server := httptest.NewServer(a.service.handler())
	rkCall(t, server, "rk-sealed", "plain", true)
	server.Close()
	a.stop(&s.said)
	t.Cleanup(func() { rotateKeyBeforeCommit = nil })

	// the connection lost before the COMMIT reached the server
	before := s.registry(t)
	rotateKeyBeforeCommit = func(c *pgConn) { c.conn.Close() }
	code, stdout, stderr := s.rotate(t, ksVersion1)
	rotateKeyBeforeCommit = nil
	if code != 1 || stdout != "" || !strings.Contains(stderr, "the key may have rotated: rerun to check") {
		t.Fatalf("the COMMIT not answered: %d %q %q", code, stdout, stderr)
	}
	if !bytes.Equal(s.registry(t), before) {
		t.Fatal("a COMMIT never sent changed the registry")
	}
	if code, stdout, stderr := s.rotate(t, ksVersion1); code != 0 || !strings.Contains(stderr, "rotation 1:") || !bytes.Equal(s.registry(t), append(bytes.Clone(before), stdout...)) {
		t.Fatalf("the rerun did not rotate: %d %q %q", code, stdout, stderr)
	}

	// the COMMIT made, and its answer lost
	rotateKeyBeforeCommit = func(c *pgConn) {
		if _, err := c.exec("COMMIT"); err != nil {
			t.Errorf("the hook's COMMIT: %v", err)
		}
		c.conn.Close()
	}
	code, stdout, stderr = s.rotate(t, ksVersion2, rkFrom(t, ksVersion1)...)
	rotateKeyBeforeCommit = nil
	if code != 1 || stdout != "" || !strings.Contains(stderr, "the key may have rotated: rerun to check") {
		t.Fatalf("the COMMIT's answer lost: %d %q %q", code, stdout, stderr)
	}
	committed := s.registry(t)
	if _, err := engineWalk(committed, edKey(mustKeyServiceSigner(t, ksVersion2).publicKey())); err != nil {
		t.Fatalf("the committed rotation does not walk to version 2: %v", err)
	}
	if code, stdout, stderr := s.rotate(t, ksVersion2, rkFrom(t, ksVersion1)...); code != 0 || stdout != "" || !strings.Contains(stderr, "already ends at this rotation, rotation 2 from key "+keyIDFor(mustKeyServiceSigner(t, ksVersion1).publicKey())+" to key "+keyIDFor(mustKeyServiceSigner(t, ksVersion2).publicKey())+", which may be an earlier run's") ||
		!bytes.Equal(s.registry(t), committed) {
		t.Fatalf("the rerun after a COMMIT made: %d %q %q", code, stdout, stderr)
	}
	s.start(t, ksVersion2, mustKeyServiceSigner(t, ksVersion2)).stop(&s.said)
}

// A configuration of the filesystem kind is a usage error, naming what
// rotates that kind's key.
func TestStoreRotateKeyNamesTheFilesystemKindsRotation(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "engine.json")
	if err := os.WriteFile(config, []byte(engineJSON(t, catalogWith(t, map[string]string{}), "", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	connection := filepath.Join(dir, "connection")
	if err := os.WriteFile(connection, []byte("postgresql://nobody:synthetic@127.0.0.1:1/none\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := cmdStoreRotateKeyAt([]string{"--connection-file", connection, "--owner", "owner_role", "--runtime", "runtime_role", "--config", config}, &stdout, &stderr, nowStamp)
	if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "gateway rotate-key") || !strings.Contains(stderr.String(), "SIGHUP") {
		t.Fatalf("a filesystem configuration: %d %q %q", code, stdout.String(), stderr.String())
	}
	for _, args := range [][]string{
		{"--from-key-version", ksVersion1},
		{"--from-key-version", "cryptoKeyVersions/1", "--from-public-key", strings.Repeat("0", 64)},
		{"--from-key-version", ksVersion1, "--from-public-key", strings.Repeat("A", 64)},
	} {
		stdout.Reset()
		stderr.Reset()
		code := cmdStoreRotateKeyAt(append([]string{"--connection-file", connection, "--owner", "owner_role", "--runtime", "runtime_role", "--config", config}, args...), &stdout, &stderr, nowStamp)
		if code != 2 || !strings.Contains(stderr.String(), "--from-") {
			t.Fatalf("%v: %d %q", args, code, stderr.String())
		}
	}
}

// gateway store rotate on the PostgreSQL kind whose continuation is stamped
// before the key history's last rotation, a clock behind, is refused before
// anything is sealed, as on the filesystem kind: the session left open stays
// open and the registry is unchanged.
func TestAPostgresStoreRotationStampedBeforeTheLastRotationIsRefusedBeforeTheSeals(t *testing.T) {
	standInKeyService(t)
	one := mustKeyServiceSigner(t, ksVersion1)
	s := newRkStore(t)
	a := s.start(t, "", nil)
	server := httptest.NewServer(a.service.handler())
	rkCall(t, server, "rk-sealed", "plain", true)
	server.Close()
	a.stop(&s.said)
	if code, stdout, stderr := s.rotateAt(t, "2026-12-01T12:00:00Z", ksVersion1); code != 0 {
		t.Fatalf("the seed to key version 1: %d %q %q", code, stdout, stderr)
	}
	b := s.start(t, ksVersion1, one)
	server = httptest.NewServer(b.service.handler())
	rkCall(t, server, "rk-left-open", "plain", false)
	server.Close()
	b.stop(&s.said)
	target := pgTestDBBeside(t, s.db)
	before := pgRegistryOf(t, s.db)
	code, stdout, stderr := rotatePgAt(t, s.versions[ksVersion1], target, s.dir, func() string { return "2026-12-01T11:59:59Z" })
	want := "the store continuation's continuedAt 2026-12-01T11:59:59Z is before the key history's last rotation 2026-12-01T12:00:00Z"
	if code != 1 || stdout != "" || !strings.Contains(stderr, want) {
		t.Fatalf("a store rotation stamped before the last: %d %q %q", code, stdout, stderr)
	}
	if after := pgRegistryOf(t, s.db); after != before || strings.Contains(after, `"sessionId":"rk-left-open"`) {
		t.Fatal("a refused rotation sealed a session")
	}
}
