package main

// An export by scope on the PostgreSQL kind (SPEC.md §5a, "An export by
// scope"; docs/adr/0042, decisions 6 to 9), end to end as scope_cut_test.go
// holds it on the filesystem kind: a service of sources fixed to two scope
// identifiers writes its receipts as rows of each scope, and gateway export
// --scope cuts them. The export holds one scope's sessions alone; a store
// holding a session no cut can attribute, or a receipt file of the scope's
// that fails the signed orders, refuses it, in the filesystem kind's words,
// and writes nothing; and a restore of the export checks against its
// manifest and verifies by the scope as the store's whole export does. Each
// test skips without a server.

import (
	"bytes"
	"crypto/ed25519"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const (
	pgExportScopeA = "scope-a"
	pgExportScopeB = "scope-b"
)

// pgScopeExportStore is a service on the PostgreSQL kind holding the
// sessions scopeStore (remove_scope_test.go) holds on the filesystem kind,
// each written through the service by a source of the scope its rows are
// of:
//
//	a1  sealed  a1/0 of scope-a (q only-a), a1/1 of scope-a (q shared)
//	a2  open    a2/0 of scope-a (q open-a)
//	b1  sealed  b1/0 of scope-b (q shared), b1/1 of scope-b (q only-b)
//	p1  sealed  p1/0 of no scope (q x)
type pgScopeExportStore struct {
	db     *pgTestDB
	dir    string
	config string
	server *httptest.Server
}

func newPgScopeExportStore(t *testing.T) *pgScopeExportStore {
	t.Helper()
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	t.Setenv(envSourceHelper, "1")
	t.Setenv(envSourceEchoStdin, "1")
	helper := sourceSpec{argv: []string{os.Args[0]}, env: helperEnv}
	scoped := func(scope string) sourceSpec { s := helper; s.scope = scope; return s }
	config, _, server := scopedServiceStart(t, db, dir, map[string]sourceSpec{
		"a": scoped(pgExportScopeA), "b": scoped(pgExportScopeB), "plain": helper,
	})
	for _, c := range []struct{ session, source, scope, q string }{
		{"a1", "a", pgExportScopeA, "only-a"}, {"a1", "a", pgExportScopeA, "shared"}, {"a2", "a", pgExportScopeA, "open-a"},
		{"b1", "b", pgExportScopeB, "shared"}, {"b1", "b", pgExportScopeB, "only-b"}, {"p1", "plain", "", "x"},
	} {
		body := `{"session":"` + c.session + `","source":"` + c.source + `","arguments":{"q":"` + c.q + `"}}`
		if c.scope != "" {
			body = `{"session":"` + c.session + `","source":"` + c.source + `","scope":"` + c.scope + `","arguments":{"q":"` + c.q + `"}}`
		}
		if code, out := post(t, server, "/acquire", body); code != 200 {
			t.Fatalf("acquire %s: %d %v", body, code, out)
		}
	}
	for _, session := range []string{"a1", "b1", "p1"} {
		if code, out := post(t, server, "/seal", `{"session":"`+session+`"}`); code != 200 {
			t.Fatalf("seal %s: %d %v", session, code, out)
		}
	}
	t.Chdir(dir)
	return &pgScopeExportStore{db: db, dir: dir, config: config, server: server}
}

// export is gateway export of the store, whole or by scope, into a new
// directory of its own.
func (s *pgScopeExportStore) export(t *testing.T, scope string) (string, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "export")
	_, err := exportEngine(s.config, out, nil, scope)
	return out, err
}

// requireRefused fails unless err is exactly the sentence want and the
// refused export left no directory.
func requireRefused(t *testing.T, what string, out string, err error, want string) {
	t.Helper()
	if err == nil || err.Error() != want {
		t.Fatalf("%s: %v, want %q", what, err, want)
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("%s: the refused export left its directory: %v", what, err)
	}
}

// pgReceiptOf is the receipt file series/entry of a whole export.
func pgReceiptOf(t *testing.T, export, series, entry string) string {
	t.Helper()
	return readFile(t, filepath.Join(export, "store", "receipts", series, entry+".json"))
}

// An export by scope of the PostgreSQL kind, of a store holding the sessions
// of two scopes and of none, holds the sessions of the scope alone: each
// receipt byte for byte as the whole export holds it, the artifacts those
// receipts name and no other, and the registry's lines of them; the manifest
// names the scope and none of another session. It checks against its
// manifest, and verifies whole and by its scope.
func TestAPostgresExportByScopeHoldsItsSessionsAlone(t *testing.T) {
	s := newPgScopeExportStore(t)
	whole, err := s.export(t, "")
	if err != nil {
		t.Fatalf("export of the whole store: %v", err)
	}
	out, err := s.export(t, pgExportScopeB)
	if err != nil {
		t.Fatalf("export by %s: %v", pgExportScopeB, err)
	}
	if wholeSessions, _ := os.ReadDir(filepath.Join(whole, "store", "receipts")); len(wholeSessions) != 4 {
		t.Fatalf("the whole export holds %d sessions: the test tests nothing", len(wholeSessions))
	}
	sessions, err := os.ReadDir(filepath.Join(out, "store", "receipts"))
	if err != nil || len(sessions) != 1 || sessions[0].Name() != "b1" {
		t.Fatalf("the export's sessions: %v %v", sessions, err)
	}
	named := map[string]bool{}
	for _, name := range []string{"0", "1"} {
		got := pgReceiptOf(t, out, "b1", name)
		if got != pgReceiptOf(t, whole, "b1", name) {
			t.Fatalf("b1/%s.json is not the whole export's, byte for byte", name)
		}
		digestsNamed([]byte(got), named)
	}
	artifacts, _ := os.ReadDir(filepath.Join(out, "store", "artifacts"))
	wholeArtifacts, _ := os.ReadDir(filepath.Join(whole, "store", "artifacts"))
	if len(artifacts) != 2 || len(wholeArtifacts) <= len(artifacts) {
		t.Fatalf("the export holds %d artifacts, the whole export %d", len(artifacts), len(wholeArtifacts))
	}
	for _, a := range artifacts {
		if !named[a.Name()] {
			t.Fatalf("the export holds an artifact no receipt of the scope names: %s", a.Name())
		}
		if readFile(t, filepath.Join(out, "store", "artifacts", a.Name())) != readFile(t, filepath.Join(whole, "store", "artifacts", a.Name())) {
			t.Fatalf("artifact %s is not the whole export's, byte for byte", a.Name())
		}
	}
	registry := readFile(t, filepath.Join(out, "registry"))
	if lines := strings.Split(strings.TrimSuffix(registry, "\n"), "\n"); len(lines) != 1 || sessionIDOfLine(lines[0]) != "b1" {
		t.Fatalf("the export's registry: %q", registry)
	}
	if !strings.Contains(readFile(t, filepath.Join(whole, "registry")), registry) {
		t.Fatal("the export's registry line is not the whole export's, byte for byte")
	}
	manifest := readFile(t, filepath.Join(out, exportManifestName))
	if !strings.Contains(manifest, `"scope":`+jsonText(t, pgExportScopeB)) {
		t.Fatalf("the manifest does not name the scope: %s", manifest)
	}
	for _, other := range []string{`"a1"`, `"a2"`, `"p1"`} {
		if strings.Contains(manifest, other) {
			t.Fatalf("the manifest names %s: %s", other, manifest)
		}
	}
	requireExportChecks(t, out)
	restored := filepath.Join(t.TempDir(), "restored")
	restoreTree(t, out, restored)
	requireExportChecks(t, restored)
	publicKey := publicOf(ed25519.NewKeyFromSeed(testSeed))
	if rep, err := verifyWithRegistry(filepath.Join(restored, "store"), filepath.Join(restored, "registry"), "gateway:test", publicKey); err != nil || !rep.OK {
		t.Fatalf("the export, verified whole: %v %v", rep, err)
	}
	if rep := cutVerdict(t, filepath.Join(restored, "store"), filepath.Join(restored, "registry"), "gateway:test", pgExportScopeB); !rep.OK || !reflect.DeepEqual(rep.Cut.Sessions, []string{"b1"}) {
		t.Fatalf("the export, verified by its scope: %+v %v", rep.Cut, rep.Findings)
	}

	// the other scope's export holds its own sessions, a1 and the session
	// left open, and none of scope-b's
	outA, err := s.export(t, pgExportScopeA)
	if err != nil {
		t.Fatalf("export by %s: %v", pgExportScopeA, err)
	}
	var held []string
	sessionsA, _ := os.ReadDir(filepath.Join(outA, "store", "receipts"))
	for _, d := range sessionsA {
		held = append(held, d.Name())
	}
	if !slices.Equal(held, []string{"a1", "a2"}) {
		t.Fatalf("the export by %s holds the sessions %v", pgExportScopeA, held)
	}
}

// An export by scope of the PostgreSQL kind refuses, naming each and
// writing nothing, a store holding a session no cut can attribute to the
// scope or to another (a sealed session of no scope whose seal counts a
// receipt the store no longer holds), and a store whose session of the scope
// holds a receipt file that fails the signed orders (a genuine receipt of
// another scope's session filed in it). The sentences are the filesystem
// kind's (export_scope.go).
func TestAPostgresExportByScopeRefusesWhatItCannotShowToBeOfTheScope(t *testing.T) {
	t.Run("a session no cut can attribute", func(t *testing.T) {
		s := newPgScopeExportStore(t)
		// p1/0, as the owner, in the rows of no scope p1 is of
		s.db.asOwner(t, `SELECT pg_catalog.set_config('gateway.scope', 'none', true)`,
			`DELETE FROM gateway.entries WHERE series = 'p1' AND name = '0'`)
		want := "the store holds sessions an export by scope cannot attribute to the scope or to another: p1; gateway verify --scope names what it finds of each, and nothing was written"
		for _, scope := range []string{pgExportScopeA, pgExportScopeB} {
			out, err := s.export(t, scope)
			requireRefused(t, "an export by "+scope+" of a store holding p1 unattributed", out, err, want)
		}
		// the whole store still exports: the refusal is of the cut
		if _, err := s.export(t, ""); err != nil {
			t.Fatalf("the whole export of that store: %v", err)
		}
	})

	t.Run("a receipt file failing the signed orders", func(t *testing.T) {
		s := newPgScopeExportStore(t)
		whole, err := s.export(t, "")
		if err != nil {
			t.Fatal(err)
		}
		other := pgReceiptOf(t, whole, "b1", "0")
		// b1/0 filed in a1, as a third receipt, in a1's rows
		c := s.db.runtimeConn(t)
		if err := c.script("BEGIN"); err != nil {
			t.Fatal(err)
		}
		if _, err := c.exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, pgRowScope(pgExportScopeA)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.exec(`INSERT INTO gateway.entries (scope, series, name, data) VALUES ($1, 'a1', '2', $2)`, pgRowScope(pgExportScopeA), []byte(other)); err != nil {
			t.Fatal(err)
		}
		if err := c.script("COMMIT"); err != nil {
			t.Fatal(err)
		}
		want := "the store holds sessions of the scope with receipt files that fail the signed orders, whose scope an export by scope cannot show: a1/2.json; gateway verify --scope names what it finds of each, the whole store exports them, and nothing was written"
		out, err := s.export(t, pgExportScopeA)
		requireRefused(t, "an export by "+pgExportScopeA+" of a session holding another scope's receipt", out, err, want)
		// the file is in a session of scope-a: scope-b's cut holds none of it
		if out, err := s.export(t, pgExportScopeB); err != nil {
			t.Fatalf("export by %s of that store: %v", pgExportScopeB, err)
		} else if _, err := os.Lstat(filepath.Join(out, "store", "receipts", "a1")); !os.IsNotExist(err) {
			t.Fatalf("the export by %s holds a1: %v", pgExportScopeB, err)
		}
		if _, err := s.export(t, ""); err != nil {
			t.Fatalf("the whole export of that store: %v", err)
		}
	})
}

// A restore of an export by scope of the PostgreSQL kind -- every file
// copied to another place -- checks against its manifest and verifies by
// its scope as the store does: byte for byte the verdict by scope of the
// store's whole export, and verified whole it gives the same verdict but
// for the cut.
func TestAPostgresExportByScopeRestoreVerifiesByItsScopeAsTheStoreDoes(t *testing.T) {
	s := newPgScopeExportStore(t)
	wholeOut, err := s.export(t, "")
	if err != nil {
		t.Fatal(err)
	}
	whole := filepath.Join(t.TempDir(), "restored-whole")
	restoreTree(t, wholeOut, whole)
	requireExportChecks(t, whole)
	for scope, session := range map[string]string{pgExportScopeA: "a1", pgExportScopeB: "b1"} {
		out, err := s.export(t, scope)
		if err != nil {
			t.Fatalf("export by %s: %v", scope, err)
		}
		restored := filepath.Join(t.TempDir(), "restored")
		restoreTree(t, out, restored)
		requireExportChecks(t, restored)
		live := cutVerdict(t, filepath.Join(whole, "store"), filepath.Join(whole, "registry"), "gateway:test", scope)
		got := cutVerdict(t, filepath.Join(restored, "store"), filepath.Join(restored, "registry"), "gateway:test", scope)
		if !slices.Contains(got.Cut.Sessions, session) || len(got.Cut.Unattributed) != 0 {
			t.Fatalf("the restored export's cut by %s: %+v", scope, got.Cut)
		}
		wantBytes, err := live.marshal()
		if err != nil {
			t.Fatal(err)
		}
		gotBytes, err := got.marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotBytes, wantBytes) {
			t.Fatalf("the restored export's verdict by %s differs from the store's:\nstore:    %s\nrestored: %s", scope, wantBytes, gotBytes)
		}
		// verified whole, the restored export gives the verdict by scope's, but for the cut
		wholeVerdict, err := verifySupplied(filepath.Join(restored, "store"), filepath.Join(restored, "registry"), "gateway:test", "", "", publicOf(ed25519.NewKeyFromSeed(testSeed)), false)
		if err != nil {
			t.Fatal(err)
		}
		live.Cut = nil
		if wantBytes, err = live.marshal(); err != nil {
			t.Fatal(err)
		}
		if gotBytes, err := wholeVerdict.marshal(); err != nil || !bytes.Equal(gotBytes, wantBytes) {
			t.Fatalf("the restored export by %s verified whole differs from the store's verdict by scope:\nby scope: %s\nwhole:    %s %v", scope, wantBytes, gotBytes, err)
		}
	}
}
