package main

// A verdict and an export cut by one scope identifier (scope_cut.go,
// export_scope.go; SPEC.md §4, "A verdict by scope", and §5a, "An export by
// scope"): exactly the sessions shown to be of the scope, every session that
// cannot be shown to be of it or of another named and kept, never left out.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// cutVerdict is the verdict by scope of a store directory and its registry.
func cutVerdict(t *testing.T, storeRoot, regPath, authority, scope string) *report {
	t.Helper()
	rep, err := verifyByScope(storeRoot, regPath, authority, "", scope, publicOf(ed25519.NewKeyFromSeed(testSeed)), false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Cut == nil || rep.Cut.Scope != scope {
		t.Fatalf("a verdict by scope without its cut: %+v", rep.Cut)
	}
	return rep
}

// sessionsNamed are the distinct sessions a verdict's findings and
// observations name, sorted.
func sessionsNamed(rep *report) []string {
	var out []string
	for _, f := range append(slices.Clone(rep.Findings), rep.Observations...) {
		if s, ok := f["sessionId"].(string); ok && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

// v030Store materializes the store gateway v0.30.0 wrote (TestAStoreV030WroteVerifiesUnchanged).
func v030Store(t *testing.T) (storeRoot, regPath, authority string) {
	t.Helper()
	var fixture v030Fixture
	if err := json.Unmarshal([]byte(readFile(t, "testdata/v0.30.0-store/store.json")), &fixture); err != nil {
		t.Fatal(err)
	}
	storeRoot, regPath = materialize(t, fixture.Files, fixture.Registry)
	return storeRoot, regPath, fixture.Authority
}

// In a store an earlier release wrote, every seal of §3's form: a session
// holding a receipt of the scope is of it, whatever its seal; a sealed
// session held whole whose receipts carry none of the scope is of another;
// and a session left open whose receipts carry no scope salt cannot be shown
// to be of the scope or of another, so the cut names it, keeps what it finds
// of it, and is not ok. A session whose seal counts a receipt the store no
// longer holds is so too.
func TestAVerdictByScopeOfAnEarlierStoreNamesWhatItCannotAttribute(t *testing.T) {
	storeRoot, regPath, authority := v030Store(t)
	rep := cutVerdict(t, storeRoot, regPath, authority, testScope)
	if want := []string{"left-open", "mixed", "scoped-only"}; !reflect.DeepEqual(rep.Cut.Sessions, want) || len(rep.Cut.Unattributed) != 0 {
		t.Fatalf("the cut of %s: %v, unattributed %v", testScope, rep.Cut.Sessions, rep.Cut.Unattributed)
	}
	if want := []string{"left-open", "mixed", "scoped-only"}; !reflect.DeepEqual(sessionsNamed(rep), want) || rep.OK {
		t.Fatalf("the verdict of %s names %v, ok %v", testScope, sessionsNamed(rep), rep.OK)
	}
	rep = cutVerdict(t, storeRoot, regPath, authority, otherScope)
	if len(rep.Cut.Sessions) != 0 || !reflect.DeepEqual(rep.Cut.Unattributed, []string{"left-open"}) {
		t.Fatalf("the cut of %s: %v, unattributed %v", otherScope, rep.Cut.Sessions, rep.Cut.Unattributed)
	}
	if rep.OK || !reflect.DeepEqual(sessionsNamed(rep), []string{"left-open"}) || !slices.Contains(statusesOf(rep), "left-open/unregistered-session") {
		t.Fatalf("the verdict of %s: ok %v, %v", otherScope, rep.OK, rep.Findings)
	}
	// the receipt plain-only's seal counts is gone
	if err := os.Remove(filepath.Join(storeRoot, "receipts", "plain-only", "0.json")); err != nil {
		t.Fatal(err)
	}
	rep = cutVerdict(t, storeRoot, regPath, authority, testScope)
	if !reflect.DeepEqual(rep.Cut.Unattributed, []string{"plain-only"}) || rep.OK || !slices.Contains(statusesOf(rep), "plain-only/tail-rollback") {
		t.Fatalf("a seal of §3's form over a receipt gone: unattributed %v, ok %v, %v", rep.Cut.Unattributed, rep.OK, statusesOf(rep))
	}
}

// A store this release wrote: each sealed session of a scope is in the cut
// of its own scope and in no other, and so is one left open, whose receipts
// carry its scope and salt; a session of no scope is in none. A sealed
// session of the other scope gone with no record saying so may have been of
// either: the cut names it, and its finding.
func TestAVerdictByScopeHoldsExactlyItsSessions(t *testing.T) {
	g, _ := scopeStore(t, [3]string{"p1", "plain", "x"})
	if _, err := g.sealSession("p1"); err != nil {
		t.Fatal(err)
	}
	rep := cutVerdict(t, g.storeRoot, g.regPath, g.authority, otherScope)
	if !rep.OK || !reflect.DeepEqual(rep.Cut.Sessions, []string{"b1"}) || len(rep.Cut.Unattributed) != 0 || !reflect.DeepEqual(sessionsNamed(rep), []string{"b1"}) {
		t.Fatalf("the cut of %s: ok %v, %v, unattributed %v, naming %v", otherScope, rep.OK, rep.Cut.Sessions, rep.Cut.Unattributed, sessionsNamed(rep))
	}
	rep = cutVerdict(t, g.storeRoot, g.regPath, g.authority, testScope)
	if !reflect.DeepEqual(rep.Cut.Sessions, []string{"a1", "a2"}) || len(rep.Cut.Unattributed) != 0 || !reflect.DeepEqual(sessionsNamed(rep), []string{"a1", "a2"}) ||
		rep.OK || !reflect.DeepEqual(statusesOf(rep), []string{"a2/unregistered-session"}) {
		t.Fatalf("the cut of %s: ok %v, %v, unattributed %v, %v", testScope, rep.OK, rep.Cut.Sessions, rep.Cut.Unattributed, statusesOf(rep))
	}
	if rep := cutVerdict(t, g.storeRoot, g.regPath, g.authority, "équipe-c"); !rep.OK || len(rep.Cut.Sessions) != 0 || len(rep.Cut.Unattributed) != 0 || len(rep.Findings) != 0 {
		t.Fatalf("the cut of a scope no session is of: %+v %v", rep.Cut, rep.Findings)
	}
	if err := os.RemoveAll(filepath.Join(g.storeRoot, "receipts", "b1")); err != nil {
		t.Fatal(err)
	}
	rep = cutVerdict(t, g.storeRoot, g.regPath, g.authority, testScope)
	if !reflect.DeepEqual(rep.Cut.Unattributed, []string{"b1"}) || !slices.Contains(statusesOf(rep), "b1/sealed-session-missing") {
		t.Fatalf("a sealed session gone: unattributed %v, %v", rep.Cut.Unattributed, statusesOf(rep))
	}
}

// A session gone that a session-removal record names is of the scope the
// record states: observed removed in that scope's cut, and in no other.
func TestAVerdictByScopeAttributesARemovedSessionByItsRecord(t *testing.T) {
	g, seedPath := scopeStore(t)
	if code, stdout, stderr := removeScopeOn(t, g, seedPath, "--scope", otherScope, "--by", "operator-1"); code != 0 {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	rep := cutVerdict(t, g.storeRoot, g.regPath, g.authority, otherScope)
	if !rep.OK || !reflect.DeepEqual(rep.Cut.Sessions, []string{"b1"}) || len(rep.Observations) != 1 || rep.Observations[0]["observation"] != observationSessionRemoved {
		t.Fatalf("the cut of the scope removed: ok %v, %v, %v", rep.OK, rep.Cut.Sessions, rep.Observations)
	}
	if rep := cutVerdict(t, g.storeRoot, g.regPath, g.authority, testScope); slices.Contains(sessionsNamed(rep), "b1") || slices.Contains(rep.Cut.Sessions, "b1") {
		t.Fatalf("the cut of another scope names the session removed: %v", sessionsNamed(rep))
	}
}

// The selection rule, branch by branch (scope_cut.go, attribute).
func TestTheAttributionOfASession(t *testing.T) {
	const id = "s"
	saltA, saltB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	holding := func(complete bool, count int64, names ...scopeNaming) *scopeHolding {
		h := newScopeHolding()
		for _, n := range names {
			if n == (scopeNaming{}) {
				h.noScope = true
				continue
			}
			h.scopes[n] = true
		}
		h.count, h.signedAll, h.last = count, complete, "head"
		return h
	}
	v2 := func(scope string) seal {
		return seal{sessionID: id, finalCount: 2, scopeDigest: sealScopeDigest(id, scope)}
	}
	v3 := func(scope, salt string) seal {
		return seal{sessionID: id, finalCount: 2, scopeDigest: saltedScopeDigest(id, scope, salt), salted: true}
	}
	plain := seal{sessionID: id, finalCount: 2}
	a, b := scopeNaming{"A", saltA}, scopeNaming{"B", saltB}
	removedAs := func(scope string) *retention {
		return &retention{sessions: map[string][]sessionRemoval{id: {{sessionID: id, finalCount: 2, scope: scope}}}}
	}
	for _, c := range []struct {
		what   string
		s      seal
		sealed bool
		h      *scopeHolding
		ret    *retention
		want   attribution
	}{
		{"a receipt of the scope, under a seal of another", v3("B", saltB), true, holding(true, 2, a, b), nil, ofTheScope},
		{"version 2 naming the scope", v2("A"), true, holding(true, 2, scopeNaming{"A", ""}), nil, ofTheScope},
		{"version 2 naming another, over no receipt", v2("B"), true, holding(false, 0), nil, ofAnother},
		{"version 3 matched by a receipt of another", v3("B", saltB), true, holding(true, 2, b), nil, ofAnother},
		{"version 3 matched by no receipt", v3("B", saltB), true, holding(false, 2, scopeNaming{"B", saltA}), nil, unattributed},
		{"§3's form, held whole, of another", plain, true, holding(true, 2, b), nil, ofAnother},
		{"§3's form, held whole, of none", plain, true, holding(true, 2, scopeNaming{}), nil, ofAnother},
		{"§3's form over a receipt not held", plain, true, holding(true, 1, b), nil, unattributed},
		{"§3's form over a receipt not signed", plain, true, holding(false, 2, b), nil, unattributed},
		{"§3c's form over another head", seal{sessionID: id, finalCount: 2, interrupted: true, head: "other"}, true, holding(true, 2, b), nil, unattributed},
		{"§3c's form over its head", seal{sessionID: id, finalCount: 2, interrupted: true, head: "head"}, true, holding(true, 2, b), nil, ofAnother},
		{"open, receipts of another with a salt", seal{}, false, holding(false, 1, b), nil, ofAnother},
		{"open, receipts of another with no salt", seal{}, false, holding(true, 1, scopeNaming{"B", ""}), nil, unattributed},
		{"open, receipts of none", seal{}, false, holding(true, 1, scopeNaming{}), nil, unattributed},
		{"open, a receipt of another and one of none", seal{}, false, holding(true, 2, b, scopeNaming{}), nil, unattributed},
		{"open, no receipt signed", seal{}, false, holding(false, 1), nil, unattributed},
		{"gone, a record of the scope", v3("A", saltA), true, nil, removedAs("A"), ofTheScope},
		{"gone, a record of another", v3("B", saltB), true, nil, removedAs("B"), ofAnother},
		{"gone, version 2 naming the scope", v2("A"), true, nil, nil, ofTheScope},
		{"gone, version 2 naming another", v2("B"), true, nil, nil, ofAnother},
		{"gone, version 3, no record", v3("B", saltB), true, nil, nil, unattributed},
		{"gone, §3's form, no record", plain, true, nil, nil, unattributed},
	} {
		if c.ret != nil {
			// the record names the seal it was made over
			for i := range c.ret.sessions[id] {
				c.ret.sessions[id][i].sealSignature, c.ret.sessions[id][i].scopeSalt = c.s.signature, map[string]string{"A": saltA, "B": saltB}[c.ret.sessions[id][i].scope]
			}
		}
		if got := attribute("A", id, c.s, c.sealed, c.h, c.ret); got != c.want {
			t.Errorf("%s: %d, want %d", c.what, got, c.want)
		}
	}
}

// An export by scope holds the sessions of the scope alone, the artifacts
// their receipts name, the registry's lines of them, and names the scope in
// its manifest; it verifies whole and by its scope, and holds to its
// manifest. A store holding a session the cut cannot attribute refuses it,
// by name, and writes nothing.
func TestAnExportByScopeHoldsItsSessionsAlone(t *testing.T) {
	g, _ := scopeStore(t, [3]string{"p1", "plain", "x"})
	if _, err := g.sealSession("p1"); err != nil {
		t.Fatal(err)
	}
	in := exportInputs{authority: g.authority, keyID: keyIDFor(g.publicKey), publicKey: g.publicKey,
		kind: newFsKind(fsLayout{store: g.storeRoot, registry: g.regPath}), storeRoot: g.storeRoot, scope: otherScope}
	out := filepath.Join(t.TempDir(), "export")
	if _, err := writeExport(in, out); err != nil {
		t.Fatal(err)
	}
	sessions, err := os.ReadDir(filepath.Join(out, "store", "receipts"))
	if err != nil || len(sessions) != 1 || sessions[0].Name() != "b1" {
		t.Fatalf("the export's sessions: %v %v", sessions, err)
	}
	registry := readFile(t, filepath.Join(out, "registry"))
	if lines := strings.Split(strings.TrimSuffix(registry, "\n"), "\n"); len(lines) != 1 || sessionIDOfLine(lines[0]) != "b1" {
		t.Fatalf("the export's registry: %q", registry)
	}
	if !strings.Contains(readFile(t, g.regPath), registry) {
		t.Fatal("the export's registry line is not the registry's, byte for byte")
	}
	named := map[string]bool{}
	for _, name := range []string{"0.json", "1.json"} {
		digestsNamed([]byte(readFile(t, filepath.Join(g.storeRoot, "receipts", "b1", name))), named)
	}
	artifacts, _ := os.ReadDir(filepath.Join(out, "store", "artifacts"))
	if len(artifacts) != 2 {
		t.Fatalf("the export holds %d artifacts", len(artifacts))
	}
	for _, a := range artifacts {
		if !named[a.Name()] {
			t.Fatalf("the export holds an artifact no receipt of the scope names: %s", a.Name())
		}
	}
	manifest := readFile(t, filepath.Join(out, exportManifestName))
	if !strings.Contains(manifest, `"scope":`+jsonText(t, otherScope)) || strings.Contains(manifest, `"a1"`) {
		t.Fatalf("the manifest: %s", manifest)
	}
	if report, err := checkExport(out); err != nil || !strings.Contains(string(canon(report)), `"ok":true`) {
		t.Fatalf("the export held to its manifest: %v %v", report, err)
	}
	exported := filepath.Join(out, "store")
	whole, err := verifyWithRegistry(exported, filepath.Join(out, "registry"), g.authority, g.publicKey)
	if err != nil || !whole.OK {
		t.Fatalf("the export, verified whole: %v %v", whole, err)
	}
	if rep := cutVerdict(t, exported, filepath.Join(out, "registry"), g.authority, otherScope); !rep.OK || !reflect.DeepEqual(rep.Cut.Sessions, []string{"b1"}) {
		t.Fatalf("the export, verified by its scope: %+v %v", rep.Cut, rep.Findings)
	}

	// a session no cut can attribute
	if err := os.Remove(filepath.Join(g.storeRoot, "receipts", "p1", "0.json")); err != nil {
		t.Fatal(err)
	}
	refused := filepath.Join(t.TempDir(), "refused")
	if _, err := writeExport(in, refused); err == nil || !strings.Contains(err.Error(), "cannot attribute") || !strings.Contains(err.Error(), "p1") {
		t.Fatalf("an export by scope of a store holding p1 unattributed: %v", err)
	}
	if _, err := os.Lstat(refused); !os.IsNotExist(err) {
		t.Fatalf("the refused export left its directory: %v", err)
	}
}

// An export by scope of a store an earlier release wrote: a session of the
// scope holding a receipt of no scope (mixed) refuses it, since the export
// would carry that receipt, and a session the cut cannot attribute
// (left-open, to the other scope) refuses it too; each by name, nothing
// written.
func TestAnExportByScopeOfAnEarlierStoreCarriesNothingOfAnother(t *testing.T) {
	storeRoot, regPath, authority := v030Store(t)
	publicKey := publicOf(ed25519.NewKeyFromSeed(testSeed))
	for scope, want := range map[string]string{testScope: "receipts carry another scope, or none, which an export by scope would carry: mixed;", otherScope: "cannot attribute to the scope or to another: left-open;"} {
		in := exportInputs{authority: authority, keyID: keyIDFor(publicKey), publicKey: publicKey,
			kind: newFsKind(fsLayout{store: storeRoot, registry: regPath}), storeRoot: storeRoot, scope: scope}
		out := filepath.Join(t.TempDir(), "export")
		if _, err := writeExport(in, out); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("an export by %s of the earlier store: %v, want %q", scope, err, want)
		}
		if _, err := os.Lstat(out); !os.IsNotExist(err) {
			t.Fatalf("the refused export by %s left its directory: %v", scope, err)
		}
	}
}

// An export by scope of a store whose session of the scope holds a receipt
// file that fails the signed orders -- a genuine receipt of another scope
// copied into it -- is refused, naming the session and the file, and
// nothing is written: the file shows no scope, and the export would carry
// it and the artifacts it names. A receipt file whose bytes change after
// the attribution read them is refused before it is written.
func TestAnExportByScopeRefusesAReceiptFileNotShownToBeOfTheScope(t *testing.T) {
	g, _ := scopeStore(t)
	in := exportInputs{authority: g.authority, keyID: keyIDFor(g.publicKey), publicKey: g.publicKey,
		kind: newFsKind(fsLayout{store: g.storeRoot, registry: g.regPath}), storeRoot: g.storeRoot, scope: testScope}
	other := readFile(t, filepath.Join(g.storeRoot, "receipts", "b1", "0.json"))
	misfiled := filepath.Join(g.storeRoot, "receipts", "a1", "2.json")
	if err := os.WriteFile(misfiled, []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "export")
	if _, err := writeExport(in, out); err == nil || !strings.Contains(err.Error(), "fail the signed orders") || !strings.Contains(err.Error(), "a1/2.json") {
		t.Fatalf("an export by scope of a session holding another scope's receipt: %v", err)
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("the refused export left its directory: %v", err)
	}
	if err := os.Remove(misfiled); err != nil {
		t.Fatal(err)
	}

	reads := 0
	in.kind = rereadKind{in.kind, func(series, entry string, data []byte) []byte {
		if series == "a1" && entry == "0" {
			if reads++; reads > 1 {
				return []byte(other)
			}
		}
		return data
	}}
	changed := filepath.Join(t.TempDir(), "changed")
	if _, err := writeExport(in, changed); err == nil || !strings.Contains(err.Error(), "a1/0.json changed after") {
		t.Fatalf("an export by scope of a receipt changed after its attribution: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(changed, "store", "receipts", "a1", "0.json")); !os.IsNotExist(err) {
		t.Fatalf("the changed receipt was written: %v", err)
	}
}

// An export by scope holds the artifacts its receipts name by the members
// that name one -- resultDigest, and a descriptor provenance's snapshot and
// statement -- and no other: a digest of another scope's artifact written
// in what a source reports, signed by the gateway as it signs any such
// member, pulls in nothing.
func TestAnExportByScopeTakesNoArtifactFromWhatASourceReports(t *testing.T) {
	g, _ := scopeStore(t)
	digestIn := func(path, name string) string {
		v, _ := parseJSON([]byte(readFile(t, path)))
		d, _ := memberString(v.(*vObject), name)
		return d
	}
	// b1/1 (q only-b) alone names its artifact
	theirs := digestIn(filepath.Join(g.storeRoot, "receipts", "b1", "1.json"), "resultDigest")
	path := filepath.Join(g.storeRoot, "receipts", "a1", "1.json")
	ours := digestIn(path, "resultDigest")
	v, err := parseJSON([]byte(readFile(t, path)))
	if err != nil {
		t.Fatal(err)
	}
	obj := v.(*vObject)
	a, _ := obj.get("acquisition")
	acq := a.(*vObject)
	acq.set("schema", vString(theirs))
	acq.set("snapshot", vString(theirs))
	r, err := receiptFrom(obj)
	if err != nil {
		t.Fatal(err)
	}
	obj.set("signature", vString(hex.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(testSeed), r.signingInput()))))
	if err := os.WriteFile(path, canon(obj), 0o600); err != nil {
		t.Fatal(err)
	}
	in := exportInputs{authority: g.authority, keyID: keyIDFor(g.publicKey), publicKey: g.publicKey,
		kind: newFsKind(fsLayout{store: g.storeRoot, registry: g.regPath}), storeRoot: g.storeRoot, scope: testScope}
	out := filepath.Join(t.TempDir(), "export")
	if _, err := writeExport(in, out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(out, "store", "artifacts", strings.TrimPrefix(theirs, "sha256:"))); !os.IsNotExist(err) {
		t.Fatalf("a digest a source reports pulled another scope's artifact into the export: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(out, "store", "artifacts", strings.TrimPrefix(ours, "sha256:"))); err != nil {
		t.Fatalf("the receipt's own artifact: %v", err)
	}

	// a descriptor provenance names its snapshot and statement; its binding's
	// pin, a commitment, the caller's token and the schema name none
	digest := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	named := map[string]bool{}
	digestsNamed([]byte(`{"resultDigest":"`+digest("1")+`","argumentsCommitment":"`+digest("2")+`","caller":{"tokenDigest":"`+digest("3")+`"},`+
		`"acquisition":{"statement":"`+digest("4")+`","schema":"`+digest("5")+`","adapter":{"digest":"`+digest("6")+`"},"pageItems":["`+digest("7")+`"],`+
		`"descriptorProvenance":{"snapshot":"`+digest("8")+`","statement":"`+digest("9")+`","binding":"n@`+digest("a")+`"}}}`), named)
	if want := map[string]bool{strings.Repeat("1", 64): true, strings.Repeat("8", 64): true, strings.Repeat("9", 64): true}; !reflect.DeepEqual(named, want) {
		t.Fatalf("the artifacts a receipt names: %v", named)
	}
}

// rereadKind is a kind whose cut gives each receipt's bytes through change.
type rereadKind struct {
	storeKind
	change func(series, entry string, data []byte) []byte
}

func (k rereadKind) snapshot() (*storeCut, error) {
	cut, err := k.storeKind.snapshot()
	if err != nil {
		return nil, err
	}
	entry := cut.entry
	cut.entry = func(series, name string) ([]byte, error) {
		data, err := entry(series, name)
		if err != nil {
			return nil, err
		}
		return k.change(series, name, data), nil
	}
	return cut, nil
}

// unprovenOfCut are a verdict by scope's findings naming a session of its
// cut with a status of the signed orders (SPEC.md §1.4, orders 1 to 6).
func unprovenOfCut(rep *report) []finding {
	var out []finding
	for _, f := range rep.Findings {
		sessionID, _ := f["sessionId"].(string)
		status, _ := f["status"].(string)
		if slices.Contains(rep.Cut.Sessions, sessionID) && !pastSignedOrders(&receipt{}, status) {
			out = append(out, f)
		}
	}
	return out
}

// Every corpus vector of a verdict by scope: where its cut attributes every
// session, the store exports by that scope, and a restore of the export
// checks against its manifest and verifies by the scope, byte for byte, as
// the store did; where it does not, the export is refused and nothing is
// written.
func TestEveryCorpusCutExportsAndVerifiesByItsScopeAsTheStoreDoes(t *testing.T) {
	corpus := filepath.Join("..", "corpus")
	publicKey, err := corpusPublicKey(corpus)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := storeVectorPaths(corpus)
	if err != nil {
		t.Fatal(err)
	}
	cuts := 0
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var vector storeVector
		if err := decodeVectorFile(raw, &vector, false); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if vector.Scope == "" {
			continue
		}
		cuts++
		t.Run(vector.Name, func(t *testing.T) {
			root, storeRoot, registryPath, _, err := materializeVector(vector)
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			verdict := func(store, registry string) ([]byte, *report) {
				rep, err := verifyByScope(store, registry, vector.Authority, "", vector.Scope, publicKey, false)
				if err != nil {
					t.Fatalf("no verdict for %s: %v", store, err)
				}
				out, err := rep.marshal()
				if err != nil {
					t.Fatal(err)
				}
				return out, rep
			}
			live, rep := verdict(storeRoot, registryPath)
			out := filepath.Join(t.TempDir(), "export")
			in := exportInputs{authority: vector.Authority, keyID: keyIDFor(publicKey), publicKey: publicKey,
				kind: newFsKind(fsLayout{store: storeRoot, registry: registryPath}), storeRoot: storeRoot, scope: vector.Scope}
			_, err = writeExport(in, out)
			if len(rep.Cut.Unattributed) > 0 {
				if err == nil || !strings.Contains(err.Error(), "cannot attribute") {
					t.Fatalf("an export of a cut naming %v unattributed: %v", rep.Cut.Unattributed, err)
				}
				if _, err := os.Lstat(out); !os.IsNotExist(err) {
					t.Fatalf("the refused export left its directory: %v", err)
				}
				return
			}
			if unproven := unprovenOfCut(rep); len(unproven) > 0 {
				if err == nil || !strings.Contains(err.Error(), "fail the signed orders") {
					t.Fatalf("an export of a cut whose sessions hold %v: %v", unproven, err)
				}
				if _, err := os.Lstat(out); !os.IsNotExist(err) {
					t.Fatalf("the refused export left its directory: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			restored := filepath.Join(t.TempDir(), "restored")
			restoreTree(t, out, restored)
			requireExportChecks(t, restored)
			// An export by scope takes no refusal journal (ADR-0059 §8), so
			// the restored export reads as the store does with its refusal
			// journals left out, and holds none of them.
			if journals, err := refusalJournalFilesIn(filepath.Join(restored, "store")); err != nil || len(journals) > 0 {
				t.Fatalf("an export by scope took refusal journals: %d %v", len(journals), err)
			}
			cutWant := live
			if kept := withoutRefusalJournals(rep); kept != nil {
				rep = kept
				if cutWant, err = rep.marshal(); err != nil {
					t.Fatal(err)
				}
			}
			if got, _ := verdict(filepath.Join(restored, "store"), filepath.Join(restored, "registry")); !bytes.Equal(got, cutWant) {
				t.Fatalf("the restored export's verdict by scope differs from the store's:\nstore:    %s\nrestored: %s", cutWant, got)
			}
			// verified whole, the export gives the same verdict, but for the cut
			whole, err := verifySupplied(filepath.Join(restored, "store"), filepath.Join(restored, "registry"), vector.Authority, "", "", publicKey, false)
			if err != nil {
				t.Fatal(err)
			}
			rep.Cut = nil
			want, err := rep.marshal()
			if err != nil {
				t.Fatal(err)
			}
			if got, err := whole.marshal(); err != nil || !bytes.Equal(got, want) {
				t.Fatalf("the restored export verified whole differs from the store's verdict by scope:\nby scope: %s\nwhole:    %s %v", want, got, err)
			}
		})
	}
	if cuts == 0 {
		t.Fatal("no vector of a verdict by scope: the test tests nothing")
	}
}

// The command lines: --scope first or not at all on gateway verify, and
// never with a decision-record directory; on gateway export never with
// --check or --observations. Each is a usage error before anything is read.
func TestTheScopeOptionsOnTheCommandLine(t *testing.T) {
	for _, args := range [][]string{
		{"store", "--scope", testScope, "registry", "gateway:test"},
		{"--ordinary-seals-only", "--scope", testScope, "store", "registry", "gateway:test"},
		{"--scope", testScope, "store", "registry", "gateway:test", "records"},
		{"--scope", "", "store", "registry", "gateway:test"},
		{"--scope"},
	} {
		if code := cmdVerify(args); code != 2 {
			t.Errorf("gateway verify %q: exit %d, want 2", args, code)
		}
	}
	for _, args := range [][]string{
		{"--check", "dir", "--scope", testScope},
		{"--config", "c", "--out", "o", "--scope", testScope, "--observations", "j"},
		{"--config", "c", "--out", "o", "--scope", ""},
		{"--config", "c", "--out", "o", "--scope", testScope, "--scope", testScope},
	} {
		if code := cmdExport(args, io.Discard, io.Discard); code != 2 {
			t.Errorf("gateway export %q: exit %d, want 2", args, code)
		}
	}
}

// withoutRefusalJournals is a verdict with its refusal journals' findings and
// observations left out, or nil when it names none.
func withoutRefusalJournals(rep *report) *report {
	isJournal := func(f finding) bool {
		name, ok := f["journal"].(string)
		return ok && isRefusalJournalName(name)
	}
	keep := func(in []finding) ([]finding, bool) {
		var out []finding
		dropped := false
		for _, f := range in {
			if isJournal(f) {
				dropped = true
				continue
			}
			out = append(out, f)
		}
		return out, dropped
	}
	findings, a := keep(rep.Findings)
	observations, b := keep(rep.Observations)
	if !a && !b {
		return nil
	}
	out := *rep
	if findings == nil {
		findings = []finding{}
	}
	out.Findings, out.Observations = findings, observations
	return &out
}
