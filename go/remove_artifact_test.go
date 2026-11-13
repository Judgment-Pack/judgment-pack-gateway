package main

// gateway remove-artifact (SPEC.md §1.3a and §6; ADR-0028): a recorded
// removal, every ordering of a record and the bytes it is about, and what
// the command refuses.

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const removalStamp = "2026-11-13T00:00:01Z"

// removalStore is a stopped gateway's store: session r holds
//
//	r/0  kept     q:a   (digest A)
//	r/1  kept     q:b   (digest B)
//	r/2  kept     q:a   (digest A, shared with r/0)
//	r/3  unkept   q:c   (artifact "not-retained")
//	r/4  scoped   q:d   (scope testScope)
//
// and is sealed; the seed is in a file of its own.
func removalStore(t *testing.T) (*gatewayService, string) {
	t.Helper()
	t.Setenv(envSourceHelper, "1")
	t.Setenv(envSourceEchoStdin, "1")
	root := t.TempDir()
	g, err := newGatewayService(
		filepath.Join(root, "store"), testSeed, "gateway:test",
		filepath.Join(root, "registry.jsonl"),
		map[string]sourceSpec{
			"kept":   {argv: []string{os.Args[0]}, env: helperEnv},
			"unkept": {argv: []string{os.Args[0]}, env: helperEnv, notRetained: true},
			"scoped": {argv: []string{os.Args[0]}, env: helperEnv, scope: testScope},
		})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(g.handler())
	for _, body := range []string{
		`{"session":"r","source":"kept","arguments":{"q":"a"}}`,
		`{"session":"r","source":"kept","arguments":{"q":"b"}}`,
		`{"session":"r","source":"kept","arguments":{"q":"a"}}`,
		`{"session":"r","source":"unkept","arguments":{"q":"c"}}`,
		`{"session":"r","source":"scoped","scope":` + jsonText(t, testScope) + `,"arguments":{"q":"d"}}`,
	} {
		if code, out := post(t, server, "/acquire", body); code != http.StatusOK {
			t.Fatalf("acquire %s: %d %v", body, code, out)
		}
	}
	if code, out := post(t, server, "/seal", `{"session":"r"}`); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, out)
	}
	server.Close()
	return g, writeSeedFile(t, t.TempDir(), testSeed)
}

// removeOn runs the command on a store removalStore made, by its flags.
func removeOn(t *testing.T, g *gatewayService, seedPath string, rest ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	args := append([]string{"--store", g.storeRoot, "--seed", seedPath, "--registry", g.regPath, "--authority", g.authority}, rest...)
	code := cmdRemoveArtifactAt(args, &stdout, &stderr, fixedStamp(removalStamp))
	return code, stdout.String(), stderr.String()
}

// unlockedLine is what the command says after its own lines on a platform
// that locks no registry (sealOpenUnlocked, for this command).
func unlockedLine() string {
	if registryLocked {
		return ""
	}
	return "remove-artifact: this platform locks no registry, so a gateway still running was not looked for; the gateway was to be stopped\n"
}

// storedDigestOf is receipt r/<index>'s resultDigest hex.
func storedDigestOf(t *testing.T, g *gatewayService, session, index string) string {
	t.Helper()
	v, err := parseJSON([]byte(readFile(t, filepath.Join(g.storeRoot, "receipts", session, index+".json"))))
	if err != nil {
		t.Fatal(err)
	}
	d, _ := memberString(v.(*vObject), "resultDigest")
	return strings.TrimPrefix(d, "sha256:")
}

// verdictOf is the store's verdict: ok, and the finding status and
// observation of each receipt of session r by its index.
func verdictOf(t *testing.T, g *gatewayService) (bool, map[string]string) {
	t.Helper()
	rep, err := verifyWithRegistry(g.storeRoot, g.regPath, g.authority, g.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	said := map[string]string{}
	for _, f := range rep.Findings {
		if f["sessionId"] == "r" {
			said[fmt.Sprint(f["callIndex"])] = f["status"].(string)
		}
	}
	for _, o := range rep.Observations {
		if o["sessionId"] == "r" {
			said[fmt.Sprint(o["callIndex"])] += " " + o["observation"].(string)
		}
	}
	return rep.OK, said
}

// The record is appended, then the bytes removed; the command prints the
// record, which loads under the gateway's key and names the receipt; the
// receipt is then ok with artifact-removed, and the one that kept nothing ok
// with artifact-not-retained. A second run appends nothing, and says so.
func TestRemoveArtifactRecordsTheRemovalAndThenRemovesTheBytes(t *testing.T) {
	g, seedPath := removalStore(t)
	digestB := storedDigestOf(t, g, "r", "1")
	code, stdout, stderr := removeOn(t, g, seedPath, "--receipt", "r/1", "--by", "operator-1")
	if code != 0 || stderr != unlockedLine() {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	file := readFile(t, filepath.Join(g.storeRoot, removalsFile))
	if stdout != file || strings.Count(file, "\n") != 1 {
		t.Fatalf("the line printed %q is not the file %q", stdout, file)
	}
	keys, err := g.reachedKeys()
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := removalOf(strings.TrimSuffix(file, "\n"), keys)
	if !ok || rec.sessionID != "r" || rec.callIndex != 1 || rec.resultDigest != "sha256:"+digestB ||
		rec.removedAt != removalStamp || rec.removedBy != "operator-1" || rec.keyID != keyIDFor(g.publicKey) {
		t.Fatalf("the record: %+v %v", rec, ok)
	}
	if _, err := os.Lstat(filepath.Join(g.storeRoot, "artifacts", digestB)); !os.IsNotExist(err) {
		t.Fatalf("the bytes are still there: %v", err)
	}
	ok, said := verdictOf(t, g)
	if !ok || said["1"] != "ok "+observationRemoved || said["3"] != "ok "+observationNotRetained || said["0"] != "ok" {
		t.Fatalf("the verdict: %v %v", ok, said)
	}

	code, stdout, stderr = removeOn(t, g, seedPath, "--receipt", "r/1", "--by", "operator-1")
	if want := "remove-artifact: receipt r/1 was recorded as removed already, and its bytes are not there; nothing is changed for it\n" + unlockedLine(); code != 0 || stdout != "" || stderr != want {
		t.Fatalf("a second run: exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	if readFile(t, filepath.Join(g.storeRoot, removalsFile)) != file {
		t.Fatal("a second run appended a record")
	}
}

// Every ordering of a record and the bytes it is about: bytes changed
// before the removal are refused, and nothing changes; bytes put back after
// it, other than they were, are artifact-mismatch, a removal hiding nothing;
// the same bytes put back are ok with no observation, as a run stopped
// between the record and the removal leaves them, and a second run removes
// them; a record whose bytes are still there names the receipt for a
// second run that removes them.
func TestRemoveArtifactInEveryOrdering(t *testing.T) {
	t.Run("changed, then removed", func(t *testing.T) {
		g, seedPath := removalStore(t)
		path := filepath.Join(g.storeRoot, "artifacts", storedDigestOf(t, g, "r", "1"))
		if err := os.WriteFile(path, []byte(`{"changed":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		tree := storeTree(t, g.storeRoot)
		code, stdout, stderr := removeOn(t, g, seedPath, "--receipt", "r/1", "--by", "operator-1")
		want := "remove-artifact: receipt r/1 does not verify under the keys the registry's walk reached (artifact-mismatch); its bytes are not removed\n" + unlockedLine()
		if code != 1 || stdout != "" || stderr != want {
			t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
		}
		if !sameEntries(storeTree(t, g.storeRoot), tree) {
			t.Fatal("the store changed")
		}
	})
	t.Run("removed, then put back changed or the same", func(t *testing.T) {
		g, seedPath := removalStore(t)
		path := filepath.Join(g.storeRoot, "artifacts", storedDigestOf(t, g, "r", "1"))
		original := readFile(t, path)
		if code, _, stderr := removeOn(t, g, seedPath, "--receipt", "r/1", "--by", "operator-1"); code != 0 {
			t.Fatalf("exit %d %q", code, stderr)
		}
		if err := os.WriteFile(path, []byte(`{"changed":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if ok, said := verdictOf(t, g); ok || said["1"] != "artifact-mismatch" {
			t.Fatalf("other bytes put back: %v %v", ok, said)
		}
		if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
			t.Fatal(err)
		}
		if ok, said := verdictOf(t, g); !ok || said["1"] != "ok" {
			t.Fatalf("the same bytes put back: %v %v", ok, said)
		}
		// the record stands beside the bytes, as a run stopped between the
		// two leaves them; a second run removes them and appends nothing
		before := readFile(t, filepath.Join(g.storeRoot, removalsFile))
		code, stdout, stderr := removeOn(t, g, seedPath, "--receipt", "r/1", "--by", "operator-2")
		if want := "remove-artifact: receipt r/1 was recorded as removed already; its bytes, still there, are removed now\n" + unlockedLine(); code != 0 || stdout != "" || stderr != want {
			t.Fatalf("a second run: exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
		}
		if readFile(t, filepath.Join(g.storeRoot, removalsFile)) != before {
			t.Fatal("a second run appended a record")
		}
		if ok, said := verdictOf(t, g); !ok || said["1"] != "ok "+observationRemoved {
			t.Fatalf("after the second run: %v %v", ok, said)
		}
	})
	t.Run("the record removed, the bytes gone", func(t *testing.T) {
		g, seedPath := removalStore(t)
		if code, _, stderr := removeOn(t, g, seedPath, "--receipt", "r/1", "--by", "operator-1"); code != 0 {
			t.Fatalf("exit %d %q", code, stderr)
		}
		if err := os.Remove(filepath.Join(g.storeRoot, removalsFile)); err != nil {
			t.Fatal(err)
		}
		if ok, said := verdictOf(t, g); ok || said["1"] != "artifact-missing" {
			t.Fatalf("no record: %v %v", ok, said)
		}
	})
	t.Run("after a torn last line", func(t *testing.T) {
		g, seedPath := removalStore(t)
		torn := `{"callIndex":0,"keyId":"`
		if err := os.WriteFile(filepath.Join(g.storeRoot, removalsFile), []byte(torn), 0o600); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := removeOn(t, g, seedPath, "--receipt", "r/1", "--by", "operator-1")
		if code != 0 {
			t.Fatalf("exit %d %q", code, stderr)
		}
		if got := readFile(t, filepath.Join(g.storeRoot, removalsFile)); got != torn+"\n"+stdout {
			t.Fatalf("the file: %q", got)
		}
		if ok, said := verdictOf(t, g); !ok || said["1"] != "ok "+observationRemoved {
			t.Fatalf("the verdict: %v %v", ok, said)
		}
	})
}

// Bytes two receipts share are removed only when both are named in the run:
// named alone, the one is refused, naming the other.
func TestRemoveArtifactOfASharedDigest(t *testing.T) {
	g, seedPath := removalStore(t)
	tree := storeTree(t, g.storeRoot)
	code, stdout, stderr := removeOn(t, g, seedPath, "--receipt", "r/0", "--by", "operator-1")
	if want := "remove-artifact: receipt r/0 shares its bytes with r/2, which keeps them; its bytes are kept\n" + unlockedLine(); code != 1 || stdout != "" || stderr != want {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	if !sameEntries(storeTree(t, g.storeRoot), tree) {
		t.Fatal("the store changed")
	}
	code, stdout, stderr = removeOn(t, g, seedPath, "--receipt", "r/0", "--receipt", "r/2", "--by", "operator-1")
	if code != 0 || strings.Count(stdout, "\n") != 2 || stderr != unlockedLine() {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	if ok, said := verdictOf(t, g); !ok || said["0"] != "ok "+observationRemoved || said["2"] != "ok "+observationRemoved {
		t.Fatalf("the verdict: %v %v", ok, said)
	}
}

// A receipt that kept nothing shares the bytes of a kept one and needs none
// of them: the kept one is removed, and the other is then ok with
// artifact-not-retained.
func TestRemoveArtifactBesideAReceiptThatKeptNothing(t *testing.T) {
	t.Setenv(envSourceHelper, "1")
	t.Setenv(envSourceEchoStdin, "1")
	root := t.TempDir()
	g, err := newGatewayService(filepath.Join(root, "store"), testSeed, "gateway:test", filepath.Join(root, "registry.jsonl"),
		map[string]sourceSpec{
			"kept":   {argv: []string{os.Args[0]}, env: helperEnv},
			"unkept": {argv: []string{os.Args[0]}, env: helperEnv, notRetained: true},
		})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(g.handler())
	for _, body := range []string{
		`{"session":"r","source":"kept","arguments":{"q":"a"}}`,
		`{"session":"r","source":"unkept","arguments":{"q":"a"}}`,
	} {
		if code, out := post(t, server, "/acquire", body); code != http.StatusOK {
			t.Fatalf("acquire: %d %v", code, out)
		}
	}
	post(t, server, "/seal", `{"session":"r"}`)
	server.Close()
	if ok, said := verdictOf(t, g); !ok || said["1"] != "ok" {
		t.Fatalf("before: the bytes the kept call wrote are re-digested for the other: %v %v", ok, said)
	}
	code, _, stderr := removeOn(t, g, writeSeedFile(t, t.TempDir(), testSeed), "--receipt", "r/0", "--by", "operator-1")
	if code != 0 {
		t.Fatalf("exit %d %q", code, stderr)
	}
	if ok, said := verdictOf(t, g); !ok || said["0"] != "ok "+observationRemoved || said["1"] != "ok "+observationNotRetained {
		t.Fatalf("after: %v %v", ok, said)
	}
}

// A receipt of a scoped source is removed only under --scope giving its
// scope byte for byte; every refusal is the one sentence, and quotes no
// scope identifier.
func TestRemoveArtifactRespectsScope(t *testing.T) {
	g, seedPath := removalStore(t)
	tree := storeTree(t, g.storeRoot)
	sentence := func(name string) string {
		return "remove-artifact: receipt " + name + ": the receipt's scope does not match --scope; its bytes are not removed\n" + unlockedLine()
	}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"a scoped receipt without --scope", []string{"--receipt", "r/4"}, sentence("r/4")},
		{"another scope", []string{"--receipt", "r/4", "--scope", "équipe-b"}, sentence("r/4")},
		{"the same letters decomposed", []string{"--receipt", "r/4", "--scope", "équipe-a"}, sentence("r/4")},
		{"--scope for a receipt that carries none", []string{"--receipt", "r/1", "--scope", testScope}, sentence("r/1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := removeOn(t, g, seedPath, append(tc.args, "--by", "operator-1")...)
			if code != 1 || stdout != "" || stderr != tc.want || strings.Contains(stderr, "quipe") {
				t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
			}
			if !sameEntries(storeTree(t, g.storeRoot), tree) {
				t.Fatal("the store changed")
			}
		})
	}
	code, _, stderr := removeOn(t, g, seedPath, "--receipt", "r/4", "--scope", testScope, "--by", "operator-1")
	if code != 0 {
		t.Fatalf("the scope given: exit %d %q", code, stderr)
	}
	if ok, said := verdictOf(t, g); !ok || said["4"] != "ok "+observationRemoved {
		t.Fatalf("the verdict: %v %v", ok, said)
	}
}

// What the command refuses, each receipt named, exit 1, and the store as it
// was; a receipt refused leaves the others named in the run to be removed.
func TestRemoveArtifactRefusesWhatItMayNotRemove(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, g *gatewayService)
		receipt string
		want    string
	}{
		{"a receipt the store does not hold", nil, "r/9", "receipt r/9 is not in the store; nothing is removed for it"},
		{"a session the store does not hold", nil, "ghost/0", "receipt ghost/0 is not in the store; nothing is removed for it"},
		{"a receipt that kept nothing", nil, "r/3", "receipt r/3 says its call kept no payload; there is nothing to remove"},
		{"a receipt whose bytes are gone with no record", func(t *testing.T, g *gatewayService) {
			if err := os.Remove(filepath.Join(g.storeRoot, "artifacts", storedDigestOf(t, g, "r", "1"))); err != nil {
				t.Fatal(err)
			}
		}, "r/1", "receipt r/1 does not verify under the keys the registry's walk reached (artifact-missing); its bytes are not removed"},
		{"a receipt whose signature does not hold", func(t *testing.T, g *gatewayService) {
			path := filepath.Join(g.storeRoot, "receipts", "r", "1.json")
			text := readFile(t, path)
			// the signature's last hexadecimal digit changed: of its form,
			// and not the key's over this receipt
			at := strings.Index(text, `"signature":"`) + len(`"signature":"`) + 127
			flipped := map[byte]byte{'0': '1'}[text[at]]
			if flipped == 0 {
				flipped = '0'
			}
			text = text[:at] + string(flipped) + text[at+1:]
			if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "r/1", "receipt r/1 does not verify under the keys the registry's walk reached (signature-mismatch); its bytes are not removed"},
		{"bytes a descriptor provenance in the store reads", func(t *testing.T, g *gatewayService) {
			writeStoreFile(t, g, "receipts/x/0.json", `{"acquisition":{"descriptorProvenance":{"binding":"b@sha256:`+strings.Repeat("0", 64)+`","snapshot":"sha256:`+storedDigestOf(t, g, "r", "1")+`","statement":"sha256:`+strings.Repeat("1", 64)+`"}}}`+"\n")
		}, "r/1", "receipt r/1: its digest is a descriptor snapshot's or statement's in the store, which descriptor provenance reads there; its bytes are kept"},
		{"bytes a file the parser refuses spells", func(t *testing.T, g *gatewayService) {
			writeStoreFile(t, g, "receipts/y/0.json", `{"resultDigest":"sha256:`+storedDigestOf(t, g, "r", "1"))
		}, "r/1", "receipt r/1 shares its bytes with y/0, which keeps them; its bytes are kept"},
		{"bytes a receipt that does not verify reads", func(t *testing.T, g *gatewayService) {
			writeStoreFile(t, g, "receipts/y/0.json", `{"resultDigest":"sha256:`+storedDigestOf(t, g, "r", "1")+`"}`+"\n")
		}, "r/1", "receipt r/1 shares its bytes with y/0, which keeps them; its bytes are kept"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, seedPath := removalStore(t)
			if tc.prepare != nil {
				tc.prepare(t, g)
			}
			tree := storeTree(t, g.storeRoot)
			code, stdout, stderr := removeOn(t, g, seedPath, "--receipt", tc.receipt, "--by", "operator-1")
			if want := "remove-artifact: " + tc.want + "\n" + unlockedLine(); code != 1 || stdout != "" || stderr != want {
				t.Fatalf("exit %d\nstdout %q\nstderr %q\nwant   %q", code, stdout, stderr, want)
			}
			if !sameEntries(storeTree(t, g.storeRoot), tree) {
				t.Fatal("the store changed")
			}
		})
	}
	t.Run("one refused beside one removed", func(t *testing.T) {
		g, seedPath := removalStore(t)
		code, stdout, stderr := removeOn(t, g, seedPath, "--receipt", "r/3", "--receipt", "r/1", "--by", "operator-1")
		if want := "remove-artifact: receipt r/3 says its call kept no payload; there is nothing to remove\n" + unlockedLine(); code != 1 || strings.Count(stdout, "\n") != 1 || stderr != want {
			t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
		}
		if ok, said := verdictOf(t, g); !ok || said["1"] != "ok "+observationRemoved {
			t.Fatalf("the verdict: %v %v", ok, said)
		}
	})
	t.Run("removal records that cannot be read", func(t *testing.T) {
		g, seedPath := removalStore(t)
		if err := os.Mkdir(filepath.Join(g.storeRoot, removalsFile), 0o755); err != nil {
			t.Fatal(err)
		}
		tree := storeTree(t, g.storeRoot)
		code, stdout, stderr := removeOn(t, g, seedPath, "--receipt", "r/1", "--by", "operator-1")
		if code != 1 || stdout != "" || !strings.HasSuffix(stderr, "is not a regular file, and nothing was removed\n") {
			t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
		}
		if !sameEntries(storeTree(t, g.storeRoot), tree) {
			t.Fatal("the store changed")
		}
	})
}

func writeStoreFile(t *testing.T, g *gatewayService, rel, text string) {
	t.Helper()
	path := filepath.Join(g.storeRoot, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// An action's result is kept: /act and its recovery read it back.
func TestRemoveArtifactRefusesAnAction(t *testing.T) {
	vec, storeRoot, registry := removalVector(t, "v3-action-policy")
	var stdout, stderr bytes.Buffer
	code := cmdRemoveArtifactAt([]string{"--store", storeRoot, "--seed", writeSeedFile(t, t.TempDir(), corpusSeed(t)), "--registry", registry, "--authority", vec.Authority, "--receipt", "s2/1", "--by", "operator-1"},
		&stdout, &stderr, fixedStamp(removalStamp))
	if want := "remove-artifact: receipt s2/1 is an action, whose result /act and its recovery read back; its bytes are kept\n" + unlockedLine(); code != 1 || stdout.String() != "" || stderr.String() != want {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout.String(), stderr.String())
	}
}

// removalVector is a corpus store vector, materialized.
func removalVector(t *testing.T, name string) (vec storeVector, storeRoot, registry string) {
	t.Helper()
	readJSON(t, corpusPath("v3", "stores", name+".json"), &vec)
	tmp, storeRoot, registry, _, err := materializeVector(vec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	return vec, storeRoot, registry
}

func TestRemoveArtifactCommandLine(t *testing.T) {
	g, seedPath := removalStore(t)
	base := []string{"--store", g.storeRoot, "--seed", seedPath, "--registry", g.regPath, "--authority", g.authority}
	for _, tc := range []struct {
		name string
		args []string
		msg  string
	}{
		{"no --receipt", append(append([]string{}, base...), "--by", "x"), ""},
		{"no --by", append(append([]string{}, base...), "--receipt", "r/1"), ""},
		{"no store", []string{"--receipt", "r/1", "--by", "x"}, ""},
		{"an unknown option", append(append([]string{}, base...), "--receipt", "r/1", "--by", "x", "--all"), ""},
		{"a receipt of no session", append(append([]string{}, base...), "--receipt", "1", "--by", "x"), "--receipt names a receipt as <sessionId>/<callIndex>: a session id of ^[A-Za-z0-9._-]{1,128}$ and a call index in decimal"},
		{"a call index with a leading zero", append(append([]string{}, base...), "--receipt", "r/01", "--by", "x"), "--receipt names a receipt as <sessionId>/<callIndex>: a session id of ^[A-Za-z0-9._-]{1,128}$ and a call index in decimal"},
		{"a call index past 2^53-1", append(append([]string{}, base...), "--receipt", "r/9007199254740992", "--by", "x"), "--receipt names a call index from 0 to 2^53-1"},
		{"a receipt named twice", append(append([]string{}, base...), "--receipt", "r/1", "--receipt", "r/1", "--by", "x"), "receipt r/1 is named twice"},
		{"--by twice", append(append([]string{}, base...), "--receipt", "r/1", "--by", "x", "--by", "y"), "--by is given twice"},
		{"a label of another form", append(append([]string{}, base...), "--receipt", "r/1", "--by", "a\tb"), "--by is a label of the form of a scope identifier: " + scopeForm},
		{"a scope of another form", append(append([]string{}, base...), "--receipt", "r/1", "--by", "x", "--scope", "a\nb"), "--scope is a scope identifier: " + scopeForm},
		{"--config beside --store", []string{"--config", "engine.json", "--store", "s", "--receipt", "r/1", "--by", "x"}, "--config names the store, the seed, the registry and the authority; --store is not given beside it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			want := removeArtifactUsage + "\n"
			if tc.msg != "" {
				want = "remove-artifact: " + tc.msg + "\n" + want
			}
			if code := cmdRemoveArtifactAt(tc.args, &stdout, &stderr, fixedStamp(removalStamp)); code != 2 || stdout.String() != "" || stderr.String() != want {
				t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout.String(), stderr.String())
			}
		})
	}
	if _, err := os.Lstat(filepath.Join(g.storeRoot, removalsFile)); !os.IsNotExist(err) {
		t.Fatalf("a usage error wrote the removal file: %v", err)
	}
}

// A citation of a receipt removed under a record, or of one that kept
// nothing, resolves as a citation of any receipt that verifies (SPEC.md §6,
// "Citations of such receipts"); with the record gone, the citation is of a
// receipt that does not verify (artifact-missing), as act_test.go holds of
// any receipt whose bytes are gone.
func TestACitationOfARemovedReceiptResolves(t *testing.T) {
	g, seedPath := removalStore(t)
	if code, _, stderr := removeOn(t, g, seedPath, "--receipt", "r/1", "--by", "operator-1"); code != 0 {
		t.Fatalf("exit %d %q", code, stderr)
	}
	keys, err := g.reachedKeys()
	if err != nil {
		t.Fatal(err)
	}
	signatureOf := func(index string) string {
		v, err := parseJSON([]byte(readFile(t, filepath.Join(g.storeRoot, "receipts", "r", index+".json"))))
		if err != nil {
			t.Fatal(err)
		}
		s, _ := memberString(v.(*vObject), "signature")
		return s
	}
	for _, index := range []int64{1, 3} {
		if got := g.resolveCitation(citation{sessionID: "r", callIndex: index, signature: signatureOf(strconv.FormatInt(index, 10))}, keys); got != "" {
			t.Fatalf("r/%d: %q", index, got)
		}
	}
	if err := os.Remove(filepath.Join(g.storeRoot, removalsFile)); err != nil {
		t.Fatal(err)
	}
	if got := g.resolveCitation(citation{sessionID: "r", callIndex: 1, signature: signatureOf("1")}, keys); got != "the receipt does not verify under this engine's keys (artifact-missing)" {
		t.Fatalf("the record gone: %q", got)
	}
	if err := os.Mkdir(filepath.Join(g.storeRoot, removalsFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := g.resolveCitation(citation{sessionID: "r", callIndex: 3, signature: signatureOf("3")}, keys); got != "the store's removal records cannot be read" {
		t.Fatalf("records that cannot be read: %q", got)
	}
}

// gateway seal-open seals a session left open whose receipts are whole with
// one removed under a record and one that kept nothing.
func TestSealOpenSealsASessionHoldingRemovedReceipts(t *testing.T) {
	t.Setenv(envSourceHelper, "1")
	t.Setenv(envSourceEchoStdin, "1")
	root := t.TempDir()
	g, err := newGatewayService(filepath.Join(root, "store"), testSeed, "gateway:test", filepath.Join(root, "registry.jsonl"),
		map[string]sourceSpec{
			"kept":   {argv: []string{os.Args[0]}, env: helperEnv},
			"unkept": {argv: []string{os.Args[0]}, env: helperEnv, notRetained: true},
		})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(g.handler())
	for _, body := range []string{
		`{"session":"left","source":"kept","arguments":{"q":"a"}}`,
		`{"session":"left","source":"unkept","arguments":{"q":"b"}}`,
	} {
		if code, out := post(t, server, "/acquire", body); code != http.StatusOK {
			t.Fatalf("acquire: %d %v", code, out)
		}
	}
	server.Close()
	seedPath := writeSeedFile(t, t.TempDir(), testSeed)
	var stdout, stderr bytes.Buffer
	if code := cmdRemoveArtifactAt([]string{"--store", g.storeRoot, "--seed", seedPath, "--registry", g.regPath, "--authority", g.authority, "--receipt", "left/0", "--by", "operator-1"},
		&stdout, &stderr, fixedStamp(removalStamp)); code != 0 {
		t.Fatalf("remove: exit %d %q", code, stderr.String())
	}
	code, sealed, said := sealOpenOn(t, g, seedPath, "2026-11-13T00:00:02Z", "--session", "left")
	if code != 0 || strings.Count(sealed, "\n") != 1 || !strings.Contains(sealed, `"finalCount":2`) {
		t.Fatalf("seal-open: exit %d\nstdout %q\nstderr %q", code, sealed, said)
	}
}

// The bytes are re-digested once more just before they are removed: bytes
// that are not the digest's -- changed after the ladder passed the receipt
// -- are not removed, and the record, appended before, makes the receipt
// artifact-mismatch, never a pass.
func TestRemoveKeptBytesRefusesBytesThatAreNotTheDigests(t *testing.T) {
	root := t.TempDir()
	digest := digestOfBytes([]byte("kept"))
	path := filepath.Join(root, "artifacts", digest)
	writeStoreFile(t, &gatewayService{storeRoot: root}, "artifacts/"+digest, "changed")
	if gone, err := removeKeptBytes(root, "sha256:"+digest); gone || err == nil || !strings.Contains(err.Error(), "are not the receipt's, and are not removed") {
		t.Fatalf("gone %v: %v", gone, err)
	}
	if readFile(t, path) != "changed" {
		t.Fatal("the bytes were removed")
	}
	if err := os.WriteFile(path, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	if gone, err := removeKeptBytes(root, "sha256:"+digest); !gone || err != nil {
		t.Fatalf("gone %v: %v", gone, err)
	}
	if gone, err := removeKeptBytes(root, "sha256:"+digest); gone || err != nil {
		t.Fatalf("nothing there: gone %v: %v", gone, err)
	}
}
