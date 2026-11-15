package main

// gateway remove-scope (SPEC.md §1.3a, "A removed session", and §6,
// "Removing one scope identifier's records"; ADR-0034): a scope's sessions
// removed beside another's, recorded first, what a verifier then reads, and
// what refuses the whole call.

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// otherScope is the scope identifier of the sessions a removal leaves.
const otherScope = "équipe-b"

// scopeStore is a stopped gateway's store:
//
//	a1  sealed  a1/0 of testScope (q only-a), a1/1 of testScope (q shared)
//	a2  open    a2/0 of testScope (q open-a)
//	b1  sealed  b1/0 of otherScope (q shared), b1/1 of otherScope (q only-b)
//
// with the acquisitions extra names (session, source, q) made before the
// seals, of source a (testScope), b (otherScope) or plain (no scope).
func scopeStore(t *testing.T, extra ...[3]string) (*gatewayService, string) {
	t.Helper()
	t.Setenv(envSourceHelper, "1")
	t.Setenv(envSourceEchoStdin, "1")
	root := t.TempDir()
	g, err := newGatewayService(filepath.Join(root, "store"), testSeed, "gateway:test", filepath.Join(root, "registry.jsonl"),
		map[string]sourceSpec{
			"a":     {argv: []string{os.Args[0]}, env: helperEnv, scope: testScope},
			"b":     {argv: []string{os.Args[0]}, env: helperEnv, scope: otherScope},
			"plain": {argv: []string{os.Args[0]}, env: helperEnv},
		})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(g.handler())
	defer server.Close()
	scopes := map[string]string{"a": testScope, "b": otherScope}
	calls := append([][3]string{{"a1", "a", "only-a"}, {"a1", "a", "shared"}, {"a2", "a", "open-a"}, {"b1", "b", "shared"}, {"b1", "b", "only-b"}}, extra...)
	for _, c := range calls {
		body := `{"session":"` + c[0] + `","source":"` + c[1] + `","arguments":{"q":"` + c[2] + `"}}`
		if scope, scoped := scopes[c[1]]; scoped {
			body = `{"session":"` + c[0] + `","source":"` + c[1] + `","scope":` + jsonText(t, scope) + `,"arguments":{"q":"` + c[2] + `"}}`
		}
		if code, out := post(t, server, "/acquire", body); code != http.StatusOK {
			t.Fatalf("acquire %s: %d %v", body, code, out)
		}
	}
	for _, session := range []string{"a1", "b1"} {
		if code, out := post(t, server, "/seal", `{"session":"`+session+`"}`); code != http.StatusOK {
			t.Fatalf("seal %s: %d %v", session, code, out)
		}
	}
	return g, writeSeedFile(t, t.TempDir(), testSeed)
}

// removeScopeOn runs the command on a store scopeStore made, by its flags.
func removeScopeOn(t *testing.T, g *gatewayService, seedPath string, rest ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	args := append([]string{"--store", g.storeRoot, "--seed", seedPath, "--registry", g.regPath, "--authority", g.authority}, rest...)
	code := cmdRemoveScopeAt(args, &stdout, &stderr, fixedStamp(removalStamp))
	return code, stdout.String(), stderr.String()
}

// scopeUnlockedLine is what the command says last on a platform that locks
// no registry.
func scopeUnlockedLine() string {
	if registryLocked {
		return ""
	}
	return "remove-scope: this platform locks no registry, so a gateway still running was not looked for; the gateway was to be stopped\n"
}

// scopeVerdict is the store's verdict: ok, every finding that is not a
// receipt's ok as "<session>[/<index>] <status>", and every observation as
// "<session>[/<index>] <observation>".
func scopeVerdict(t *testing.T, g *gatewayService) (bool, []string, []string) {
	t.Helper()
	rep, err := verifyWithRegistry(g.storeRoot, g.regPath, g.authority, g.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	name := func(f finding) string {
		s, _ := f["sessionId"].(string)
		if index, ok := f["callIndex"]; ok {
			return s + "/" + fmt.Sprint(index)
		}
		return s
	}
	var findings, observations []string
	for _, f := range rep.Findings {
		if f["status"] != "ok" {
			findings = append(findings, name(f)+" "+f["status"].(string))
		}
	}
	for _, o := range rep.Observations {
		observations = append(observations, name(o)+" "+o["observation"].(string))
	}
	return rep.OK, findings, observations
}

// filesHolding are the files under root whose bytes hold s, by their path
// from root.
func filesHolding(t *testing.T, root, s string) []string {
	t.Helper()
	var held []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(s)) {
			rel, _ := filepath.Rel(root, path)
			held = append(held, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return held
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// The scope's sessions and the payloads only they name are removed; the
// other scope's sessions, and a payload they name too, are kept. The
// command prints the records, which are the file: one session-removal
// record for the sealed session, naming its seal, and one scope-removal
// record of the counts. The store then verifies ok, the removed sealed
// session observed session-removed, and the scope identifier is in no file
// of the store but the removal file. A second run changes nothing; with the
// session's record taken away, it is sealed-session-missing again.
func TestRemoveScopeRemovesTheScopesSessionsBesideAnother(t *testing.T) {
	g, seedPath := scopeStore(t)
	onlyA, shared, openA := storedDigestOf(t, g, "a1", "0"), storedDigestOf(t, g, "a1", "1"), storedDigestOf(t, g, "a2", "0")
	if storedDigestOf(t, g, "b1", "0") != shared {
		t.Fatal("the fixture: b1/0 and a1/1 do not share their payload")
	}
	b1 := storeTree(t, filepath.Join(g.storeRoot, "receipts", "b1"))

	code, stdout, stderr := removeScopeOn(t, g, seedPath, "--scope", testScope, "--by", "operator-1")
	if code != 0 || stderr != "remove-scope: removed 2 session(s), 1 sealed, holding 3 receipt(s), and 2 payload(s)\n"+scopeUnlockedLine() {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	file := readFile(t, filepath.Join(g.storeRoot, removalsFile))
	lines := strings.Split(strings.TrimSuffix(file, "\n"), "\n")
	if stdout != file || len(lines) != 2 {
		t.Fatalf("the lines printed %q are not the file %q", stdout, file)
	}
	keys, err := g.reachedKeys()
	if err != nil {
		t.Fatal(err)
	}
	walk, err := engineWalk([]byte(readFile(t, g.regPath)), g.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	set, _, err := scanRecords(strings.NewReader(file), keys)
	if err != nil {
		t.Fatal(err)
	}
	recs := set.sessions["a1"]
	seal := walk.seals["a1"]
	if len(recs) != 1 || recs[0].sealSignature != seal.signature || recs[0].finalCount != 2 || recs[0].scope != testScope ||
		recs[0].removedAt != removalStamp || recs[0].removedBy != "operator-1" || recs[0].keyID != keyIDFor(g.publicKey) || len(set.sessions) != 1 {
		t.Fatalf("the session-removal records: %+v", set.sessions)
	}
	v, err := parseJSON([]byte(lines[1]))
	if err != nil {
		t.Fatal(err)
	}
	scoped, ok := scopeRemovalOf(v.(*vObject), keys)
	if !ok || scoped.scope != testScope || scoped.sealedSessions != 1 || scoped.openSessions != 1 || scoped.receipts != 3 || scoped.payloads != 2 {
		t.Fatalf("the scope-removal record: %v %+v", ok, scoped)
	}

	for _, gone := range []string{"receipts/a1", "receipts/a2", "artifacts/" + onlyA, "artifacts/" + openA} {
		if exists(filepath.Join(g.storeRoot, gone)) {
			t.Fatalf("%s is still there", gone)
		}
	}
	if !exists(filepath.Join(g.storeRoot, "artifacts", shared)) {
		t.Fatal("the payload b1/0 names too was removed")
	}
	if !sameEntries(storeTree(t, filepath.Join(g.storeRoot, "receipts", "b1")), b1) {
		t.Fatal("the other scope's session changed")
	}
	ok, findings, observations := scopeVerdict(t, g)
	if !ok || len(findings) != 0 || strings.Join(observations, ",") != "a1 "+observationSessionRemoved {
		t.Fatalf("the verdict: %v %v %v", ok, findings, observations)
	}
	if held := filesHolding(t, g.storeRoot, testScope); strings.Join(held, ",") != removalsFile {
		t.Fatalf("the scope identifier is in %v", held)
	}

	code, stdout, stderr = removeScopeOn(t, g, seedPath, "--scope", testScope, "--by", "operator-1")
	if code != 0 || stdout != "" || stderr != "remove-scope: no session of the scope identifier is in the store; nothing was removed\n"+scopeUnlockedLine() {
		t.Fatalf("a second run: exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	if readFile(t, filepath.Join(g.storeRoot, removalsFile)) != file {
		t.Fatal("a second run changed the removal file")
	}

	if err := os.WriteFile(filepath.Join(g.storeRoot, removalsFile), []byte(lines[1]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, findings, observations = scopeVerdict(t, g)
	if ok || strings.Join(findings, ",") != "a1 sealed-session-missing" || len(observations) != 0 {
		t.Fatalf("the record taken away: %v %v %v", ok, findings, observations)
	}
}

// A session holding a receipt that carries the scope beside one that does
// not -- of another scope identifier, of none, or one whose signature does
// not verify -- refuses the whole call by name: nothing is written or
// removed, the other sessions of the scope included, and no refusal names
// the scope identifier.
func TestRemoveScopeRefusesASessionOfMixedScopesWhole(t *testing.T) {
	g, seedPath := scopeStore(t, [3]string{"m", "a", "m-a"}, [3]string{"m", "b", "m-b"}, [3]string{"n", "a", "n-a"}, [3]string{"n", "plain", "n-plain"})
	// a1/1 changed after signing, its scope as it was: it no longer
	// verifies, whatever it says
	digest := storedDigestOf(t, g, "a1", "1")
	changed := digest[:63] + string("10"[map[bool]int{true: 1}[digest[63] == '1']])
	path := filepath.Join(g.storeRoot, "receipts", "a1", "1.json")
	if err := os.WriteFile(path, bytes.Replace([]byte(readFile(t, path)), []byte(digest), []byte(changed), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	tree := storeTree(t, g.storeRoot)
	code, stdout, stderr := removeScopeOn(t, g, seedPath, "--scope", testScope, "--by", "operator-1")
	mixed := func(session, others string) string {
		return "remove-scope: session " + session + " holds receipts of the scope identifier beside " + others + ", of another scope identifier, of none, or not verifying under the keys the registry's walk reached; the session is left whole\n"
	}
	want := mixed("a1", "a1/1") + mixed("m", "m/1") + mixed("n", "n/1") + "remove-scope: nothing was removed\n" + scopeUnlockedLine()
	if code != 1 || stdout != "" || stderr != want || strings.Contains(stderr, "quipe") {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	if !sameEntries(storeTree(t, g.storeRoot), tree) {
		t.Fatal("the store changed")
	}
}

// A receipt left in the store that cites a receipt the call would remove --
// in an action's cites, whether or not it verifies -- or whose bytes do not
// parse and spell such a receipt's signature, and a payload's path holding
// something that is not a regular file, refuse the whole call by name.
func TestRemoveScopeRefusesWhatItCannotRemoveWhole(t *testing.T) {
	vector := readStoreVector(t, "v3-action-remote-transport-valid")
	action := vector.Files["receipts/s2/1.json"]
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, g *gatewayService)
		want  string
	}{
		{"an action citing a removed receipt", func(t *testing.T, g *gatewayService) {
			writeStoreFile(t, g, "receipts/c/1.json", strings.Replace(action, `"sessionId":"s2","signature"`, `"sessionId":"a1","signature"`, 1))
		}, "remove-scope: receipt c/1 cites receipt a1/0, of session a1, which the call would remove; its citation would no longer resolve\n"},
		{"bytes that spell a removed receipt's signature", func(t *testing.T, g *gatewayService) {
			v, err := parseJSON([]byte(readFile(t, filepath.Join(g.storeRoot, "receipts", "a2", "0.json"))))
			if err != nil {
				t.Fatal(err)
			}
			signature, _ := memberString(v.(*vObject), "signature")
			writeStoreFile(t, g, "receipts/c/0.json", `{"cites":[{"signature":"`+signature+`"}]`)
		}, "remove-scope: receipt c/0 does not parse, and its bytes spell the signature of receipt a2/0, which the call would remove; it is left as it is\n"},
		{"a directory at a payload's path", func(t *testing.T, g *gatewayService) {
			path := filepath.Join(g.storeRoot, "artifacts", storedDigestOf(t, g, "a2", "0"))
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}, "remove-scope: the payload a receipt of session a2 names is at a path that holds something other than a regular file; it is not removed\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, seedPath := scopeStore(t)
			tc.setup(t, g)
			tree := storeTree(t, g.storeRoot)
			code, stdout, stderr := removeScopeOn(t, g, seedPath, "--scope", testScope, "--by", "operator-1")
			if code != 1 || stdout != "" || stderr != tc.want+"remove-scope: nothing was removed\n"+scopeUnlockedLine() || strings.Contains(stderr, "quipe") {
				t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
			}
			if !sameEntries(storeTree(t, g.storeRoot), tree) {
				t.Fatal("the store changed")
			}
		})
	}
}

// A sealed session's directory a run cut off left empty -- its receipts
// gone, its directory not -- is a session a verifier finds tail-rollback;
// a second run removes the directory a record of the scope names, beside
// the rest of the removal, and the store then verifies ok. An empty
// directory no record of the scope names is left as it is.
func TestRemoveScopeRemovesTheEmptyDirectoryOfASessionItRecorded(t *testing.T) {
	g, seedPath := scopeStore(t)
	if code, _, stderr := removeScopeOn(t, g, seedPath, "--scope", testScope, "--by", "operator-1"); code != 0 {
		t.Fatalf("exit %d %q", code, stderr)
	}
	file := readFile(t, filepath.Join(g.storeRoot, removalsFile))
	// as a run cut off after a1's receipts and before its directory leaves
	// it: a1 empty, a2 whole with its payload gone, as payloads go first
	for _, dir := range []string{"receipts/a1", "receipts/a2", "receipts/b2"} {
		if err := os.MkdirAll(filepath.Join(g.storeRoot, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	g2, _ := scopeStore(t)
	writeStoreFile(t, g, "receipts/a2/0.json", readFile(t, filepath.Join(g2.storeRoot, "receipts", "a2", "0.json")))
	if ok, findings, _ := scopeVerdict(t, g); ok || !strings.Contains(strings.Join(findings, ","), "a1 tail-rollback") {
		t.Fatalf("the directory left: %v %v", ok, findings)
	}
	code, stdout, stderr := removeScopeOn(t, g, seedPath, "--scope", testScope, "--by", "operator-1")
	want := "remove-scope: session a1 was recorded as removed already, and its directory held no receipt; the directory is removed now\n" +
		"remove-scope: removed 1 session(s), 0 sealed, holding 1 receipt(s), and 0 payload(s)\n" + scopeUnlockedLine()
	if code != 0 || strings.Count(stdout, "\n") != 1 || !strings.Contains(stdout, `"kind":"scope-removal"`) || stderr != want {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	if readFile(t, filepath.Join(g.storeRoot, removalsFile)) != file+stdout {
		t.Fatal("the second run appended other than its scope-removal record")
	}
	if exists(filepath.Join(g.storeRoot, "receipts", "a1")) || exists(filepath.Join(g.storeRoot, "receipts", "a2")) || !exists(filepath.Join(g.storeRoot, "receipts", "b2")) {
		t.Fatal("the directories")
	}
	// b2, an empty directory of no session sealed, is unregistered-session
	// as it was before the run
	ok, findings, observations := scopeVerdict(t, g)
	if ok || strings.Join(findings, ",") != "b2 unregistered-session" || strings.Join(observations, ",") != "a1 "+observationSessionRemoved {
		t.Fatalf("the verdict: %v %v %v", ok, findings, observations)
	}
}

// What the command refuses as a usage error: exit 2, and nothing written.
func TestRemoveScopeCommandLine(t *testing.T) {
	g, seedPath := scopeStore(t)
	base := []string{"--store", g.storeRoot, "--seed", seedPath, "--registry", g.regPath, "--authority", g.authority}
	with := func(rest ...string) []string { return append(append([]string{}, base...), rest...) }
	for _, tc := range []struct {
		name string
		args []string
		msg  string
	}{
		{"no --scope", with("--by", "x"), ""},
		{"no --by", with("--scope", testScope), ""},
		{"no store", []string{"--scope", testScope, "--by", "x"}, ""},
		{"an unknown option", with("--scope", testScope, "--by", "x", "--all"), ""},
		{"--receipt", with("--scope", testScope, "--by", "x", "--receipt", "a1/0"), ""},
		{"--scope twice", with("--scope", testScope, "--scope", otherScope, "--by", "x"), "--scope is given twice"},
		{"a scope of another form", with("--scope", "a\nb", "--by", "x"), "--scope is a scope identifier: " + scopeForm},
		{"a label of another form", with("--scope", testScope, "--by", "a\tb"), "--by is a label of the form of a scope identifier: " + scopeForm},
		{"--config beside --store", []string{"--config", "engine.json", "--store", "s", "--scope", testScope, "--by", "x"}, "--config names the store, the seed, the registry and the authority; --store is not given beside it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			want := removeScopeUsage + "\n"
			if tc.msg != "" {
				want = "remove-scope: " + tc.msg + "\n" + want
			}
			if code := cmdRemoveScopeAt(tc.args, &stdout, &stderr, fixedStamp(removalStamp)); code != 2 || stdout.String() != "" || stderr.String() != want {
				t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout.String(), stderr.String())
			}
		})
	}
	if exists(filepath.Join(g.storeRoot, removalsFile)) {
		t.Fatal("a usage error wrote the removal file")
	}
}
