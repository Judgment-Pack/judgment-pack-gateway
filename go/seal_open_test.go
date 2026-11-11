package main

// gateway seal-open (gateway #395; SPEC.md §3c): the seal it writes, byte for
// byte against the hand-written corpus; what it refuses, and that a refusal
// changes nothing; --all; and a session so sealed, never continued.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusSeed is the corpus's published TEST-SEED, the key its vectors are
// signed by (testSeed is another).
func corpusSeed(t *testing.T) []byte {
	t.Helper()
	return mustHex(t, strings.TrimSpace(readFile(t, corpusPath("TEST-SEED"))))
}

// corpusRotationKey1 is the seed of the corpus's rotation key 1, the key
// rotation-followed-twice rotates to first (corpus/README.md).
func corpusRotationKey1() []byte {
	sum := sha256.Sum256([]byte("judgment-pack-gateway corpus rotation key 1"))
	return sum[:]
}

// writeSeedFile is seed, in the hex form keygen writes, in a file of dir.
func writeSeedFile(t *testing.T, dir string, seed []byte) string {
	t.Helper()
	path := filepath.Join(dir, "seed")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// sealOpenVector is a corpus vector whose registry ends in a seal made after
// an interruption, materialized with the registry as it stood before that
// seal; sealLine is the seal, as the corpus holds it.
func sealOpenVector(t *testing.T, name string) (vec storeVector, storeRoot, registry, sealLine string) {
	t.Helper()
	readJSON(t, corpusPath("stores", name+".json"), &vec)
	lines := strings.SplitAfter(vec.Registry, "\n")
	if len(lines) < 2 || lines[len(lines)-1] != "" || !strings.Contains(lines[len(lines)-2], `"kind":"seal-after-interruption"`) {
		t.Fatalf("%s: the registry does not end in a seal made after an interruption", name)
	}
	sealLine = strings.TrimSuffix(lines[len(lines)-2], "\n")
	tmp, storeRoot, registry, _, err := materializeVector(vec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	if err := os.WriteFile(registry, []byte(strings.Join(lines[:len(lines)-2], "")), 0o600); err != nil {
		t.Fatal(err)
	}
	return vec, storeRoot, registry, sealLine
}

// The command writes the seal the corpus holds, byte for byte: the members
// in code-point order and the signature over §3c's prefix, by the key the
// registry's walk ends at -- after a rotation, the key rotated to, over
// receipts the key rotated from signed. It prints the line it appended and
// nothing else. The start's sealing writes the same line, sealedVia start.
func TestSealOpenWritesTheSealTheCorpusHolds(t *testing.T) {
	for _, tc := range []struct {
		vector string
		seed   []byte
	}{
		{"interruption-seal", corpusSeed(t)},
		{"interruption-seal-after-rotation", corpusRotationKey1()},
	} {
		vec, storeRoot, registry, sealLine := sealOpenVector(t, tc.vector)
		seedPath := writeSeedFile(t, t.TempDir(), tc.seed)
		var stdout, stderr bytes.Buffer
		code := cmdSealOpenAt([]string{"--store", storeRoot, "--seed", seedPath, "--registry", registry, "--authority", vec.Authority, "--session", "s1"},
			&stdout, &stderr, fixedStamp("2026-11-10T00:00:01Z"))
		if code != 0 || stdout.String() != sealLine+"\n" || stderr.String() != "" {
			t.Fatalf("%s: exit %d\nstdout %q\nstderr %q\nwant stdout %q", tc.vector, code, stdout.String(), stderr.String(), sealLine+"\n")
		}
		if got := readFile(t, registry); got != vec.Registry {
			t.Fatalf("%s: the registry is\n%s\nnot\n%s", tc.vector, got, vec.Registry)
		}
	}

	vec, storeRoot, registry, sealLine := sealOpenVector(t, "interruption-seal-by-the-start")
	writer, err := newRegistryWriter(registry, corpusSeed(t), func() (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	sealed, refused, err := sealOpenUnder(storeRoot, vec.Authority, writer, []byte(readFile(t, registry)), "", sealedViaStart, fixedStamp("2026-11-10T00:00:01Z"))
	if err != nil || len(refused) != 0 || len(sealed) != 1 || string(canon(sealed[0])) != sealLine {
		t.Fatalf("the start's sealing: %v %q %v", err, refused, sealed)
	}
	if got := readFile(t, registry); got != vec.Registry {
		t.Fatalf("the start's sealing left the registry\n%s", got)
	}
}

// What the writer will not write: a seal no reader would load. The registry
// is not touched.
func TestSealAfterInterruptionWritesOnlyWhatLoads(t *testing.T) {
	_, _, registry, _ := sealOpenVector(t, "interruption-seal")
	writer, err := newRegistryWriter(registry, corpusSeed(t), func() (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	head := strings.Repeat("ab", 64)
	const refusal = "a seal after an interruption counts from 1 to 2^53-1 receipts, names the last one's signature in lowercase hexadecimal, is stamped YYYY-MM-DDThh:mm:ssZ, and is made by the command or the start"
	for _, tc := range []struct {
		name, head, at, via string
		count               int64
	}{
		{"no receipt", head, "2026-11-10T00:00:01Z", sealedViaCommand, 0},
		{"past 2^53-1", head, "2026-11-10T00:00:01Z", sealedViaCommand, maxSafeInteger + 1},
		{"the head in uppercase", strings.ToUpper(head), "2026-11-10T00:00:01Z", sealedViaCommand, 3},
		{"the head short", head[:126], "2026-11-10T00:00:01Z", sealedViaCommand, 3},
		{"a time of another form", head, "2026-11-10 00:00:01Z", sealedViaCommand, 3},
		{"by no path a seal is made by", head, "2026-11-10T00:00:01Z", "operator", 3},
	} {
		if _, err := writer.sealAfterInterruption("s1", tc.count, tc.head, tc.at, tc.via); err == nil || err.Error() != refusal {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
	if got := readFile(t, registry); got != "" {
		t.Fatalf("a refused seal wrote %q", got)
	}
	// a session the registry holds a seal of either kind for is sealed
	if _, err := writer.sealAfterInterruption("s1", 3, head, "2026-11-10T00:00:01Z", sealedViaCommand); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.sealAfterInterruption("s1", 3, head, "2026-11-10T00:00:02Z", sealedViaStart); err == nil || err.Error() != "session already sealed: s1" {
		t.Fatalf("a second seal after an interruption: %v", err)
	}
	if _, err := writer.seal("s1", 3, "2026-11-10T00:00:02Z"); err == nil || err.Error() != "session already sealed: s1" {
		t.Fatalf("an ordinary seal after one made after an interruption: %v", err)
	}
}

// storeTree is every file under root and what it holds, a directory as
// "dir": what a refusal must leave as it was.
func storeTree(t *testing.T, root string) map[string]string {
	t.Helper()
	tree := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			tree[rel] = "dir"
		} else {
			tree[rel] = readFile(t, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

// sealOpenOn runs the command on a store leftOpenStore made, by its flags,
// the seed in a file of its own.
func sealOpenOn(t *testing.T, g *gatewayService, seedPath string, at string, rest ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	args := append([]string{"--store", g.storeRoot, "--seed", seedPath, "--registry", g.regPath, "--authority", "gateway:test"}, rest...)
	code := cmdSealOpenAt(args, &stdout, &stderr, fixedStamp(at))
	return code, stdout.String(), stderr.String()
}

// What the command refuses, each named as it is, exit 1, and the store and
// the registry as they were: nothing sealed, changed or deleted.
func TestSealOpenRefusesWhatItMayNotSeal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, g *gatewayService, seedPath string)
		session string
		stderr  func(g *gatewayService, seedPath string) string
	}{
		{"a session sealed in the registry", nil, "closed",
			func(*gatewayService, string) string {
				return "seal-open: session closed is sealed in the registry; it is not sealed again\n"
			}},
		{"a session the store does not hold", nil, "ghost",
			func(*gatewayService, string) string { return "seal-open: session ghost is not in the store\n" }},
		{"a session holding no receipt", func(t *testing.T, g *gatewayService, _ string) {
			if err := os.Mkdir(filepath.Join(g.storeRoot, "receipts", "empty"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "empty", func(*gatewayService, string) string {
			return "seal-open: session empty holds no receipt; there is nothing to seal\n"
		}},
		{"a file where a session directory would be", func(t *testing.T, g *gatewayService, _ string) {
			if err := os.WriteFile(filepath.Join(g.storeRoot, "receipts", "flat"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "flat", func(*gatewayService, string) string {
			return "seal-open: session flat is in the store as something other than a session directory; nothing is sealed there\n"
		}},
		{"a session id §3a refuses", nil, "a/b",
			func(*gatewayService, string) string {
				return "seal-open: session id must match ^[A-Za-z0-9._-]{1,128}$\n"
			}},
		{"its last receipt torn", func(t *testing.T, g *gatewayService, _ string) {
			path := filepath.Join(g.storeRoot, "receipts", "left", "1.json")
			text := readFile(t, path)
			if err := os.WriteFile(path, []byte(text[:len(text)/2]), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "left", func(*gatewayService, string) string {
			return "seal-open: session left is not whole, so it is not sealed: file 1.json malformed; gateway verify reports what it finds of it, and nothing is changed or deleted\n"
		}},
		{"its first receipt gone", func(t *testing.T, g *gatewayService, _ string) {
			if err := os.Remove(filepath.Join(g.storeRoot, "receipts", "left", "0.json")); err != nil {
				t.Fatal(err)
			}
		}, "left", func(*gatewayService, string) string {
			return "seal-open: session left is not whole, so it is not sealed: sequence-broken; gateway verify reports what it finds of it, and nothing is changed or deleted\n"
		}},
		{"the registry not there", func(t *testing.T, g *gatewayService, _ string) {
			if err := os.Remove(g.regPath); err != nil {
				t.Fatal(err)
			}
		}, "left", func(g *gatewayService, _ string) string {
			return "seal-open: the registry is not there: " + g.regPath + "; a gateway makes it when it starts, and a seal is recorded in it\n"
		}},
		{"a rotation under way beside the seed", func(t *testing.T, _ *gatewayService, seedPath string) {
			if err := os.WriteFile(seedPath+".next", []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "left", func(g *gatewayService, seedPath string) string {
			return "seal-open: a rotation is pending: " + seedPath + ".next is there; finish it with gateway rotate-key --resume --seed " + seedPath + " --registry " + g.regPath + "\n"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := leftOpenStore(t)
			seedPath := writeSeedFile(t, t.TempDir(), testSeed)
			if tc.prepare != nil {
				tc.prepare(t, g, seedPath)
			}
			tree := storeTree(t, g.storeRoot)
			registry, _, _ := readRegistryBytes(g.regPath)
			code, stdout, stderr := sealOpenOn(t, g, seedPath, "2026-11-10T00:00:01Z", "--session", tc.session)
			if want := tc.stderr(g, seedPath); code != 1 || stdout != "" || stderr != want {
				t.Fatalf("exit %d\nstdout %q\nstderr %q\nwant   %q", code, stdout, stderr, want)
			}
			if after, _, _ := readRegistryBytes(g.regPath); !bytes.Equal(after, registry) {
				t.Fatalf("the registry changed: %q", after)
			}
			if !sameEntries(storeTree(t, g.storeRoot), tree) {
				t.Fatal("the store changed")
			}
		})
	}
}

// A seed whose key the registry rotated from is refused under the lock, as
// a gateway's start refuses it: a seal it signed would load nowhere.
func TestSealOpenRefusesASeedTheRegistryRotatedFrom(t *testing.T) {
	vec, storeRoot, registry, _ := sealOpenVector(t, "interruption-seal-after-rotation")
	before := readFile(t, registry)
	seedPath := writeSeedFile(t, t.TempDir(), corpusSeed(t))
	var stdout, stderr bytes.Buffer
	code := cmdSealOpenAt([]string{"--store", storeRoot, "--seed", seedPath, "--registry", registry, "--authority", vec.Authority, "--session", "s1"},
		&stdout, &stderr, fixedStamp("2026-11-10T00:00:01Z"))
	const want = "seal-open: the registry's rotations end at key 33719bd9925ba0b0ef0ddb302e5a3ef4, not this gateway's key ddb406e95cad582adc111a7d6fbff25d: a gateway does not start under a key its registry rotated from, and a rotation pending its switch is finished by gateway rotate-key --resume\n"
	if code != 1 || stdout.String() != "" || stderr.String() != want {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout.String(), stderr.String())
	}
	if readFile(t, registry) != before {
		t.Fatal("the registry changed")
	}
}

// --all seals each session no seal closes whose receipts are whole, passes
// over a sealed session and one holding no receipt, and names each one that
// is not whole, and a directory no session id names, each of which stays as
// it is; a staging file an interrupted write
// left is no receipt and is left where it is. Run again, it seals nothing
// more and names the same session.
func TestSealOpenAllSealsWhatIsWholeAndNamesWhatIsNot(t *testing.T) {
	g := leftOpenStore(t)
	server := httptest.NewServer(g.handler())
	if code, out := post(t, server, "/acquire", `{"session":"torn","source":"screening","arguments":{"q":"x"}}`); code != 200 {
		t.Fatalf("acquire: %d %v", code, out)
	}
	server.Close()
	torn := filepath.Join(g.storeRoot, "receipts", "torn", "0.json")
	text := readFile(t, torn)
	if err := os.WriteFile(torn, []byte(text[:len(text)/2]), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(g.storeRoot, "receipts", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(g.storeRoot, "receipts", "bad name"), 0o755); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(g.storeRoot, "receipts", "left", "2.json.4242.0123456789abcdef.tmp")
	if err := os.WriteFile(staging, []byte(`{"half":`), 0o600); err != nil {
		t.Fatal(err)
	}
	seedPath := writeSeedFile(t, t.TempDir(), testSeed)
	priv := ed25519.NewKeyFromSeed(testSeed)
	head := receiptSignature(t, g.storeRoot, "left", 1)
	const tornRefusal = "seal-open: the store's directory \"bad name\" is not named as a session is (SPEC.md §3a); it is not sealed\n" +
		"seal-open: session torn is not whole, so it is not sealed: file 0.json malformed; gateway verify reports what it finds of it, and nothing is changed or deleted\n"

	code, stdout, stderr := sealOpenOn(t, g, seedPath, "2026-11-10T00:00:01Z", "--all")
	want := interruptionSealLineBy(priv, g.keyID, "left", 2, head, "2026-11-10T00:00:01Z", "command") + "\n"
	if code != 1 || stdout != want || stderr != tornRefusal {
		t.Fatalf("exit %d\nstdout %q\nstderr %q\nwant   %q", code, stdout, stderr, want)
	}
	if readFile(t, staging) != `{"half":` || readFile(t, torn) != text[:len(text)/2] {
		t.Fatal("seal-open changed a file it found")
	}
	rep, err := verifyWithRegistry(g.storeRoot, g.regPath, "gateway:test", g.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := interruptedLines(rep); strings.Join(got, " ") != "left/1/sealed-after-interruption" {
		t.Fatalf("observations: %v", got)
	}

	registry := readFile(t, g.regPath)
	code, stdout, stderr = sealOpenOn(t, g, seedPath, "2026-11-10T00:00:02Z", "--all")
	if code != 1 || stdout != "" || stderr != tornRefusal || readFile(t, g.regPath) != registry {
		t.Fatalf("again: exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
}

// --all over a store with nothing left open seals nothing, says so, and
// succeeds.
func TestSealOpenAllWithNothingLeftOpen(t *testing.T) {
	g := leftOpenStore(t)
	seedPath := writeSeedFile(t, t.TempDir(), testSeed)
	if code, _, stderr := sealOpenOn(t, g, seedPath, "2026-11-10T00:00:01Z", "--session", "left"); code != 0 || stderr != "" {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	registry := readFile(t, g.regPath)
	code, stdout, stderr := sealOpenOn(t, g, seedPath, "2026-11-10T00:00:02Z", "--all")
	if code != 0 || stdout != "" || stderr != "seal-open: no session in the store is left open; nothing was sealed\n" || readFile(t, g.regPath) != registry {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
}

// A session sealed after an interruption is never continued: a gateway
// started on the store refuses to acquire into it, to seal it and to mint
// an action into it, each as a sealed session, and nothing is written.
func TestASessionSealedAfterAnInterruptionIsNeverContinued(t *testing.T) {
	g := leftOpenStore(t)
	seedPath := writeSeedFile(t, t.TempDir(), testSeed)
	if code, _, stderr := sealOpenOn(t, g, seedPath, "2026-11-10T00:00:01Z", "--session", "left"); code != 0 || stderr != "" {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	restarted, err := newGatewayService(g.storeRoot, testSeed, "gateway:test", g.regPath, g.sources)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(restarted.handler())
	defer server.Close()
	registry := readFile(t, g.regPath)
	held := sessionEntries(t, g.storeRoot, "left")
	const answer = `{"error":"session is sealed in the registry: left"}`
	for _, tc := range []struct{ path, body string }{
		{"/acquire", `{"session":"left","source":"screening","arguments":{"q":"z"}}`},
		{"/seal", `{"session":"left"}`},
	} {
		code, raw := postRawWith(t, server, tc.path, tc.body, "")
		if code != 400 || string(raw) != answer {
			t.Fatalf("%s: %d %q", tc.path, code, raw)
		}
	}
	if reason := restarted.sessionOpen("left"); reason != "session is sealed in the registry: left" {
		t.Fatalf("an action into it: %q", reason)
	}
	if readFile(t, g.regPath) != registry || !sameEntries(sessionEntries(t, g.storeRoot, "left"), held) {
		t.Fatal("a refusal wrote")
	}
}

// The command line: exactly one of --session and --all, the store, the seed,
// the registry and the authority by their flags or --config alone, and no
// flag twice. A usage error exits 2.
func TestSealOpenCommandLine(t *testing.T) {
	usage := sealOpenUsage + "\n"
	for _, tc := range []struct {
		args   []string
		stderr string
	}{
		{nil, usage},
		{[]string{"--store", "s", "--seed", "k", "--registry", "r", "--authority", "a"}, usage},
		{[]string{"--store", "s", "--seed", "k", "--registry", "r", "--authority", "a", "--session", "x", "--all"}, usage},
		{[]string{"--store", "s", "--seed", "k", "--registry", "r", "--session", "x"}, usage},
		{[]string{"--store", "s", "--seed", "k", "--registry", "r", "--authority", "a", "--session"}, usage},
		{[]string{"--store", "s", "--seed", "k", "--registry", "r", "--authority", "a", "--force", "--all"}, usage},
		{[]string{"--all", "--all"}, "seal-open: --all is given twice\n" + usage},
		{[]string{"--store", "s", "--store", "t", "--all"}, "seal-open: --store is given twice\n" + usage},
		{[]string{"--config", "c", "--registry", "r", "--all"}, "seal-open: --config names the store, the seed, the registry and the authority; --registry is not given beside it\n" + usage},
	} {
		var stdout, stderr bytes.Buffer
		if code := cmdSealOpenAt(tc.args, &stdout, &stderr, fixedStamp("2026-11-10T00:00:01Z")); code != 2 || stdout.String() != "" || stderr.String() != tc.stderr {
			t.Fatalf("%q: exit %d\nstderr %q", tc.args, code, stderr.String())
		}
	}
}

// --config names what the flags would, from the engine configuration.
func TestSealOpenByTheEngineConfiguration(t *testing.T) {
	g := leftOpenStore(t)
	dir := t.TempDir()
	seedPath := writeSeedFile(t, dir, testSeed)
	config := filepath.Join(dir, "engine.json")
	body := fmt.Sprintf(`{"engineVersion":"1","authority":"gateway:test","seed":%q,"store":%q,"registry":%q,"decisionRecords":%q,"listen":"127.0.0.1:8787","catalog":%q,"platforms":{}}`,
		seedPath, g.storeRoot, g.regPath, filepath.Join(dir, "decisions"), filepath.Join(dir, "catalog"))
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := cmdSealOpenAt([]string{"--config", config, "--session", "left"}, &stdout, &stderr, fixedStamp("2026-11-10T00:00:01Z"))
	want := interruptionSealLineBy(ed25519.NewKeyFromSeed(testSeed), g.keyID, "left", 2, receiptSignature(t, g.storeRoot, "left", 1), "2026-11-10T00:00:01Z", "command") + "\n"
	if code != 0 || stdout.String() != want || stderr.String() != "" {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout.String(), stderr.String())
	}
}

// --config's seed is looked at by the name configured and by the name it
// resolves to, as serve --config looks at it: a rotation under way beside
// either is refused, and nothing is sealed.
func TestSealOpenByTheEngineConfigurationSeesARotationBesideTheSeedResolved(t *testing.T) {
	g := leftOpenStore(t)
	dir := t.TempDir()
	real := writeSeedFile(t, dir, testSeed)
	link := filepath.Join(dir, "seed-link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real+".rotation", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "engine.json")
	body := fmt.Sprintf(`{"engineVersion":"1","authority":"gateway:test","seed":%q,"store":%q,"registry":%q,"decisionRecords":%q,"listen":"127.0.0.1:8787","catalog":%q,"platforms":{}}`,
		link, g.storeRoot, g.regPath, filepath.Join(dir, "decisions"), filepath.Join(dir, "catalog"))
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	registry := readFile(t, g.regPath)
	var stdout, stderr bytes.Buffer
	code := cmdSealOpenAt([]string{"--config", config, "--session", "left"}, &stdout, &stderr, fixedStamp("2026-11-10T00:00:01Z"))
	want := "seal-open: a rotation is pending: " + real + ".rotation is there; finish it with gateway rotate-key --resume --seed " + real + " --registry " + g.regPath + "\n"
	if code != 1 || stdout.String() != "" || stderr.String() != want || readFile(t, g.regPath) != registry {
		t.Fatalf("exit %d\nstdout %q\nstderr %q\nwant   %q", code, stdout.String(), stderr.String(), want)
	}
}

// The switch is off unless it is given: --seal-open-at-start on serve's
// command line, once, or sealOpenAtStart in a configuration of version 17,
// true or false and nothing else.
func TestTheSealOpenAtStartSwitch(t *testing.T) {
	base := []string{"store", "seed", "gateway:test", "registry.jsonl"}
	if opts, msg, ok := parseServeOptions(base); !ok || opts.sealOpenAtStart {
		t.Fatalf("off by default: %v %q", opts.sealOpenAtStart, msg)
	}
	if opts, msg, ok := parseServeOptions(append(base, "--seal-open-at-start")); !ok || !opts.sealOpenAtStart {
		t.Fatalf("on: %v %q", opts.sealOpenAtStart, msg)
	}
	if _, msg, ok := parseServeOptions(append(base, "--seal-open-at-start", "--seal-open-at-start")); ok || msg != "duplicate --seal-open-at-start option" {
		t.Fatalf("twice: %q", msg)
	}

	catalog := t.TempDir()
	at := func(version, extra string) string {
		return strings.Replace(engineJSON(t, catalog, extra, ``), `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
	}
	for _, tc := range []struct {
		name, text string
		on         bool
	}{
		{"version 17 without it", at("17", ``), false},
		{"version 17, false", at("17", `,"sealOpenAtStart":false`), false},
		{"version 17, true", at("17", `,"sealOpenAtStart":true`), true},
	} {
		cfg, err := parseEngineConfig([]byte(tc.text))
		if err != nil || cfg.sealOpenAtStart != tc.on {
			t.Fatalf("%s: %v %v", tc.name, err, cfg.sealOpenAtStart)
		}
	}
	for _, tc := range []struct{ name, text, want string }{
		{"version 16", at("16", `,"sealOpenAtStart":true`), "engine configuration: sealOpenAtStart is a version-17 member; engineVersion 16 has no sealOpenAtStart"},
		{"a string", at("17", `,"sealOpenAtStart":"true"`), "engine configuration: sealOpenAtStart, when present, is true or false"},
		{"a number", at("17", `,"sealOpenAtStart":1`), "engine configuration: sealOpenAtStart, when present, is true or false"},
	} {
		if _, err := parseEngineConfig([]byte(tc.text)); err == nil || err.Error() != tc.want {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
}
