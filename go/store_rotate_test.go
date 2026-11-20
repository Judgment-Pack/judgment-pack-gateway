package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rotateOn runs gateway store rotate over g's store into newStore and
// newRegistry, stamped at.
func rotateOn(t *testing.T, g *gatewayService, seedPath, newStore, newRegistry, at string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := cmdStoreRotateAt([]string{"--store", g.storeRoot, "--seed", seedPath, "--registry", g.regPath, "--authority", "gateway:test",
		"--new-store", newStore, "--new-registry", newRegistry}, &stdout, &stderr, fixedStamp(at))
	return code, stdout.String(), stderr.String()
}

// linkOf is the findings --previous gives of the registry at registry
// against the one at previous.
func linkOf(t *testing.T, registry, previous string) []finding {
	t.Helper()
	pub := ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)
	walk := walkRegistry([]byte(readFile(t, registry)), pub)
	rep := &report{OK: true, continuation: walk.continuation, continuationRefused: walk.continuationFinding != nil}
	if err := linkPrevious(rep, previous, pub); err != nil {
		t.Fatal(err)
	}
	return rep.Findings
}

// A rotation seals what was left open, as seal-open --all does, then makes a
// new store and a registry whose one line is a store continuation naming the
// old registry's bytes as they stand after those seals; the old store keeps
// its receipts and is marked rotated away from. The new registry links to
// the old one, and to no other: a registry of another count, or of the same
// count and other bytes anywhere in it, is refused by name.
func TestStoreRotateSealsWhatIsOpenAndLinksTheNewRegistry(t *testing.T) {
	g := leftOpenStore(t)
	seedPath := writeSeedFile(t, t.TempDir(), testSeed)
	dir := t.TempDir()
	newStore, newRegistry := filepath.Join(dir, "store"), filepath.Join(dir, "registry.jsonl")
	receipts := storeTree(t, g.storeRoot)
	code, stdout, stderr := rotateOn(t, g, seedPath, newStore, newRegistry, "2026-11-19T00:00:01Z")
	if code != 0 || strings.TrimPrefix(stderr, sealOpenUnlocked()) != "" {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	out := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(out) != 2 || !strings.Contains(out[0], `"kind":"seal-after-interruption"`) || !strings.Contains(out[0], `"sessionId":"left"`) {
		t.Fatalf("the seal of the session left open was not printed first: %q", stdout)
	}
	old := readFile(t, g.regPath)
	if !strings.HasSuffix(old, out[0]+"\n") {
		t.Fatalf("the old registry does not end in the seal printed:\n%s", old)
	}
	if got := readFile(t, newRegistry); got != out[1]+"\n" {
		t.Fatalf("the new registry is %q, not the continuation printed", got)
	}
	if info, err := os.Stat(newStore); err != nil || !info.IsDir() {
		t.Fatalf("the new store: %v", err)
	}
	if after := storeTree(t, g.storeRoot); len(after) != len(receipts) {
		t.Fatalf("the old store changed: %d files, was %d", len(after), len(receipts))
	}
	lines, last := registryLink([]byte(old))
	walk, err := engineWalk([]byte(readFile(t, newRegistry)), ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))
	if err != nil || walk.continuation == nil || walk.continuation.previousLines != lines || walk.continuation.previousDigest != last {
		t.Fatalf("the new registry's own reading: %v %+v, want %d %s", err, walk, lines, last)
	}
	if f := linkOf(t, newRegistry, g.regPath); len(f) != 0 {
		t.Fatalf("the link to the old registry: %v", f)
	}

	for _, tc := range []struct {
		name, previous, status string
	}{
		{"one line more", old + out[1] + "\n", statusContinuationCountMismatch},
		{"one line fewer", strings.Join(strings.SplitAfter(old, "\n")[1:], ""), statusContinuationCountMismatch},
		{"the last line changed", strings.TrimSuffix(old, out[0]+"\n") + strings.Replace(out[0], `"left"`, `"lefT"`, 1) + "\n", statusContinuationDigestMismatch},
		// a line blanked keeps the count and the last line, and is not the
		// registry the continuation names
		{"an earlier line blanked", "\n" + strings.Join(strings.SplitAfter(old, "\n")[1:], ""), statusContinuationDigestMismatch},
	} {
		path := filepath.Join(t.TempDir(), "previous.jsonl")
		if err := os.WriteFile(path, []byte(tc.previous), 0o600); err != nil {
			t.Fatal(err)
		}
		if f := linkOf(t, newRegistry, path); len(f) != 1 || f[0]["status"] != tc.status {
			t.Fatalf("%s: %v, want %s", tc.name, f, tc.status)
		}
	}
	// a registry with no continuation does not link to anything
	if f := linkOf(t, g.regPath, g.regPath); len(f) != 1 || f[0]["status"] != statusContinuationMissing {
		t.Fatalf("a registry with no continuation: %v", f)
	}

	// the old store is marked rotated away from, outside its registry's
	// bytes, and a second rotation of it is refused by the mark's name,
	// nothing made
	mark := rotatedMark([]byte(out[1] + "\n"))
	if got := readFile(t, rotatedMarkPath(g.regPath)); got != mark+"\n" || readFile(t, g.regPath) != old {
		t.Fatalf("the mark is %q, want %q", got, mark)
	}
	code, _, stderr = rotateOn(t, g, seedPath, newStore, filepath.Join(dir, "other.jsonl"), "2026-11-19T00:00:02Z")
	if code != 1 || !strings.Contains(stderr, "the store was rotated away from ("+mark+")") || readFile(t, g.regPath) != old {
		t.Fatalf("a store rotated away from: exit %d: %s", code, stderr)
	}
	if _, err := os.Lstat(filepath.Join(dir, "other.jsonl")); err == nil {
		t.Fatal("a refused rotation made a registry")
	}
}

// A store continuation is a registry's first line or nothing: one after any
// other line loads nothing, is the registry's finding, and the gateway's own
// reading refuses it; one at the first line the key in force did not sign is
// forged.
func TestAStoreContinuationIsTheFirstLineOrAFinding(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(testSeed)
	pub := priv.Public().(ed25519.PublicKey)
	line := newContinuationLine(priv, []byte("x\n"), []byte("h"), "2026-11-19T00:00:00Z")
	if w := walkRegistry(line, pub); w.continuation == nil || w.continuationFinding != nil {
		t.Fatalf("at the first line: %+v", w)
	}
	for _, data := range [][]byte{append([]byte("{}\n"), line...), append([]byte("\n"), line...), append(append([]byte{}, line...), line...)} {
		w := walkRegistry(data, pub)
		if w.continuationFinding["status"] != statusContinuationMisplaced {
			t.Fatalf("%q: %v", data, w.continuationFinding)
		}
		if _, err := engineWalk(data, pub); err == nil {
			t.Fatalf("%q: the gateway's own reading took it", data)
		}
	}
	// the walk continued from where it stopped knows the line it is at
	head := walkRegistry([]byte("{}\n"), pub)
	if next := head.continued(line); next.continuationFinding["status"] != statusContinuationMisplaced {
		t.Fatalf("continued: %v", next.continuationFinding)
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	if w := walkRegistry(newContinuationLine(other, nil, nil, "2026-11-19T00:00:00Z"), pub); w.continuationFinding["status"] != statusContinuationForged {
		t.Fatalf("signed by another key: %v", w.continuationFinding)
	}
	// the key history it names is one of its members, of previousDigest's
	// form: a continuation without it, or with another form, is forged
	// though the key in force signed it
	for name, digest := range map[string]value{
		"without keyHistoryDigest":     nil,
		"a sha256:-prefixed digest":    vString("sha256:" + keyHistoryDigestOf([]byte("h"))),
		"an upper-case digest":         vString(strings.ToUpper(keyHistoryDigestOf([]byte("h")))),
		"a digest one character short": vString(keyHistoryDigestOf([]byte("h"))[1:]),
		"a digest that is no string":   vInt(1),
	} {
		obj := continuationLine(strings.TrimSuffix(string(line), "\n"))
		rest := newObject()
		for _, n := range obj.names {
			if v, _ := obj.get(n); n != "keyHistoryDigest" && n != "signature" {
				rest.set(n, v)
			}
		}
		if digest != nil {
			rest.set("keyHistoryDigest", digest)
		}
		rest.set("signature", vString(hex.EncodeToString(ed25519.Sign(priv, continuationSigningInput(rest)))))
		if w := walkRegistry(append(canon(rest), '\n'), pub); w.continuationFinding["status"] != statusContinuationForged || w.continuation != nil {
			t.Errorf("%s: %v", name, w.continuationFinding)
		}
	}
}

// While a gateway holds the registry, a rotation is refused and nothing is
// sealed or made.
func TestStoreRotateIsRefusedWhileAGatewayHoldsTheRegistry(t *testing.T) {
	if !registryLocked {
		t.Skip("this platform locks no registry")
	}
	g := leftOpenStore(t)
	seedPath := writeSeedFile(t, t.TempDir(), testSeed)
	hold, err := holdEngineRegistry([]string{seedPath}, g.regPath, testSeed)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	old := readFile(t, g.regPath)
	dir := t.TempDir()
	code, stdout, stderr := rotateOn(t, g, seedPath, filepath.Join(dir, "store"), filepath.Join(dir, "registry.jsonl"), "2026-11-19T00:00:01Z")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "stop the gateway, then rotate") || readFile(t, g.regPath) != old {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("a refused rotation made %v", entries)
	}
}

// Every later hold of a store rotated away from is refused by the mark's
// name: the gateway's start, seal-open and rotate-key take the same hold.
// A rerun after a crash finishes the rotation: one stopped before the new
// registry was renamed into place leaves an empty store directory and the
// file written beside it, which do not refuse it; one stopped before the
// mark leaves the new registry whole, and the rerun writes only the mark.
func TestStoreRotateMarksTheOldStoreAndARerunFinishesIt(t *testing.T) {
	g := leftOpenStore(t)
	seedPath := writeSeedFile(t, t.TempDir(), testSeed)
	dir := t.TempDir()
	newStore := filepath.Join(dir, "store")
	newRegistry := filepath.Join(newStore, "registry.jsonl")
	if err := os.Mkdir(newStore, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newRegistryTemp(newRegistry), []byte(`{"kind":"store-cont`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := rotateOn(t, g, seedPath, newStore, newRegistry, "2026-11-19T00:00:01Z")
	if code != 0 {
		t.Fatalf("over what a crash left: exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	out := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	line := out[len(out)-1] + "\n"
	if readFile(t, newRegistry) != line {
		t.Fatalf("the new registry: %q", readFile(t, newRegistry))
	}
	if _, err := os.Lstat(newRegistryTemp(newRegistry)); err == nil {
		t.Fatal("the file the registry was written to is still there")
	}
	mark := rotatedMark([]byte(line))
	if _, err := holdEngineRegistry([]string{seedPath}, g.regPath, testSeed); err == nil || !strings.Contains(err.Error(), "("+mark+")") {
		t.Fatalf("a hold of the old registry: %v", err)
	}

	// stopped before the mark: the rerun writes it, and nothing else
	if err := os.Remove(rotatedMarkPath(g.regPath)); err != nil {
		t.Fatal(err)
	}
	old := readFile(t, g.regPath)
	code, stdout, stderr = rotateOn(t, g, seedPath, newStore, newRegistry, "2026-11-19T00:00:09Z")
	if code != 0 || stdout != line || readFile(t, newRegistry) != line || readFile(t, g.regPath) != old {
		t.Fatalf("the rerun: exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	if readFile(t, rotatedMarkPath(g.regPath)) != mark+"\n" {
		t.Fatal("the rerun did not mark the old store")
	}

	// a new registry that is not this registry's continuation alone is
	// refused, the mark not written
	if err := os.Remove(rotatedMarkPath(g.regPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newRegistry, []byte(line+line), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = rotateOn(t, g, seedPath, newStore, newRegistry, "2026-11-19T00:00:09Z")
	if code != 1 || !strings.Contains(stderr, "is there already") {
		t.Fatalf("a new registry of two lines: exit %d: %s", code, stderr)
	}
	if _, err := os.Lstat(rotatedMarkPath(g.regPath)); err == nil {
		t.Fatal("a refused rerun marked the old store")
	}
	// a store directory holding anything else is refused before the hold
	if err := os.WriteFile(filepath.Join(newStore, "other"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr = rotateOn(t, g, seedPath, newStore, filepath.Join(dir, "r.jsonl"), "2026-11-19T00:00:09Z"); code != 1 || !strings.Contains(stderr, newStore+" is there already") {
		t.Fatalf("a store directory holding a file: exit %d: %s", code, stderr)
	}
}

// Under --previous the continuation's key is the key the registry before it
// ends at, walked from its first key-continuation's previous key: a new
// store whose key is not where the old registry's rotations end does not
// link, though it names that registry's count and digest.
func TestALinkHoldsTheContinuationToTheOldRegistrysLastKey(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(testSeed)
	first := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	dir := t.TempDir()
	for _, tc := range []struct {
		name   string
		old    []byte
		status string
	}{
		{"rotated to the new store's key", rotationRecord(nil, 1, "2026-11-18T00:00:00Z", first, priv), ""},
		{"rotated to another key", rotationRecord(nil, 1, "2026-11-18T00:00:00Z", first, other), statusContinuationKeyMismatch},
		{"rotated to it, then on to another", append(rotationRecord(nil, 1, "2026-11-18T00:00:00Z", first, priv),
			rotationRecord(nil, 2, "2026-11-18T00:00:01Z", priv, other)...), statusContinuationKeyMismatch},
		// a registry that never rotated is held to the key its last seal
		// states, not to the key pinned
		{"never rotated, its seals another key's", sealLineBy(other, "s1"), statusContinuationKeyMismatch},
		{"never rotated, its seals the new store's key", sealLineBy(priv, "s1"), ""},
		// a seal before the rotation states the key it was made under
		{"sealed, then rotated to the new store's key", append(sealLineBy(first, "s1"), rotationRecord([]byte("x\n"), 1, "2026-11-18T00:00:00Z", first, priv)...), ""},
		{"rotated to it, a seal after stating another key", append(rotationRecord(nil, 1, "2026-11-18T00:00:00Z", first, priv), sealLineBy(first, "s2")...), statusContinuationKeyMismatch},
	} {
		previous, registry := filepath.Join(dir, "previous.jsonl"), filepath.Join(dir, "registry.jsonl")
		if err := os.WriteFile(previous, tc.old, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(registry, newContinuationLine(priv, tc.old, nil, "2026-11-19T00:00:00Z"), 0o600); err != nil {
			t.Fatal(err)
		}
		f := linkOf(t, registry, previous)
		if (tc.status == "" && len(f) != 0) || (tc.status != "" && (len(f) != 1 || f[0]["status"] != tc.status)) {
			t.Fatalf("%s: %v, want %q", tc.name, f, tc.status)
		}
	}
}

// sealLineBy is a seal of today's form of session, count 1, signed by key.
func sealLineBy(key ed25519.PrivateKey, session string) []byte {
	keyID := keyIDFor(key.Public().(ed25519.PublicKey))
	at := "2026-11-18T00:00:00Z"
	obj := newObject()
	obj.set("finalCount", vInt(1))
	obj.set("keyId", vString(keyID))
	obj.set("sealedAt", vString(at))
	obj.set("sessionId", vString(session))
	obj.set("signature", vString(hex.EncodeToString(ed25519.Sign(key, sealSigningInput(session, 1, at, keyID)))))
	return append(canon(obj), '\n')
}
