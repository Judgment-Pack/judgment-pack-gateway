package main

import (
	"bytes"
	"crypto/ed25519"
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
	walk := walkRegistry([]byte(readFile(t, registry)), ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))
	rep := &report{OK: true, continuation: walk.continuation, continuationRefused: walk.continuationFinding != nil}
	if err := linkPrevious(rep, previous); err != nil {
		t.Fatal(err)
	}
	return rep.Findings
}

// A rotation seals what was left open, as seal-open --all does, then makes a
// new store and a registry whose one line is a store continuation naming the
// old registry's tail as it stands after those seals; the old store keeps
// its receipts. The new registry links to the old one, and to no other: a
// registry of another count, or of the same count and another last line, is
// refused by name.
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
	lines, last := registryTail([]byte(old))
	walk, err := engineWalk([]byte(readFile(t, newRegistry)), ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))
	if err != nil || walk.continuation == nil || walk.continuation.previousLines != lines || walk.continuation.previousLastLine != last {
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
		{"the last line changed", strings.TrimSuffix(old, out[0]+"\n") + strings.Replace(out[0], `"left"`, `"lefT"`, 1) + "\n", statusContinuationTailMismatch},
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

	// a second rotation into paths that are there is refused, nothing made
	code, _, stderr = rotateOn(t, g, seedPath, newStore, filepath.Join(dir, "other.jsonl"), "2026-11-19T00:00:02Z")
	if code != 1 || !strings.Contains(stderr, "is there already") || readFile(t, g.regPath) != old {
		t.Fatalf("into a store that is there: exit %d: %s", code, stderr)
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
	line := newContinuationLine(priv, []byte("x\n"), "2026-11-19T00:00:00Z")
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
	if w := walkRegistry(newContinuationLine(other, nil, "2026-11-19T00:00:00Z"), pub); w.continuationFinding["status"] != statusContinuationForged {
		t.Fatalf("signed by another key: %v", w.continuationFinding)
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
