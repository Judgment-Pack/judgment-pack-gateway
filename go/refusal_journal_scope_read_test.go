package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A verdict by scope reads its own scope's refusal journal alone (ADR-0059
// §8), as verify-ts does: another scope's journal that cannot be read, a
// directory in its place or a file no one may read, leaves scope-a's verdict
// as v3-cut-a-refusal-journals-of-others states it. The verdict of the whole
// store still has no answer over the file it cannot read.
func TestRefusalJournalOfAnotherScopeUnreadableLeavesTheVerdict(t *testing.T) {
	vector := readStoreVector(t, "v3-cut-a-refusal-journals-of-others")
	publicKey, err := corpusPublicKey(filepath.Join("..", "corpus"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name       string
		unreadable bool
	}{{"a directory in its place", false}, {"a file no one may read", true}} {
		t.Run(c.name, func(t *testing.T) {
			if c.unreadable && (runtime.GOOS == "windows" || os.Geteuid() == 0) {
				t.Skip("a file's mode keeps no reader out here")
			}
			root, storeRoot, registryPath, _, err := materializeVector(vector)
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			ofB := filepath.Join(storeRoot, journalsDir, refusalJournalName("scope-b")+".jsonl")
			if c.unreadable {
				if err := os.Chmod(ofB, 0); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(ofB, 0o600)
			} else {
				if err := os.Remove(ofB); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(ofB, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			rep, err := verifyByScope(storeRoot, registryPath, vector.Authority, "", vector.Scope, publicKey, false)
			if err != nil {
				t.Fatalf("no verdict by %s: %v", vector.Scope, err)
			}
			if !rep.OK || len(rep.Findings) != 2 || len(rep.Observations) != 1 || rep.Observations[0]["journal"] != refusalJournalName("scope-a") {
				t.Fatalf("the verdict by %s: ok %v, %d findings, observations %v", vector.Scope, rep.OK, len(rep.Findings), rep.Observations)
			}
			if c.unreadable {
				if _, err := verifySupplied(storeRoot, registryPath, vector.Authority, "", "", publicKey, false); err == nil {
					t.Fatal("the verdict of the whole store read past a journal it could not read")
				}
			}
		})
	}
}
