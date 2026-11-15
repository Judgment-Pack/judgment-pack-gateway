//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A gateway serving the registry holds it, and the command is refused while
// it does: nothing is written or removed. Once the gateway lets go, the
// removal runs.
func TestRemoveScopeIsRefusedWhileAGatewayHoldsTheRegistry(t *testing.T) {
	g, seedPath := scopeStore(t)
	hold, err := holdEngineRegistry([]string{seedPath}, g.regPath, testSeed)
	if err != nil {
		t.Fatal(err)
	}
	tree := storeTree(t, g.storeRoot)
	code, stdout, stderr := removeScopeOn(t, g, seedPath, "--scope", testScope, "--by", "operator-1")
	want := "remove-scope: the registry is held by a running gateway, or by a rotation under way: " + g.regPath + "; stop the gateway, then remove\n"
	if code != 1 || stdout != "" || stderr != want {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	if !sameEntries(storeTree(t, g.storeRoot), tree) {
		t.Fatal("the store changed")
	}
	hold.Close()
	if code, _, stderr := removeScopeOn(t, g, seedPath, "--scope", testScope, "--by", "operator-1"); code != 0 {
		t.Fatalf("after the gateway let go: exit %d: %s", code, stderr)
	}
}

// Every record is appended, and made durable, before anything is removed: a
// run whose first removal fails leaves the records beside the whole store,
// which verifies as it did, the sessions a record names verified as they
// are. A second run completes the removal, appending no session's record
// again, and a third changes nothing.
func TestRemoveScopeRecordsFirstAndASecondRunCompletesIt(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a directory's mode does not keep the superuser out")
	}
	g, seedPath := scopeStore(t)
	_, beforeFindings, beforeObservations := scopeVerdict(t, g)
	tree := storeTree(t, g.storeRoot)
	artifacts := filepath.Join(g.storeRoot, "artifacts")
	if err := os.Chmod(artifacts, 0o500); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := removeScopeOn(t, g, seedPath, "--scope", testScope, "--by", "operator-1")
	if err := os.Chmod(artifacts, 0o755); err != nil {
		t.Fatal(err)
	}
	if code != 1 || !strings.HasPrefix(stderr, "remove-scope: a payload could not be removed: ") ||
		!strings.HasSuffix(stderr, "; the records stand, and a second run completes the removal\n") || strings.Contains(stderr, "quipe") {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	file := readFile(t, filepath.Join(g.storeRoot, removalsFile))
	if file != stdout || strings.Count(file, "\n") != 2 {
		t.Fatalf("the records %q, printed %q", file, stdout)
	}
	after := storeTree(t, g.storeRoot)
	delete(after, removalsFile)
	if !sameEntries(after, tree) {
		t.Fatal("something was removed before the records were durable, or changed")
	}
	ok, findings, observations := scopeVerdict(t, g)
	if ok || strings.Join(findings, ",") != strings.Join(beforeFindings, ",") || strings.Join(observations, ",") != strings.Join(beforeObservations, ",") {
		t.Fatalf("the verdict beside the records: %v %v %v, before %v %v", ok, findings, observations, beforeFindings, beforeObservations)
	}

	code, stdout, stderr = removeScopeOn(t, g, seedPath, "--scope", testScope, "--by", "operator-1")
	want := "remove-scope: session a1 was recorded as removed already; its files, still there, are removed now\n" +
		"remove-scope: removed 2 session(s), 1 sealed, holding 3 receipt(s), and 2 payload(s)\n" + scopeUnlockedLine()
	if code != 0 || strings.Count(stdout, "\n") != 1 || !strings.Contains(stdout, `"kind":"scope-removal"`) || stderr != want {
		t.Fatalf("the second run: exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	if readFile(t, filepath.Join(g.storeRoot, removalsFile)) != file+stdout {
		t.Fatal("the second run appended other than its scope-removal record")
	}
	ok, findings, observations = scopeVerdict(t, g)
	if !ok || len(findings) != 0 || strings.Join(observations, ",") != "a1 "+observationSessionRemoved {
		t.Fatalf("the verdict: %v %v %v", ok, findings, observations)
	}
	if code, stdout, _ := removeScopeOn(t, g, seedPath, "--scope", testScope, "--by", "operator-1"); code != 0 || stdout != "" {
		t.Fatalf("a third run: exit %d %q", code, stdout)
	}
}
