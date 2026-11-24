package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A draw ended after its staged file and before the link leaves no key, so
// the next start draws one whole; a staged file a start left in the store's
// root is removed at the next, of any journal's name, a scope's no longer
// configured among them (gateway #611), and only a regular file of the
// exact form, never one of this process's own identifier. A start that
// removes only its configured journals' fails it.
func TestAKeyDrawEndedPartWayLeavesNoShortKey(t *testing.T) {
	root := t.TempDir()
	f := refusalFS{root: root}
	name := refusalJournalName(callerScopeA)
	path := filepath.Join(f.dir(), name+".key")
	keyDrawCut = func() error { return errors.New("ended mid-draw") }
	t.Cleanup(func() { keyDrawCut = nil })
	if _, _, err := f.key(name); err == nil {
		t.Fatal("the cut draw answered a key")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a cut draw left a key file: %v", err)
	}
	keyDrawCut = nil
	k, missing, err := f.key(name)
	if err != nil || missing || len(k) != 32 {
		t.Fatalf("the next draw: %v %v %d", err, missing, len(k))
	}
	if again, _, err := f.key(name); err != nil || !bytes.Equal(again, k) {
		t.Fatalf("the key read back: %v", err)
	}

	// another process's identifier: never this one's, whose draw may be
	// under way
	pid, next := 4242, 4243
	if os.Getpid() == pid || os.Getpid() == next {
		pid, next = 4244, 4245
	}
	other := refusalJournalName("another-scope")
	leftovers := []string{
		fmt.Sprintf(".%s.key.%d.0123456789ab.tmp", name, pid),
		// a scope the start is not configured with
		fmt.Sprintf(".%s.key.%d.0123456789ab.tmp", other, pid),
	}
	kept := []string{
		fmt.Sprintf("%s.key.%d.0123456789ab.tmp", name, pid),
		fmt.Sprintf(".%s.key.%d.0123456789ab", name, pid),
		fmt.Sprintf(".%s.key.%d.0123456789a.tmp", other, pid),
		fmt.Sprintf(".operator.key.%d.0123456789ab.tmp", pid),
	}
	for _, n := range append(append([]string{}, leftovers...), kept...) {
		if err := os.WriteFile(filepath.Join(root, n), []byte("ab"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// a directory of the exact form stands
	dirName := fmt.Sprintf(".%s.key.%d.0123456789ac.tmp", other, pid)
	if err := os.Mkdir(filepath.Join(root, dirName), 0o700); err != nil {
		t.Fatal(err)
	}
	kept = append(kept, dirName)
	// uppercase hexadecimal is not the exact form; where the filesystem
	// folds case (as on Windows and macOS by default) that name is the
	// leftover itself, so the case is made only where the two are two files
	upper := fmt.Sprintf(".%s.key.%d.0123456789AB.tmp", name, pid)
	if err := os.WriteFile(filepath.Join(root, upper), []byte("AB"), 0o600); err != nil {
		t.Fatal(err)
	}
	if a, err := os.Stat(filepath.Join(root, leftovers[0])); err != nil {
		t.Fatal(err)
	} else if b, err := os.Stat(filepath.Join(root, upper)); err != nil {
		t.Fatal(err)
	} else if !os.SameFile(a, b) {
		kept = append(kept, upper)
	} else if err := os.WriteFile(filepath.Join(root, leftovers[0]), []byte("ab"), 0o600); err != nil {
		t.Fatal(err)
	}
	// every file so far was written long ago, so only the form keeps one;
	// a staged file of the exact form written just now, of another process
	// or this one, may be a draw under way, and stands
	for _, n := range append(append([]string{}, leftovers...), kept...) {
		stagedLongAgo(t, filepath.Join(root, n))
	}
	if _, err := os.Stat(filepath.Join(root, upper)); err == nil {
		stagedLongAgo(t, filepath.Join(root, upper))
	}
	for _, p := range []int{pid, os.Getpid()} {
		young := fmt.Sprintf(".%s.key.%d.fedcba987654.tmp", other, p)
		if err := os.WriteFile(filepath.Join(root, young), []byte("ab"), 0o600); err != nil {
			t.Fatal(err)
		}
		kept = append(kept, young)
	}
	linked := fmt.Sprintf(".%s.key.%d.0123456789ab.tmp", other, next)
	if err := os.Symlink(filepath.Join(root, kept[0]), filepath.Join(root, linked)); err != nil {
		t.Skipf("no symbolic link here: %v", err)
	}
	if _, err := newRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, map[string]bool{callerScopeA: true}, f, nil, nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, n := range leftovers {
		if _, err := os.Lstat(filepath.Join(root, n)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the staged file %s stands: %v", n, err)
		}
	}
	for _, n := range append(kept, linked) {
		if _, err := os.Lstat(filepath.Join(root, n)); err != nil {
			t.Errorf("%s went: %v", n, err)
		}
	}
}

// remove-scope of a scope removes the staged key files a start ended
// mid-draw left for its refusal journal, and no other journal's (gateway
// #611); a remove-scope that leaves them fails it.
func TestRemoveScopeRemovesItsScopesStagedKeyFiles(t *testing.T) {
	g, config := journalStore(t)
	pid := os.Getpid() + 1
	mine := fmt.Sprintf(".%s.key.%d.0123456789ab.tmp", refusalJournalName("never-held"), pid)
	theirs := fmt.Sprintf(".%s.key.%d.0123456789ab.tmp", refusalJournalName("another-scope"), pid)
	// the scope's, written just now: another process's draw may be under way
	young := fmt.Sprintf(".%s.key.%d.fedcba987654.tmp", refusalJournalName("never-held"), pid)
	for _, n := range []string{mine, theirs, young} {
		if err := os.WriteFile(filepath.Join(g.storeRoot, n), []byte("ab"), 0o600); err != nil {
			t.Fatal(err)
		}
		if n != young {
			stagedLongAgo(t, filepath.Join(g.storeRoot, n))
		}
	}
	var stdout, stderr bytes.Buffer
	if code := cmdRemoveScopeAt([]string{"--config", config, "--scope", "never-held", "--by", "operator-2"}, &stdout, &stderr, fixedStamp(removalStamp)); code != 0 ||
		!strings.Contains(stderr.String(), "remove-scope: 1 staged key file(s) of the scope's refusal journal, which a start ended mid-draw left, are removed\n") {
		t.Fatalf("remove-scope: exit %d, %q", code, stderr.String())
	}
	if _, err := os.Lstat(filepath.Join(g.storeRoot, mine)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the scope's staged file stands: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(g.storeRoot, theirs)); err != nil {
		t.Errorf("another journal's staged file went: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(g.storeRoot, young)); err != nil {
		t.Errorf("a staged file written just now went: %v", err)
	}
}

// stagedLongAgo sets a staged file's time past stagedKeyAge, as a leftover's
// is, so that a sweep takes it by its form alone.
func stagedLongAgo(t *testing.T, path string) {
	t.Helper()
	old := time.Now().Add(-2 * stagedKeyAge)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}
