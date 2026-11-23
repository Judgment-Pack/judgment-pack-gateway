package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// foldedStat stands a filesystem that does not tell case apart: every name is
// looked up in lower case, as such a filesystem finds it.
func foldedStat(t *testing.T) {
	t.Helper()
	statOnDisk = func(path string) (os.FileInfo, error) { return os.Stat(strings.ToLower(path)) }
	t.Cleanup(func() { statOnDisk = os.Stat })
}

// Two names for one directory (#590): where both are there, the start check
// compares the directories themselves (os.SameFile), so a pair that differs by
// case alone, on a filesystem that does not tell case apart, is one directory,
// and so is a directory beneath another under such a name. The load check
// compares the spellings and passes both.
func TestActScopeDecisionRecordsOneDirectoryUnderTwoNames(t *testing.T) {
	root := strings.ToLower(t.TempDir())
	if err := os.MkdirAll(filepath.Join(root, "records", "gateway"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "records", "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	gateway := filepath.Join(root, "records", "gateway")
	a := platformConfig{name: "tickets-a", scope: callerScopeA, decisionRecords: filepath.Join(root, "records", "a")}
	cases := []struct {
		name      string
		gateway   string
		platforms []platformConfig
	}{
		{"the gateway's, by case", gateway, []platformConfig{{name: "tickets-b", scope: callerScopeB, decisionRecords: filepath.Join(root, "records", "Gateway")}}},
		{"beneath the gateway's, by case", gateway, []platformConfig{{name: "tickets-b", scope: callerScopeB, decisionRecords: filepath.Join(root, "records", "GATEWAY", "b")}}},
		{"another scope's, by case", "", []platformConfig{a, {name: "tickets-b", scope: callerScopeB, decisionRecords: filepath.Join(root, "records", "A")}}},
		{"above another scope's, by case", "", []platformConfig{a, {name: "tickets-b", scope: callerScopeB, decisionRecords: filepath.Join(root, "Records")}}},
	}
	for _, c := range cases {
		if err := decisionRecordsApart(c.gateway, c.platforms, nestedAsSpelled); err != nil {
			t.Errorf("%s: the load check, which compares spellings: %v", c.name, err)
		}
	}
	foldedStat(t)
	for _, c := range cases {
		if err := decisionRecordsApart(c.gateway, c.platforms, nestedOnDisk); err == nil {
			t.Errorf("%s: one directory under two names loaded at start", c.name)
		}
	}
	apart := []platformConfig{a, {name: "tickets-b", scope: callerScopeB, decisionRecords: filepath.Join(root, "records", "B")}}
	if err := decisionRecordsApart(gateway, apart, nestedOnDisk); err != nil {
		t.Fatalf("directories apart, one not made yet: %v", err)
	}
}

// A link that leads nowhere yet is followed by its text a part at a time
// (#590): "sub/.." is the directory above where sub leads, not the link's
// own, so a text that reaches the gateway's directory through a link and
// ".." is refused, and one that leads apart is not.
func TestActScopeDecisionRecordsDanglingLinkTextWithDotDot(t *testing.T) {
	root := t.TempDir()
	gateway := filepath.Join(root, "elsewhere")
	for _, dir := range []string{filepath.Join(gateway, "deep"), filepath.Join(root, "d"), filepath.Join(root, "other", "deep")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// the texts are written as they are, never cleaned, or ".." would go
	sep := string(filepath.Separator)
	links := map[string]string{
		filepath.Join(root, "d", "sub"):   filepath.Join(gateway, "deep"),
		filepath.Join(root, "d", "into"):  "sub" + sep + ".." + sep + "later",
		filepath.Join(root, "d", "apart"): "away" + sep + ".." + sep + "later",
		filepath.Join(root, "d", "away"):  filepath.Join(root, "other", "deep"),
	}
	for link, text := range links {
		if err := os.Symlink(text, link); err != nil {
			t.Skipf("no symbolic links here: %v", err)
		}
	}
	into := []platformConfig{{name: "tickets-b", scope: callerScopeB, decisionRecords: filepath.Join(root, "d", "into")}}
	if err := decisionRecordsApart(gateway, into, nestedOnDisk); err == nil {
		t.Fatal("a dangling link whose text reaches the gateway's directory through sub/.. loaded")
	}
	if got, want := resolvedOrClean(filepath.Join(root, "d", "into", "b")), filepath.Join(resolvedOrClean(gateway), "later", "b"); got != want {
		t.Fatalf("resolved %s, want %s", got, want)
	}
	apart := []platformConfig{{name: "tickets-b", scope: callerScopeB, decisionRecords: filepath.Join(root, "d", "apart")}}
	if err := decisionRecordsApart(gateway, apart, nestedOnDisk); err != nil {
		t.Fatalf("a dangling link whose text leads apart: %v", err)
	}
}
