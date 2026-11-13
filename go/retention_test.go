package main

// Payload retention (SPEC.md §1.3a; docs/adr/0028-payloads-a-gateway-does-not-keep.md):
// what the artifact step reads beside the store's own bytes -- the removal
// file and a directory of bytes a reader supplied -- where the corpus cannot
// hold it: an entry that is not a regular file, something at an artifact's
// path that yields no bytes, a store with no artifacts/ at all, and
// gateway verify's --artifacts. The corpus holds the verdicts themselves
// (corpus/v3/stores/v3-artifact-*).

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// retentionStore is a corpus vector written out, and the hex of each
// receipt's result digest in session s1, by call index.
type retentionStore struct {
	vector                         storeVector
	tmp, root, registry, decisions string
	hexOf                          map[int]string
	publicKey                      []byte
}

func materializeRetention(t *testing.T, name string) retentionStore {
	t.Helper()
	vector := readStoreVector(t, name)
	tmp, root, registry, decisions, err := materializeVector(vector)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	s := retentionStore{vector: vector, tmp: tmp, root: root, registry: registry, decisions: decisions, hexOf: map[int]string{},
		publicKey: mustHex(t, strings.TrimSpace(readFile(t, corpusPath("TEST-PUBLIC-KEY"))))}
	for i := 0; i < 2; i++ {
		v, err := parseJSON([]byte(readFile(t, filepath.Join(root, "receipts", "s1", fmt.Sprintf("%d.json", i)))))
		if err != nil {
			t.Fatal(err)
		}
		digest, _ := memberString(v.(*vObject), "resultDigest")
		s.hexOf[i] = strings.TrimPrefix(digest, "sha256:")
	}
	return s
}

func (s retentionStore) verify(t *testing.T, supplied string) (*report, error) {
	t.Helper()
	return verifySupplied(s.root, s.registry, s.vector.Authority, s.decisions, supplied, s.publicKey, false)
}

// statusOf is the status of receipt index of s1 in a verdict, and the
// observations it carries.
func statusOf(t *testing.T, rep *report, index int) (string, []string) {
	t.Helper()
	status := ""
	for _, f := range rep.Findings {
		if f["sessionId"] == "s1" && fmt.Sprint(f["callIndex"]) == fmt.Sprint(index) {
			status, _ = f["status"].(string)
		}
	}
	var observations []string
	for _, o := range rep.Observations {
		if o["sessionId"] == "s1" && fmt.Sprint(o["callIndex"]) == fmt.Sprint(index) {
			observations = append(observations, fmt.Sprint(o["observation"]))
		}
	}
	return status, observations
}

// verdict is the verdict, failing the test where there is none.
func (s retentionStore) verdict(t *testing.T, supplied string) *report {
	t.Helper()
	rep, err := s.verify(t, supplied)
	if err != nil {
		t.Fatalf("no verdict: %v", err)
	}
	return rep
}

// A removal file that is not there loads nothing, and nor does anything at
// its path that is not a regular file (SPEC.md §1.3a, §4.1): it is not read,
// so the removed receipt is artifact-missing -- a directory, and a link,
// whatever it leads to, the very records that load where they are
// included. The FIFO and a file that cannot be read: retention_unix_test.go.
func TestARemovalFileThatIsNotARegularFileIsNotRead(t *testing.T) {
	for name, make := range map[string]func(file, records string) error{
		"a directory":               func(file, _ string) error { return os.Mkdir(file, 0o755) },
		"a link to the records":     func(file, records string) error { return os.Symlink(records, file) },
		"a link that leads nowhere": func(file, records string) error { return os.Symlink(records+".nowhere", file) },
	} {
		t.Run(name, func(t *testing.T) {
			s := materializeRetention(t, "v3-artifact-removed")
			if status, observations := statusOf(t, s.verdict(t, ""), 0); status != "ok" || len(observations) != 1 || observations[0] != observationRemoved {
				t.Fatalf("with the record: %s %v", status, observations)
			}
			file := filepath.Join(s.root, removalsFile)
			records := filepath.Join(s.tmp, "records.jsonl")
			if err := os.Rename(file, records); err != nil {
				t.Fatal(err)
			}
			if status, _ := statusOf(t, s.verdict(t, ""), 0); status != "artifact-missing" {
				t.Fatalf("with no removal file: %s, want artifact-missing", status)
			}
			if err := make(file, records); err != nil {
				if runtime.GOOS == "windows" && name != "a directory" {
					t.Skipf("no link here: %v", err)
				}
				t.Fatal(err)
			}
			if status, _ := statusOf(t, s.verdict(t, ""), 0); status != "artifact-missing" {
				t.Fatalf("%s at the removal file's path: %s, want artifact-missing", name, status)
			}
		})
	}
}

// The file read is the entry judged: another file put in its place between
// the look at the entry and the open is not read as the records, and there
// is no verdict -- the store changed under the verifier.
func TestTheRemovalFileReadIsTheEntryJudged(t *testing.T) {
	s := materializeRetention(t, "v3-artifact-removed")
	file := filepath.Join(s.root, removalsFile)
	other := filepath.Join(s.root, "other.jsonl")
	if err := os.WriteFile(other, []byte(readFile(t, file)), 0o600); err != nil {
		t.Fatal(err)
	}
	removalJudged = func() {
		if err := os.Rename(other, file); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { removalJudged = nil })
	if rep, err := s.verify(t, ""); err == nil {
		t.Fatalf("another file put in the removal file's place gave a verdict: %+v", rep)
	}
}

// Records naming one receipt by the same members are kept once, under the
// latest key any of them was signed by, which is all namedBy reads.
func TestKeepRemovalKeepsTheLatestKeyOnce(t *testing.T) {
	removals := map[string][]removalRecord{}
	rec := removalRecord{sessionID: "s1", callIndex: 0, receiptSignature: "sig", resultDigest: "d"}
	for _, pos := range []int{0, 1, 0} {
		rec.keyPos = pos
		keepRemoval(removals, rec)
	}
	if named := removals["sig"]; len(named) != 1 || named[0].keyPos != 1 {
		t.Fatalf("kept %+v", named)
	}
	other := rec
	other.callIndex = 1
	keepRemoval(removals, other)
	if len(removals["sig"]) != 2 {
		t.Fatalf("a record of another index is another record: %+v", removals["sig"])
	}
}

// The removal file is read a line at a time (SPEC.md §1.3a): a line of at
// most removalLineBound bytes before its line feed is judged, and a longer
// one loads nothing and does not swallow the line after it; blank lines
// and lines that repeat a record keep nothing more; a last line with no
// line feed loads nothing and is torn. The corpus holds the bound itself
// (v3-artifact-removal-record-at-line-bound, -over-line-bound), for both
// verifiers.
func TestTheRemovalFileIsReadALineAtATime(t *testing.T) {
	s := materializeRetention(t, "v3-artifact-removed")
	data := []byte(readFile(t, filepath.Join(s.root, removalsFile)))
	record := strings.TrimSuffix(string(data), "\n")
	if strings.Contains(record, "\n") || len(record) > removalLineBound {
		t.Fatalf("the vector's file is not one record: %q", data)
	}
	padded := func(n int) string { return "{" + strings.Repeat(" ", n-len(record)) + record[1:] }
	keys := []reachedKey{{key: ed25519.PublicKey(s.publicKey), keyID: keyIDFor(s.publicKey)}}
	loaded := func(t *testing.T, text string) (int, bool) {
		t.Helper()
		removals, torn, err := scanRemovals(strings.NewReader(text), keys)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, named := range removals {
			n += len(named)
		}
		return n, torn
	}
	for name, c := range map[string]struct {
		text   string
		loaded int
		torn   bool
	}{
		"the record":    {record + "\n", 1, false},
		"at the bound":  {padded(removalLineBound) + "\n", 1, false},
		"one byte over": {padded(removalLineBound+1) + "\n", 0, false},
		// spaces after the record: its first removalLineBound bytes are a
		// record, so only the bound refuses the line
		"at the bound, spaces after":       {record + strings.Repeat(" ", removalLineBound-len(record)) + "\n", 1, false},
		"one byte over, spaces after":      {record + strings.Repeat(" ", removalLineBound+1-len(record)) + "\n", 0, false},
		"over, then the record":            {strings.Repeat("x", 3*removalLineBound+7) + "\n" + record + "\n", 1, false},
		"over and torn":                    {record + "\n" + strings.Repeat("x", 2*removalLineBound+2), 1, true},
		"blank lines and the record twice": {"\n\n" + record + "\n\n" + record + "\n" + padded(len(record)+3) + "\n", 1, false},
		"torn":                             {record, 0, true},
		"empty":                            {"", 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			if n, torn := loaded(t, c.text); n != c.loaded || torn != c.torn {
				t.Fatalf("%d record(s) kept, torn %v; want %d, %v", n, torn, c.loaded, c.torn)
			}
		})
	}
}

// Something at an artifact's path that yields no bytes -- a directory, a
// link that leads nowhere -- is artifact-missing, as it always was, for a
// receipt that says its call kept nothing too: only nothing at all there is
// a payload not kept.
func TestSomethingAtAnArtifactPathIsArtifactMissing(t *testing.T) {
	for name, make := range map[string]func(path string) error{
		"a directory": func(path string) error { return os.Mkdir(path, 0o755) },
		"a link that leads nowhere": func(path string) error {
			return os.Symlink(filepath.Join(filepath.Dir(path), "nowhere"), path)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := materializeRetention(t, "v3-artifact-not-retained")
			if err := make(filepath.Join(s.root, "artifacts", s.hexOf[0])); err != nil {
				if runtime.GOOS == "windows" && name != "a directory" {
					t.Skipf("no link here: %v", err)
				}
				t.Fatal(err)
			}
			if status, _ := statusOf(t, s.verdict(t, ""), 0); status != "artifact-missing" {
				t.Fatalf("%s at the path: %s, want artifact-missing", name, status)
			}
		})
	}
}

// A store that holds no artifacts/ at all holds nothing at any artifact's
// path: a receipt whose call kept nothing passes, and a kept one is
// artifact-missing. On Windows a name under a directory that is not there
// answers ERROR_PATH_NOT_FOUND, which absent does not take for absence, so
// the step looks at artifacts/ itself; the stand-in below gives that answer
// here.
func TestAStoreWithNoArtifactsDirectory(t *testing.T) {
	s := materializeRetention(t, "v3-artifact-not-retained")
	if err := os.RemoveAll(filepath.Join(s.root, "artifacts")); err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T) {
		t.Helper()
		rep := s.verdict(t, "")
		if status, observations := statusOf(t, rep, 0); status != "ok" || len(observations) != 1 || observations[0] != observationNotRetained {
			t.Fatalf("receipt 0, never kept: %s %v", status, observations)
		}
		if status, _ := statusOf(t, rep, 1); status != "artifact-missing" {
			t.Fatalf("receipt 1, kept: %s, want artifact-missing", status)
		}
	}
	check(t)
	t.Run("a name under a directory that is not there", func(t *testing.T) {
		under := filepath.Join(s.root, "artifacts") + string(filepath.Separator)
		lstat = func(path string) (fs.FileInfo, error) {
			if strings.HasPrefix(path, under) {
				return nil, &fs.PathError{Op: "lstat", Path: path, Err: syscall.Errno(3)}
			}
			return os.Lstat(path)
		}
		t.Cleanup(func() { lstat = os.Lstat })
		check(t)
	})
}

// Bytes a reader supplied are read only for a receipt that passed order 7
// with none in the store; there, an entry that is not a regular file is no
// verdict. For a receipt whose bytes the store holds, or a kept one that is
// gone with no record, the entry is never read.
func TestASuppliedEntryIsReadOnlyForAReceiptThatPassedWithNoBytes(t *testing.T) {
	unreadable := func(t *testing.T, s retentionStore, hexes ...string) string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "supplied")
		for _, h := range hexes {
			if err := os.MkdirAll(filepath.Join(dir, h), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	never := materializeRetention(t, "v3-artifact-not-retained")
	if rep, err := never.verify(t, unreadable(t, never, never.hexOf[0])); err == nil || !errors.Is(err, errSuppliedUnreadable) {
		t.Fatalf("an entry that is a directory, for a receipt that kept nothing: %v %+v", err, rep)
	}
	// receipt 1 is kept and its bytes are there: they are re-digested, and
	// the entry for them never read
	rep := never.verdict(t, unreadable(t, never, never.hexOf[1]))
	if status, _ := statusOf(t, rep, 1); status != "ok" {
		t.Fatalf("a kept receipt whose bytes are there: %s", status)
	}
	// receipt 0 kept, its bytes gone, no record: artifact-missing, the entry
	// never read
	gone := materializeRetention(t, "v3-artifact-missing-no-record")
	if status, _ := statusOf(t, gone.verdict(t, unreadable(t, gone, gone.hexOf[0])), 0); status != "artifact-missing" {
		t.Fatalf("a kept receipt gone with no record: %s, want artifact-missing", status)
	}
}

// The directory --artifacts names is there and a directory, or no verdict.
func TestASuppliedDirectoryThatIsNotADirectoryIsNoVerdict(t *testing.T) {
	s := materializeRetention(t, "v3-artifact-not-retained")
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{file, filepath.Join(t.TempDir(), "absent")} {
		if rep, err := s.verify(t, dir); err == nil {
			t.Fatalf("%s gave a verdict: %+v", dir, rep)
		}
	}
}

// gateway verify --artifacts <dir>: after --ordinary-seals-only, before the
// store root, or not at all. In any other place, given twice or with no
// directory, it is a usage error, exit 2 with nothing on stdout -- never
// taken as an argument and the verdict run without it.
func TestVerifyArtifactsOnTheCommandLine(t *testing.T) {
	s := materializeRetention(t, "v3-artifact-not-retained-supplied")
	supplied := suppliedOf(s.vector, s.tmp)
	stderr := captureStderr(t)
	oldStdin, oldStdout := os.Stdin, os.Stdout
	t.Cleanup(func() { os.Stdin, os.Stdout = oldStdin, oldStdout })
	run := func(args ...string) (int, string) {
		t.Helper()
		dir := t.TempDir()
		in, err := os.Create(filepath.Join(dir, "key"))
		if err != nil {
			t.Fatal(err)
		}
		defer in.Close()
		if _, err := in.Write(s.publicKey); err != nil {
			t.Fatal(err)
		}
		in.Seek(0, 0)
		out, err := os.Create(filepath.Join(dir, "out"))
		if err != nil {
			t.Fatal(err)
		}
		defer out.Close()
		os.Stdin, os.Stdout = in, out
		code := cmdVerify(args)
		os.Stdin, os.Stdout = oldStdin, oldStdout
		return code, readFile(t, out.Name())
	}
	const checked = `{"ok":true,"findings":[{"callIndex":0,"sessionId":"s1","status":"ok"},{"callIndex":1,"sessionId":"s1","status":"ok"}]}` + "\n"
	const observed = `{"ok":true,"findings":[{"callIndex":0,"sessionId":"s1","status":"ok"},{"callIndex":1,"sessionId":"s1","status":"ok"}],"observations":[{"callIndex":0,"observation":"artifact-not-retained","sessionId":"s1"}]}` + "\n"
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"--artifacts first":           {[]string{"--artifacts", supplied, s.root, s.registry, s.vector.Authority}, checked},
		"after --ordinary-seals-only": {[]string{"--ordinary-seals-only", "--artifacts", supplied, s.root, s.registry, s.vector.Authority}, checked},
		"not at all":                  {[]string{s.root, s.registry, s.vector.Authority}, observed},
	} {
		if code, out := run(c.args...); code != 0 || out != c.want {
			t.Fatalf("%s: %d %s", name, code, out)
		}
	}
	const misplaced = "gateway verify: --artifacts goes before the store root, after --ordinary-seals-only; a directory so named is given as ./--artifacts\n"
	const usage = "usage: gateway verify [--ordinary-seals-only] [--artifacts <dir>] <store-root> <registry-path> <authority> [--decision-records <dir> | <dir>]\n"
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"after the store root":         {[]string{s.root, "--artifacts", supplied, s.registry, s.vector.Authority}, misplaced + usage},
		"as the fourth argument":       {[]string{s.root, s.registry, s.vector.Authority, "--artifacts"}, misplaced + usage},
		"given twice":                  {[]string{"--artifacts", supplied, "--artifacts", supplied, s.root, s.registry, s.vector.Authority}, misplaced + usage},
		"with no directory":            {[]string{"--artifacts"}, usage},
		"with an empty directory name": {[]string{"--artifacts", "", s.root, s.registry, s.vector.Authority}, usage},
		"before --ordinary-seals-only": {[]string{"--artifacts", supplied, "--ordinary-seals-only", s.root, s.registry, s.vector.Authority}, "gateway verify: --ordinary-seals-only goes first, before the store root; a directory so named is given as ./--ordinary-seals-only\n" + usage},
	} {
		before := stderr()
		if code, out := run(c.args...); code != 2 || out != "" {
			t.Fatalf("%s: %d %q", name, code, out)
		}
		if got := strings.TrimPrefix(stderr(), before); got != c.want {
			t.Fatalf("%s: stderr %q, want %q", name, got, c.want)
		}
	}
	// a supplied directory that is not there: no verdict
	if code, out := run("--artifacts", filepath.Join(t.TempDir(), "absent"), s.root, s.registry, s.vector.Authority); code == 0 || out != "" {
		t.Fatalf("an absent supplied directory: %d %q", code, out)
	}
}

// A line loads as a removal record only of its form, member by member: each
// row below is the record of the first line, signed again over the change,
// so only the form refuses it. The first loads.
func TestARemovalRecordLoadsOnlyOfItsForm(t *testing.T) {
	seed := mustHex(t, strings.TrimSpace(readFile(t, corpusPath("TEST-SEED"))))
	priv := ed25519.NewKeyFromSeed(seed)
	public := priv.Public().(ed25519.PublicKey)
	keyID := keyIDFor(public)
	keys := []reachedKey{{key: public, keyID: keyID}}
	members := func() map[string]any {
		return map[string]any{
			"callIndex": int64(3), "keyId": keyID, "kind": removalKind,
			"receiptSignature": strings.Repeat("ab", 64), "removedAt": "2026-11-13T00:00:00Z",
			"removedBy": "retention-job", "resultDigest": "sha256:" + strings.Repeat("0", 64), "sessionId": "s1",
		}
	}
	line := func(m map[string]any) string {
		t.Helper()
		obj := newObject()
		for name, v := range m {
			switch v := v.(type) {
			case int64:
				obj.set(name, vInt(v))
			case string:
				obj.set(name, vString(v))
			}
		}
		obj.set("signature", vString(hex.EncodeToString(ed25519.Sign(priv, removalSigningInput(obj)))))
		return string(canon(obj))
	}
	if rec, ok := removalOf(line(members()), keys); !ok || rec.callIndex != 3 || rec.sessionID != "s1" || rec.keyPos != 0 {
		t.Fatalf("the record of its form: %+v %v", rec, ok)
	}
	for _, at := range []string{"2028-02-29T23:59:59Z", "0000-01-01T00:00:00Z", "9999-12-31T23:59:59Z"} {
		m := members()
		m["removedAt"] = at
		if _, ok := removalOf(line(m), keys); !ok {
			t.Errorf("removed at %s, an instant: not loaded", at)
		}
	}
	for name, change := range map[string]func(m map[string]any){
		"another kind":                 func(m map[string]any) { m["kind"] = "seal" },
		"a callIndex below 0":          func(m map[string]any) { m["callIndex"] = int64(-1) },
		"a callIndex past 2^53-1":      func(m map[string]any) { m["callIndex"] = int64(maxCallIndex + 1) },
		"a callIndex that is a string": func(m map[string]any) { m["callIndex"] = "3" },
		"a session id that is ..":      func(m map[string]any) { m["sessionId"] = ".." },
		"a receipt signature short":    func(m map[string]any) { m["receiptSignature"] = strings.Repeat("ab", 63) },
		"a digest of another form":     func(m map[string]any) { m["resultDigest"] = strings.Repeat("0", 64) },
		"a time of another form":       func(m map[string]any) { m["removedAt"] = "2026-11-13 00:00:00Z" },
		"a time of no calendar":        func(m map[string]any) { m["removedAt"] = "2026-13-45T99:99:99Z" },
		"a thirteenth month":           func(m map[string]any) { m["removedAt"] = "2026-13-01T00:00:00Z" },
		"a 30 February":                func(m map[string]any) { m["removedAt"] = "2028-02-30T00:00:00Z" },
		"a 29 February of no leap":     func(m map[string]any) { m["removedAt"] = "2026-02-29T00:00:00Z" },
		"a day 0":                      func(m map[string]any) { m["removedAt"] = "2026-11-00T00:00:00Z" },
		"an hour 24":                   func(m map[string]any) { m["removedAt"] = "2026-11-13T24:00:00Z" },
		"a minute 60":                  func(m map[string]any) { m["removedAt"] = "2026-11-13T00:60:00Z" },
		"a second 60":                  func(m map[string]any) { m["removedAt"] = "2026-11-13T23:59:60Z" },
		"an hour of one digit":         func(m map[string]any) { m["removedAt"] = "2026-11-13T1:00:00Z" },
		"a fraction of a second":       func(m map[string]any) { m["removedAt"] = "2026-11-13T00:00:00.5Z" },
		"an empty label":               func(m map[string]any) { m["removedBy"] = "" },
		"a label holding a line feed":  func(m map[string]any) { m["removedBy"] = "a\nb" },
		"a member left out":            func(m map[string]any) { delete(m, "removedAt") },
		"a tenth member":               func(m map[string]any) { m["note"] = "x" },
		"a key no walk reached":        func(m map[string]any) { m["keyId"] = strings.Repeat("0", 32) },
	} {
		m := members()
		change(m)
		if rec, ok := removalOf(line(m), keys); ok {
			t.Errorf("%s: loaded %+v", name, rec)
		}
	}
}
