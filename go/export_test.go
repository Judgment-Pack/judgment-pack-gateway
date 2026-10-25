package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// restoreTree restores an export as an operator would: every directory
// and every file copied to another place.
func restoreTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(at string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, at)
		if err != nil {
			return err
		}
		target := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		data, err := os.ReadFile(at)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// verdictBytes is what `gateway verify` prints for a store.
func verdictBytes(t *testing.T, storeRoot, registryPath, authority, records string, publicKey []byte) []byte {
	t.Helper()
	rep, err := verifyWithRegistryAndRecords(storeRoot, registryPath, authority, records, publicKey)
	if err != nil {
		t.Fatalf("no verdict for %s: %v", storeRoot, err)
	}
	out, err := rep.marshal()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// restoredVerdict is the verdict over a restored export, given the
// decision-record directory only where the manifest says there was one.
func restoredVerdict(t *testing.T, restored, authority string, publicKey []byte) []byte {
	t.Helper()
	m, err := readExportManifest(restored)
	if err != nil {
		t.Fatal(err)
	}
	records := ""
	if m.decisionRecords {
		records = filepath.Join(restored, "decision-records")
	}
	return verdictBytes(t, filepath.Join(restored, "store"), filepath.Join(restored, "registry"), authority, records, publicKey)
}

func requireExportChecks(t *testing.T, dir string) {
	t.Helper()
	report, err := checkExport(dir)
	if err != nil {
		t.Fatalf("no verdict for the export: %v", err)
	}
	if ok, _ := report.get("ok"); ok != vBool(true) {
		t.Fatalf("the export does not check against its manifest: %s", canon(report))
	}
}

// Every corpus store -- damaged ones too: misfiled and malformed receipts,
// artifacts that do not digest, empty sessions, an absent registry, absent
// and present decision records -- exports, and a restore of the export
// checks against its manifest and verifies, byte for byte, as the store did.
func TestEveryCorpusStoreExportsAndARestoreVerifiesByteForByte(t *testing.T) {
	corpus := filepath.Join("..", "corpus")
	publicKey, err := corpusPublicKey(corpus)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := storeVectorPaths(corpus)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no store vectors: the test tests nothing")
	}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var vector storeVector
		if err := decodeVectorFile(raw, &vector, false); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		t.Run(vector.Name, func(t *testing.T) {
			root, storeRoot, registryPath, records, err := materializeVector(vector)
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			live := verdictBytes(t, storeRoot, registryPath, vector.Authority, records, publicKey)
			out := filepath.Join(t.TempDir(), "export")
			kind := newFsKind(fsLayout{store: storeRoot, registry: registryPath})
			if _, err := writeExport(exportInputs{authority: vector.Authority, keyID: keyIDFor(publicKey), kind: kind, decisionRecords: records}, out); err != nil {
				t.Fatalf("export: %v", err)
			}
			restored := filepath.Join(t.TempDir(), "restored")
			restoreTree(t, out, restored)
			requireExportChecks(t, restored)
			if got := restoredVerdict(t, restored, vector.Authority, publicKey); !bytes.Equal(got, live) {
				t.Fatalf("the restored export's verdict differs from the store's:\nstore:    %s\nrestored: %s", live, got)
			}
		})
	}
}

// A store written to while it is exported exports as one cut: at each
// moment the cut reads, a session is minted and sealed, and the export of
// it holds no seal whose receipts it lacks, nor a receipt whose artifact
// it lacks. A session minted after the registry was read is in the export
// unregistered, as it was in the store at that read; one minted later is
// not in the export at all.
func TestTheExportOfALiveStoreIsAConsistentCut(t *testing.T) {
	st, reg, storeRoot, registryPath := testStore(t)
	stampSession(t, st, "settled", 3)
	if _, err := reg.seal("settled", 3, "2026-10-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	var steps []string
	snapshotRead = func(space string) {
		steps = append(steps, space)
		session := "late-" + space
		stampSession(t, st, session, 2)
		if _, err := reg.seal(session, 2, "2026-10-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { snapshotRead = nil }()
	out := filepath.Join(t.TempDir(), "export")
	if _, err := writeExport(exportInputs{authority: "gateway:test", keyID: st.keyID, kind: newFsKind(fsLayout{store: storeRoot, registry: registryPath})}, out); err != nil {
		t.Fatal(err)
	}
	snapshotRead = nil
	if strings.Join(steps, ",") != "log,entries,blobs" {
		t.Fatalf("the cut read its spaces in the order %v", steps)
	}
	requireExportChecks(t, out)
	rep, err := verifyWithRegistry(filepath.Join(out, "store"), filepath.Join(out, "registry"), "gateway:test", st.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	unregistered := map[string]bool{}
	for _, f := range rep.Findings {
		switch f["status"] {
		case "ok":
		case "unregistered-session":
			unregistered[f["sessionId"].(string)] = true
		default:
			t.Errorf("the export of a live store is no consistent cut: %v", f)
		}
	}
	if len(unregistered) != 1 || !unregistered["late-log"] {
		t.Fatalf("the sessions minted while the cut read: unregistered in the export %v, want late-log alone", unregistered)
	}
	for _, s := range []string{"late-entries", "late-blobs"} {
		if _, err := os.Stat(filepath.Join(out, "store", "receipts", s)); err == nil {
			t.Fatalf("%s, minted after the cut listed the sessions, is in the export", s)
		}
	}
	// the store itself, every session now sealed, verifies
	if ok, counts := statuses(t, storeRoot, registryPath); !ok {
		t.Fatalf("the live store: %v", counts)
	}
}

// The export goes through `gateway export --config`: the key named by its
// id, the receipts, the registry, the decision records -- a link among
// them never followed -- the descriptor snapshot a platform pins and an
// observation journal; and `gateway export --check` and `gateway verify`
// over a restore of it agree with the store, byte for byte. The seed is
// in no file of it.
func TestExportCommandWritesWhatVerifyReads(t *testing.T) {
	dir := tempDirAt(t, 0o700)
	seedPath := filepath.Join(dir, "gateway.seed")
	if err := os.WriteFile(seedPath, []byte(hex.EncodeToString(testSeed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	storeRoot, registryPath, records := filepath.Join(dir, "store"), filepath.Join(dir, "registry.jsonl"), filepath.Join(dir, "decisions")
	st, err := newStore(storeRoot, testSeed, "gateway:test")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := newRegistryWriter(registryPath, testSeed, noHistory)
	if err != nil {
		t.Fatal(err)
	}
	stampSession(t, st, "sealed", 2)
	if _, err := reg.seal("sealed", 2, "2026-10-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	stampSession(t, st, "open", 1)
	if err := os.MkdirAll(filepath.Join(records, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"a.jsonl": "{\"one\":1}\n{\"two\":2}\n", "nested/b.json": `{"three":3}`, "..c.json": `{"four":4}`} {
		if err := os.WriteFile(filepath.Join(records, filepath.FromSlash(name)), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(seedPath, filepath.Join(records, "link.json")); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := canonicalSnapshot(t, servedTools)
	sum := sha256.Sum256(snapshot)
	pin := "sha256:" + hex.EncodeToString(sum[:])
	config := filepath.Join(dir, "engine.json")
	if err := os.Mkdir(config+".descriptors", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(config+".descriptors", 0o755); err != nil {
		t.Fatal(err)
	}
	snapshotFile := filepath.Join(config+".descriptors", hex.EncodeToString(sum[:])+".json")
	if err := os.WriteFile(snapshotFile, snapshot, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(snapshotFile, 0o644); err != nil {
		t.Fatal(err)
	}
	// every path written as a JSON string by the gateway's own encoder, so
	// a path reads as itself whatever its separators: a Windows path's
	// backslashes are no escapes
	str := func(s string) string { return string(canon(vString(s))) }
	text := `{"engineVersion":"3","authority":"gateway:test","seed":` + str(seedPath) + `,"store":` + str(storeRoot) + `,` +
		`"registry":` + str(registryPath) + `,"decisionRecords":` + str(records) + `,"listen":"127.0.0.1:8787",` +
		`"catalog":` + str(filepath.Join(dir, "catalog")) + `,"platforms":{"tickets":{"binding":` + str(servedBinding) + `,` +
		`"credentials":{"live":{"file":` + str(filepath.Join(dir, "tickets.env")) + `}},"user":"tickets","descriptors":` + str(pin) + `}}}`
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(dir, "observations.json")
	if err := os.WriteFile(journal, []byte(`{"version":"1","operations":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "export")
	var stdout, stderr bytes.Buffer
	if code := cmdExport([]string{"--config", config, "--out", out, "--observations", journal}, &stdout, &stderr); code != 0 {
		t.Fatalf("export: exit %d: %s", code, stderr.String())
	}
	// the registry, three receipts and their artifacts, three decision
	// records, the snapshot and the journal
	if want := fmt.Sprintf(`{"files":%d,"keyId":"%s","sessions":2}`+"\n", 12, st.keyID); stdout.String() != want {
		t.Fatalf("export said %q, want %q", stdout.String(), want)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	restoreTree(t, out, restored)
	stdout.Reset()
	if code := cmdExport([]string{"--check", restored}, &stdout, &stderr); code != 0 || stdout.String() != `{"findings":[],"ok":true}`+"\n" {
		t.Fatalf("check: exit %d: %s %s", code, stdout.String(), stderr.String())
	}
	m, err := readExportManifest(restored)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"registry", "decision-records/a.jsonl", "decision-records/nested/b.json", "decision-records/..c.json", "descriptors/" + hex.EncodeToString(sum[:]) + ".json", "observations/0.json"} {
		if _, ok := m.files[want]; !ok {
			t.Errorf("the manifest does not name %s", want)
		}
	}
	if _, ok := m.files["decision-records/link.json"]; ok {
		t.Error("the export followed a link among the decision records")
	}
	manifest, err := os.ReadFile(filepath.Join(restored, exportManifestName))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"keyId":"` + st.keyID + `"`, `"descriptors":[{"pin":"` + pin + `","platform":"tickets"}]`, `"sessions":["open","sealed"]`, `"authority":"gateway:test"`} {
		if !strings.Contains(string(manifest), want) {
			t.Errorf("the manifest does not carry %s: %s", want, manifest)
		}
	}
	live := verdictBytes(t, storeRoot, registryPath, "gateway:test", records, st.publicKey)
	if got := restoredVerdict(t, restored, "gateway:test", st.publicKey); !bytes.Equal(got, live) {
		t.Fatalf("the restored export's verdict differs:\nstore:    %s\nrestored: %s", live, got)
	}
	// the seed, in either form, is in no file of the export
	err = filepath.WalkDir(out, func(at string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(at)
		if err != nil {
			return err
		}
		if bytes.Contains(data, testSeed) || bytes.Contains(data, []byte(hex.EncodeToString(testSeed))) {
			t.Errorf("%s holds the seed", at)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// An export directory is never made inside what it exports, nor over
// anything that is there.
func TestExportRefusesAnOutputInsideTheStoreOrThere(t *testing.T) {
	_, _, storeRoot, registryPath := testStore(t)
	kind := newFsKind(fsLayout{store: storeRoot, registry: registryPath})
	for _, out := range []string{filepath.Join(storeRoot, "receipts", "export"), storeRoot} {
		if err := exportOutside(out, storeRoot, ""); err == nil {
			t.Errorf("an export at %s was not refused", out)
		}
	}
	if err := exportOutside(filepath.Join(filepath.Dir(storeRoot), "export"), storeRoot, ""); err != nil {
		t.Errorf("an export beside the store: %v", err)
	}
	there := t.TempDir()
	if _, err := writeExport(exportInputs{authority: "gateway:test", keyID: keyIDFor(make([]byte, 32)), kind: kind}, there); err == nil {
		t.Fatal("an export over a directory that is there was not refused")
	}
	if entries, _ := os.ReadDir(there); len(entries) != 0 {
		t.Fatalf("the refused export wrote %v", entries)
	}
}

// exportFixture is an export of a small store, restored, for a test to
// alter.
func exportFixture(t *testing.T) string {
	t.Helper()
	st, reg, storeRoot, registryPath := testStore(t)
	stampSession(t, st, "sealed", 2)
	if _, err := reg.seal("sealed", 2, "2026-10-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(storeRoot, "receipts", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "export")
	if _, err := writeExport(exportInputs{authority: "gateway:test", keyID: st.keyID, kind: newFsKind(fsLayout{store: storeRoot, registry: registryPath})}, out); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	restoreTree(t, out, restored)
	return restored
}

// Each alteration of a restore is found, by its path and what it is.
func TestExportCheckFindsEveryAlteration(t *testing.T) {
	artifact := func(t *testing.T, dir string) string {
		entries, err := os.ReadDir(filepath.Join(dir, "store", "artifacts"))
		if err != nil || len(entries) == 0 {
			t.Fatalf("no artifact to alter: %v", err)
		}
		return "store/artifacts/" + entries[0].Name()
	}
	cases := []struct {
		name  string
		alter func(t *testing.T, dir string) string
		want  string
	}{
		{"a byte changed", func(t *testing.T, dir string) string {
			at := filepath.Join(dir, "store", "receipts", "sealed", "0.json")
			data, _ := os.ReadFile(at)
			data[len(data)-2] ^= 1
			os.WriteFile(at, data, 0o600)
			return "store/receipts/sealed/0.json"
		}, "digest-mismatch"},
		{"a file cut short", func(t *testing.T, dir string) string {
			rel := artifact(t, dir)
			at := filepath.Join(dir, filepath.FromSlash(rel))
			data, _ := os.ReadFile(at)
			os.WriteFile(at, data[:len(data)-1], 0o600)
			return rel
		}, "size-mismatch"},
		{"a file removed", func(t *testing.T, dir string) string {
			os.Remove(filepath.Join(dir, "registry"))
			return "registry"
		}, "missing"},
		{"a file added", func(t *testing.T, dir string) string {
			os.WriteFile(filepath.Join(dir, "store", "receipts", "sealed", "2.json"), []byte("{}\n"), 0o600)
			return "store/receipts/sealed/2.json"
		}, "unlisted"},
		{"an empty session removed", func(t *testing.T, dir string) string {
			os.Remove(filepath.Join(dir, "store", "receipts", "empty"))
			return "store/receipts/empty"
		}, "missing"},
		{"a session added", func(t *testing.T, dir string) string {
			os.Mkdir(filepath.Join(dir, "store", "receipts", "replayed"), 0o700)
			return "store/receipts/replayed"
		}, "unlisted"},
		{"a directory of decision records added", func(t *testing.T, dir string) string {
			os.Mkdir(filepath.Join(dir, "decision-records"), 0o700)
			return "decision-records"
		}, "unlisted"},
	}
	if runtime.GOOS != "windows" {
		cases = append(cases, struct {
			name  string
			alter func(t *testing.T, dir string) string
			want  string
		}{"a file made a link to its copy", func(t *testing.T, dir string) string {
			at := filepath.Join(dir, "registry")
			copied := filepath.Join(filepath.Dir(dir), "registry-copy")
			data, _ := os.ReadFile(at)
			os.WriteFile(copied, data, 0o600)
			os.Remove(at)
			if err := os.Symlink(copied, at); err != nil {
				t.Fatal(err)
			}
			return "registry"
		}, "not-a-file"})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := exportFixture(t)
			requireExportChecks(t, dir)
			rel := c.alter(t, dir)
			report, err := checkExport(dir)
			if err != nil {
				t.Fatal(err)
			}
			want := `{"findings":[{"path":"` + rel + `","status":"` + c.want + `"}`
			if got := string(canon(report)); !strings.HasPrefix(got, want) || !strings.HasSuffix(got, `],"ok":false}`) {
				t.Fatalf("the check found %s, want %s...", got, want)
			}
		})
	}
}

// A manifest that cannot be read as one is no verdict: missing, empty,
// past its bound, not in the form it is written in, or naming what an
// export never writes.
func TestExportCheckRefusesAManifestItCannotRead(t *testing.T) {
	rewrite := func(t *testing.T, dir string, edit func(string) string) {
		at := filepath.Join(dir, exportManifestName)
		data, err := os.ReadFile(at)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(at, []byte(edit(string(data))), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name  string
		alter func(t *testing.T, dir string)
		want  string
	}{
		{"missing", func(t *testing.T, dir string) { os.Remove(filepath.Join(dir, exportManifestName)) }, "manifest.json"},
		{"empty", func(t *testing.T, dir string) { rewrite(t, dir, func(string) string { return "" }) }, "not JSON"},
		{"past its bound", func(t *testing.T, dir string) {
			info, _ := os.Stat(filepath.Join(dir, exportManifestName))
			saved := maxExportManifestBytes
			maxExportManifestBytes = int(info.Size()) - 1
			t.Cleanup(func() { maxExportManifestBytes = saved })
		}, "larger than"},
		{"not canonical", func(t *testing.T, dir string) {
			rewrite(t, dir, func(s string) string { return strings.Replace(s, `{"authority"`, `{ "authority"`, 1) })
		}, "canonical form"},
		{"no newline", func(t *testing.T, dir string) {
			rewrite(t, dir, func(s string) string { return strings.TrimSuffix(s, "\n") })
		}, "canonical form"},
		{"an unknown member", func(t *testing.T, dir string) {
			rewrite(t, dir, func(s string) string { return strings.Replace(s, `"registry":`, `"other":"x","registry":`, 1) })
		}, "unknown member"},
		{"another version", func(t *testing.T, dir string) {
			rewrite(t, dir, func(s string) string {
				return strings.Replace(s, `"exportVersion":"1"`, `"exportVersion":"2"`, 1)
			})
		}, "exportVersion"},
		{"a path outside the export", func(t *testing.T, dir string) {
			rewrite(t, dir, func(s string) string { return strings.Replace(s, `"path":"registry"`, `"path":"../registry"`, 1) })
		}, "not one an export writes"},
		{"a file named twice", func(t *testing.T, dir string) {
			rewrite(t, dir, func(s string) string {
				i := strings.Index(s, `{"digest"`)
				j := strings.Index(s[i:], "}") + i + 1
				return s[:j] + "," + s[i:]
			})
		}, "named twice"},
		{"a session it does not name", func(t *testing.T, dir string) {
			rewrite(t, dir, func(s string) string {
				return strings.Replace(s, `"sessions":["empty","sealed"]`, `"sessions":["empty"]`, 1)
			})
		}, "does not name"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := exportFixture(t)
			c.alter(t, dir)
			report, err := checkExport(dir)
			if err == nil {
				t.Fatalf("a verdict over a manifest that cannot be read: %s", canon(report))
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refused for %v, want %q", err, c.want)
			}
		})
	}
}

// The export's own refusals and its usage, through the command.
func TestExportCommandRefusals(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--config"},
		{"--config", "a.json"},
		{"--out", "x"},
		{"--check", "x", "--out", "y"},
		{"--config", "a.json", "--config", "b.json", "--out", "x"},
		{"--unknown", "x"},
		{"--check", ""},
	} {
		var stdout, stderr bytes.Buffer
		if code := cmdExport(args, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "usage:") {
			t.Errorf("%q: exit %d, %q", args, code, stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := cmdExport([]string{"--check", filepath.Join(t.TempDir(), "absent")}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
		t.Errorf("a check of nothing: exit %d, %q %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	missing := filepath.Join(t.TempDir(), "engine.json")
	if code := cmdExport([]string{"--config", missing, "--out", filepath.Join(t.TempDir(), "out")}, &stdout, &stderr); code != 1 || !strings.HasPrefix(stderr.String(), "export: engine configuration:") {
		t.Errorf("an export of a configuration that is not there: exit %d, %q", code, stderr.String())
	}
}

// An observation journal is taken as the custody wrote it, held to a JSON
// object within its bound.
func TestExportHoldsAnObservationJournalToItsForm(t *testing.T) {
	dir := t.TempDir()
	for name, text := range map[string]string{"empty": "", "array": "[]", "text": "journal"} {
		at := filepath.Join(dir, name)
		if err := os.WriteFile(at, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readObservationJournal(at); err == nil {
			t.Errorf("a journal that is %s was taken", name)
		}
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte(" "), maxObservationJournalBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readObservationJournal(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("a journal past its bound: %v", err)
	}
	if _, err := readObservationJournal(filepath.Join(dir, "absent")); err == nil {
		t.Error("a journal that is not there was taken")
	}
}

// withoutMember is an object with one member left out.
func withoutMember(obj *vObject, name string) *vObject {
	out := newObject()
	for _, n := range obj.names {
		if n != name {
			v, _ := obj.get(n)
			out.set(n, v)
		}
	}
	return out
}

// A hand-written export -- its files and manifest written by hand, each
// digest taken by another tool -- checks; and every member its manifest
// carries is read: an export whose manifest lacks any one of them is no
// verdict.
func TestAHandWrittenExportChecks(t *testing.T) {
	fixture := filepath.Join("testdata", "export")
	requireExportChecks(t, fixture)
	data, err := os.ReadFile(filepath.Join(fixture, exportManifestName))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	manifest := parsed.(*vObject)
	type removal struct {
		where, member string
		strip         func(member string) *vObject
	}
	var removals []removal
	for _, member := range manifest.names {
		removals = append(removals, removal{"manifest", member, func(m string) *vObject { return withoutMember(manifest, m) }})
	}
	for _, list := range []string{"files", "descriptors"} {
		raw, _ := manifest.get(list)
		first := raw.(vArray)[0].(*vObject)
		for _, member := range first.names {
			removals = append(removals, removal{list, member, func(m string) *vObject {
				items := append(vArray{withoutMember(first, m)}, raw.(vArray)[1:]...)
				out := withoutMember(manifest, list)
				out.set(list, items)
				return out
			}})
		}
	}
	if len(removals) != 13 {
		t.Fatalf("%d members to remove: the manifest is not the one written by hand", len(removals))
	}
	// an operation's pin names its operation, a non-empty string
	raw, _ := manifest.get("descriptors")
	byOperation := raw.(vArray)[1].(*vObject)
	if _, named := byOperation.get("operation"); !named {
		t.Fatal("the hand-written manifest pins no operation's snapshot")
	}
	for _, bad := range []value{vString(""), vInt(1)} {
		op := withoutMember(byOperation, "operation")
		op.set("operation", bad)
		out := withoutMember(manifest, "descriptors")
		out.set("descriptors", vArray{raw.(vArray)[0], op})
		removals = append(removals, removal{"descriptors", "an operation's name", func(string) *vObject { return out }})
	}
	for _, r := range removals {
		t.Run(r.where+" without "+r.member, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "export")
			restoreTree(t, fixture, dir)
			if err := os.WriteFile(filepath.Join(dir, exportManifestName), append(canon(r.strip(r.member)), '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			if report, err := checkExport(dir); err == nil {
				t.Fatalf("a verdict without %s: %s", r.member, canon(report))
			}
		})
	}
}

// The write path runs on any kind: receipts stamped and sessions sealed
// into the in-memory kind through the contract alone, exported, verify as
// a store of the filesystem kind does -- the export is how a kind other
// than the filesystem is verified.
func TestAStoreOfAnotherKindExportsAndVerifies(t *testing.T) {
	kind := newMemoryKind(nil)
	st := newStoreOn("", kind.artifacts(), kind.receipts(), testSeed, "gateway:test")
	reg, err := newRegistryWriterOn(kind.registry(), "the in-memory registry", testSeed, noHistory)
	if err != nil {
		t.Fatal(err)
	}
	stampSession(t, st, "first", 3)
	if _, err := reg.seal("first", 3, "2026-10-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.seal("first", 3, "2026-10-01T00:00:00Z"); err == nil || !strings.Contains(err.Error(), "already sealed") {
		t.Fatalf("a second seal of a session on the in-memory kind: %v", err)
	}
	stampSession(t, st, "second", 1)
	if _, err := reg.seal("second", 1, "2026-10-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "export")
	if _, err := writeExport(exportInputs{authority: "gateway:test", keyID: st.keyID, kind: kind}, out); err != nil {
		t.Fatal(err)
	}
	requireExportChecks(t, out)
	if ok, counts := statuses(t, filepath.Join(out, "store"), filepath.Join(out, "registry")); !ok || counts["ok"] != 4 {
		t.Fatalf("the export of the in-memory kind: ok=%v %v", ok, counts)
	}
}

// A platform's own pin and each of its operations' pins are exported, in
// the operations' order, each snapshot once, named in the manifest by the
// platform and, for an operation's, the operation.
func TestExportCarriesEveryOperationsPinnedSnapshot(t *testing.T) {
	f := newServedFixture(t, canonicalSnapshot(t, servedTools))
	other := f.write(t, canonicalSnapshot(t, `{"close":{"description":"Close a ticket"}}`))
	cfg := engineConfig{platforms: []platformConfig{
		{name: "tickets", binding: servedBinding, descriptors: f.pin},
		{name: "warehouse", binding: servedBinding, operationDescriptors: map[string]string{"write": f.pin, "live": other}},
	}}
	pins, err := readPinnedSnapshots(f.config, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range pins {
		got = append(got, p.platform+"/"+p.operation+"="+p.pin)
	}
	if want := []string{"tickets/=" + f.pin, "warehouse/live=" + other, "warehouse/write=" + f.pin}; strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("pins read %v, want %v", got, want)
	}
	_, _, storeRoot, registryPath := testStore(t)
	out := filepath.Join(t.TempDir(), "export")
	if _, err := writeExport(exportInputs{authority: "gateway:test", keyID: keyIDFor(make([]byte, 32)), kind: newFsKind(fsLayout{store: storeRoot, registry: registryPath}), pins: pins}, out); err != nil {
		t.Fatal(err)
	}
	requireExportChecks(t, out)
	manifest, err := os.ReadFile(filepath.Join(out, exportManifestName))
	if err != nil {
		t.Fatal(err)
	}
	want := `"descriptors":[{"pin":"` + f.pin + `","platform":"tickets"},{"operation":"live","pin":"` + other + `","platform":"warehouse"},{"operation":"write","pin":"` + f.pin + `","platform":"warehouse"}]`
	if !strings.Contains(string(manifest), want) {
		t.Fatalf("the manifest's descriptors: %s", manifest)
	}
	snapshots, err := os.ReadDir(filepath.Join(out, "descriptors"))
	if err != nil || len(snapshots) != 2 {
		t.Fatalf("the exported snapshots: %v %v", snapshots, err)
	}
}
