package main

// `gateway export` (docs/design/store-contract.md, "The audit export"):
// one consistent cut of an engine's durable state -- the receipts and
// artifacts, the registry, the decision records, the descriptor snapshots
// its platforms pin, and the observation journals its connection custody
// exported -- written in the store layout SPEC.md §1.3 states, so
// `gateway verify` reads an export, or a restore of one, as it reads a
// live store; with a manifest naming the signer's key and every file by
// its digest, which `gateway export --check` holds the files to, byte for
// byte.
//
// The cut is the store kind's (storeKind.snapshot): the registry read
// first, so every seal it holds counts receipts the export holds. The
// decision records are the runtime's files and no space of the kind; they
// are read after the cut, so a record written before an action receipt the
// cut holds is in the export. Nothing is written into the store, and the
// seed never leaves: the manifest names the key by its id, and a verifier
// pins the public key out of band (SECURITY.md).

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const exportUsage = `usage:
  gateway export --config <engine.json> --out <dir> [--observations <file>]...
  gateway export --check <dir>
--out is a directory that is not there yet; --observations names a journal
the connection custody exported (gateway-connections --export-observations).
--check holds an export, or a restore of one, to its manifest.`

const (
	exportVersion = "1"
	// exportManifestName is the manifest's file in an export.
	exportManifestName = "manifest.json"
	// maxObservationJournalBytes bounds an observation journal an export
	// takes; the custody's own journal is far smaller.
	maxObservationJournalBytes = 1 << 20
)

// maxExportManifestBytes bounds the manifest --check reads; a test lowers it.
var maxExportManifestBytes = 1 << 30

func cmdExport(args []string, stdout, stderr io.Writer) int {
	var config, out, check string
	var observations []string
	for rest := args; len(rest) > 0; rest = rest[2:] {
		if len(rest) < 2 || rest[1] == "" {
			fmt.Fprintln(stderr, exportUsage)
			return 2
		}
		var into *string
		switch rest[0] {
		case "--config":
			into = &config
		case "--out":
			into = &out
		case "--check":
			into = &check
		case "--observations":
			observations = append(observations, rest[1])
			continue
		default:
			fmt.Fprintln(stderr, exportUsage)
			return 2
		}
		if *into != "" {
			fmt.Fprintf(stderr, "%s is given twice\n%s\n", rest[0], exportUsage)
			return 2
		}
		*into = rest[1]
	}
	if check != "" {
		if config != "" || out != "" || len(observations) > 0 {
			fmt.Fprintln(stderr, exportUsage)
			return 2
		}
		report, err := checkExport(check)
		if err != nil {
			// no verdict: the manifest cannot be read as one
			fmt.Fprintln(stderr, "export check:", err)
			return 1
		}
		stdout.Write(append(canon(report), '\n'))
		return 0
	}
	if config == "" || out == "" {
		fmt.Fprintln(stderr, exportUsage)
		return 2
	}
	summary, err := exportEngine(config, out, observations)
	if err != nil {
		fmt.Fprintln(stderr, "export:", err)
		return 1
	}
	stdout.Write(append(canon(summary), '\n'))
	return 0
}

// exportEngine exports the durable state an engine configuration names.
func exportEngine(configPath, out string, observations []string) (*vObject, error) {
	data, err := readBounded(configPath, maxEngineConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("engine configuration: %v", err)
	}
	cfg, err := parseEngineConfig(data)
	if err != nil {
		return nil, err
	}
	seed, err := loadSeed(cfg.seed)
	if err != nil {
		return nil, fmt.Errorf("seed: %v", err)
	}
	keyID := keyIDFor(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if err := exportOutside(out, cfg.store, cfg.decisionRecords); err != nil {
		return nil, err
	}
	// every pin is read and digested before anything is written
	pins, err := readPinnedSnapshots(configPath, cfg)
	if err != nil {
		return nil, err
	}
	journals := make([][]byte, 0, len(observations))
	for _, p := range observations {
		journal, err := readObservationJournal(p)
		if err != nil {
			return nil, err
		}
		journals = append(journals, journal)
	}
	kind := newFsKind(fsLayout{store: cfg.store, registry: cfg.registry})
	return writeExport(exportInputs{
		authority: cfg.authority, keyID: keyID, kind: kind,
		decisionRecords: cfg.decisionRecords, pins: pins, observations: journals,
	}, out)
}

// exportOutside refuses an export directory inside what it exports: a
// directory made under the store's receipts would be a session there, and
// a file made under the decision records a record verification reads.
func exportOutside(out string, roots ...string) error {
	resolve := func(p string) (string, error) {
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", err
		}
		// the deepest part of the path that is there, links resolved,
		// and the rest as spelled
		rest := ""
		for at := abs; ; at = filepath.Dir(at) {
			if real, err := filepath.EvalSymlinks(at); err == nil {
				return filepath.Join(real, rest), nil
			}
			if filepath.Dir(at) == at {
				return abs, nil
			}
			rest = filepath.Join(filepath.Base(at), rest)
		}
	}
	target, err := resolve(out)
	if err != nil {
		return err
	}
	for _, root := range roots {
		if root == "" {
			continue
		}
		held, err := resolve(root)
		if err != nil {
			return err
		}
		if rel, err := filepath.Rel(held, target); err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))) {
			return fmt.Errorf("the export directory %s is inside %s, which it exports", out, root)
		}
	}
	return nil
}

// exportPin is a descriptor snapshot a platform pins -- for the platform,
// or for one of its operations (operationDescriptors) -- read and digested.
type exportPin struct {
	platform, operation, pin string
	data                     []byte
}

// readPinnedSnapshots reads every snapshot a platform pins, its own and
// each of its operations' in the operations' order, as the MCP server opens
// the snapshots' directory (openServedDirectory) and as a blob of the
// filesystem kind; each must digest to its pin.
func readPinnedSnapshots(configPath string, cfg engineConfig) ([]exportPin, error) {
	dir, err := openServedDirectory(configPath, cfg)
	if err != nil || dir == nil {
		return nil, err
	}
	defer dir.Close()
	pins := fsHeldPins{dir: dir.dir, name: dir.name, owner: dir.owner}
	var out []exportPin
	read := func(platform, operation, pin string) error {
		what := "platform " + platform + ": descriptors"
		if operation != "" {
			what = "platform " + platform + ": operation " + operation + ": descriptors"
		}
		data, err := pins.getBlob(pin)
		if err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		sum := sha256.Sum256(data)
		if "sha256:"+hex.EncodeToString(sum[:]) != pin {
			return fmt.Errorf("%s: the snapshot does not digest to its pin", what)
		}
		out = append(out, exportPin{platform: platform, operation: operation, pin: pin, data: data})
		return nil
	}
	for _, p := range cfg.platforms {
		if p.descriptors != "" {
			if err := read(p.name, "", p.descriptors); err != nil {
				return nil, err
			}
		}
		operations := make([]string, 0, len(p.operationDescriptors))
		for name := range p.operationDescriptors {
			operations = append(operations, name)
		}
		sort.Strings(operations)
		for _, name := range operations {
			if err := read(p.name, name, p.operationDescriptors[name]); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// readObservationJournal reads a journal the custody exported: a regular
// file, bounded, holding one JSON object. Its members are the custody's;
// the export names it by its digest and reads nothing else of it.
func readObservationJournal(p string) ([]byte, error) {
	data, err := readBounded(p, maxObservationJournalBytes)
	if err != nil {
		return nil, fmt.Errorf("observations: %v", err)
	}
	if v, err := parseJSON(data); err != nil {
		return nil, fmt.Errorf("observations: %s is not JSON: %v", p, err)
	} else if _, ok := v.(*vObject); !ok {
		return nil, fmt.Errorf("observations: %s is not a JSON object", p)
	}
	return data, nil
}

// exportInputs is what an export writes: the kind it cuts, and what lies
// beside the kind.
type exportInputs struct {
	authority       string
	keyID           string
	kind            storeKind
	decisionRecords string
	pins            []exportPin
	observations    [][]byte
}

// exportWriter writes an export's files, each made once, synced, and named
// in the manifest by its digest.
type exportWriter struct {
	out   string
	files vArray
	dirs  map[string]bool
}

func (w *exportWriter) dir(rel string) error {
	at := filepath.Join(w.out, filepath.FromSlash(rel))
	if err := os.MkdirAll(at, 0o700); err != nil {
		return err
	}
	for d := rel; d != "." && d != "/"; d = path.Dir(d) {
		w.dirs[d] = true
	}
	return nil
}

func (w *exportWriter) put(rel string, data []byte) error {
	if !exportPathWritten(rel) {
		return fmt.Errorf("%q cannot be named in an export: a manifest names a file by a clean, slash-separated path", rel)
	}
	if err := w.dir(path.Dir(rel)); err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(w.out, filepath.FromSlash(rel)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("%s: %v", rel, err)
	}
	sum := sha256.Sum256(data)
	entry := newObject()
	entry.set("digest", vString("sha256:"+hex.EncodeToString(sum[:])))
	entry.set("path", vString(rel))
	entry.set("size", vInt(len(data)))
	w.files = append(w.files, entry)
	return nil
}

// writeExport writes the export into out, which must not be there yet.
func writeExport(in exportInputs, out string) (*vObject, error) {
	if err := os.Mkdir(out, 0o700); err != nil {
		return nil, fmt.Errorf("the export directory: %v", err)
	}
	w := &exportWriter{out: out, dirs: map[string]bool{}}
	cut, err := in.kind.snapshot()
	if err != nil {
		return nil, fmt.Errorf("the store's cut: %w", err)
	}
	if cut.logPresent {
		if err := w.put("registry", cut.log); err != nil {
			return nil, err
		}
	}
	for _, rel := range []string{"store/receipts", "store/artifacts"} {
		if err := w.dir(rel); err != nil {
			return nil, err
		}
	}
	sessions := vArray{}
	for _, series := range cut.series {
		if series == "" || strings.ContainsAny(series, `/\`) || series == "." || series == ".." {
			return nil, fmt.Errorf("session %q cannot be named in an export", series)
		}
		if err := w.dir("store/receipts/" + series); err != nil {
			return nil, err
		}
		sessions = append(sessions, vString(series))
		for _, entry := range cut.entries[series] {
			data, err := cut.entry(series, entry)
			if err != nil {
				return nil, fmt.Errorf("receipt %s/%s.json: %w", series, entry, err)
			}
			if err := w.put("store/receipts/"+series+"/"+entry+".json", data); err != nil {
				return nil, err
			}
		}
	}
	for _, name := range cut.blobs {
		data, err := cut.blob(name)
		switch faultOf(err) {
		case "":
		case faultAbsent:
			// listed and gone by its name -- a link that leads nowhere --
			// is the artifact verification finds missing, and the export
			// holds none for it either
			continue
		default:
			return nil, fmt.Errorf("artifact %s: %w", name, err)
		}
		hexSum, _ := blobHex(name)
		if err := w.put("store/artifacts/"+hexSum, data); err != nil {
			return nil, err
		}
	}
	// the decision records, read after the cut, as verification walks them
	recordsThere := false
	if in.decisionRecords != "" {
		var walkErr error
		_, _, there, err := walkDecisionRecords(in.decisionRecords, nil, decisionWalk{onFile: func(at string, data []byte) {
			if walkErr != nil {
				return
			}
			rel, err := filepath.Rel(in.decisionRecords, at)
			if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				walkErr = fmt.Errorf("decision record %s is not under its directory", at)
				return
			}
			walkErr = w.put("decision-records/"+filepath.ToSlash(rel), data)
		}})
		if err != nil {
			return nil, fmt.Errorf("decision records: %w", err)
		}
		if walkErr != nil {
			return nil, walkErr
		}
		if recordsThere = there; there {
			if err := w.dir("decision-records"); err != nil {
				return nil, err
			}
		}
	}
	descriptors := vArray{}
	for _, p := range in.pins {
		hexSum, _ := blobHex(p.pin)
		if !w.listed("descriptors/" + hexSum + ".json") {
			if err := w.put("descriptors/"+hexSum+".json", p.data); err != nil {
				return nil, err
			}
		}
		pinned := newObject()
		if p.operation != "" {
			pinned.set("operation", vString(p.operation))
		}
		pinned.set("pin", vString(p.pin))
		pinned.set("platform", vString(p.platform))
		descriptors = append(descriptors, pinned)
	}
	for i, journal := range in.observations {
		if err := w.put(fmt.Sprintf("observations/%d.json", i), journal); err != nil {
			return nil, err
		}
	}
	sort.Slice(w.files, func(i, j int) bool { return filePath(w.files[i]) < filePath(w.files[j]) })
	manifest := newObject()
	manifest.set("authority", vString(in.authority))
	manifest.set("decisionRecords", vBool(recordsThere))
	manifest.set("descriptors", descriptors)
	manifest.set("exportVersion", vString(exportVersion))
	manifest.set("files", w.files)
	manifest.set("keyId", vString(in.keyID))
	manifest.set("registry", vBool(cut.logPresent))
	manifest.set("sessions", sessions)
	// the manifest last: an export without one is an export that stopped
	if err := w.writeManifest(append(canon(manifest), '\n')); err != nil {
		return nil, err
	}
	summary := newObject()
	summary.set("files", vInt(len(w.files)))
	summary.set("keyId", vString(in.keyID))
	summary.set("sessions", vInt(len(sessions)))
	return summary, nil
}

func filePath(v value) string {
	s, _ := memberString(v.(*vObject), "path")
	return s
}

func (w *exportWriter) listed(rel string) bool {
	for _, f := range w.files {
		if filePath(f) == rel {
			return true
		}
	}
	return false
}

// writeManifest syncs every directory the export made, deepest first, as
// far as the platform can, and only then writes the manifest: a manifest
// that is there names files whose entries are as durable as it is.
func (w *exportWriter) writeManifest(data []byte) error {
	dirs := make([]string, 0, len(w.dirs))
	for d := range w.dirs {
		dirs = append(dirs, d)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dirs)))
	for _, d := range dirs {
		syncDir(filepath.Join(w.out, filepath.FromSlash(d)))
	}
	file, err := os.OpenFile(filepath.Join(w.out, exportManifestName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("%s: %v", exportManifestName, err)
	}
	syncDir(w.out)
	return nil
}

// exportManifest is a manifest as --check reads it.
type exportManifest struct {
	files           map[string]exportFile
	sessions        map[string]bool
	decisionRecords bool
}

type exportFile struct {
	digest string
	size   int64
}

// readExportManifest reads the manifest and holds it to its shape: the
// canonical form it is written in, every member of its type, every path
// one the export writes.
func readExportManifest(dir string) (*exportManifest, error) {
	at := filepath.Join(dir, exportManifestName)
	info, err := os.Lstat(at)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", at)
	}
	data, err := readBounded(at, maxExportManifestBytes)
	if err != nil {
		return nil, err
	}
	v, err := parseJSON(data)
	if err != nil {
		return nil, fmt.Errorf("the manifest is not JSON: %v", err)
	}
	if string(data) != string(canon(v))+"\n" {
		return nil, errors.New("the manifest is not in the canonical form it is written in")
	}
	obj, ok := v.(*vObject)
	if !ok {
		return nil, errors.New("the manifest is not an object")
	}
	if err := exactlyMembers(obj, map[string]bool{
		"authority": true, "decisionRecords": true, "descriptors": true, "exportVersion": true,
		"files": true, "keyId": true, "registry": true, "sessions": true,
	}, "manifest"); err != nil {
		return nil, err
	}
	if version, _ := memberString(obj, "exportVersion"); version != exportVersion {
		return nil, fmt.Errorf("the manifest's exportVersion is not %q", exportVersion)
	}
	if _, err := requireString(obj, "authority"); err != nil {
		return nil, fmt.Errorf("manifest: %v", err)
	}
	if keyID, _ := memberString(obj, "keyId"); !isLowerHexOfLen(keyID, len(keyIDFor(make([]byte, ed25519.PublicKeySize)))) {
		return nil, errors.New("manifest: keyId is not a key id")
	}
	m := &exportManifest{files: map[string]exportFile{}, sessions: map[string]bool{}}
	flag := func(name string) (bool, error) {
		raw, _ := obj.get(name)
		b, ok := raw.(vBool)
		if !ok {
			return false, fmt.Errorf("manifest: %s is not a boolean", name)
		}
		return bool(b), nil
	}
	registry, err := flag("registry")
	if err != nil {
		return nil, err
	}
	if m.decisionRecords, err = flag("decisionRecords"); err != nil {
		return nil, err
	}
	array := func(name string) (vArray, error) {
		raw, _ := obj.get(name)
		a, ok := raw.(vArray)
		if !ok {
			return nil, fmt.Errorf("manifest: %s is not an array", name)
		}
		return a, nil
	}
	files, err := array("files")
	if err != nil {
		return nil, err
	}
	previous := ""
	for _, raw := range files {
		f, ok := raw.(*vObject)
		if !ok || exactlyMembers(f, map[string]bool{"digest": true, "path": true, "size": true}, "manifest file") != nil {
			return nil, errors.New("manifest: a file is not {digest, path, size}")
		}
		p, _ := memberString(f, "path")
		digest, _ := memberString(f, "digest")
		size, isInt := func() (vInt, bool) { s, _ := f.get("size"); n, ok := s.(vInt); return n, ok }()
		if !exportPathWritten(p) || !isDigest(digest) || !isInt || size < 0 {
			return nil, fmt.Errorf("manifest: a file is not one an export writes: %q", p)
		}
		if p <= previous {
			return nil, fmt.Errorf("manifest: the files are not in order, or %q is named twice", p)
		}
		previous = p
		m.files[p] = exportFile{digest: digest, size: int64(size)}
	}
	if _, listed := m.files["registry"]; listed != registry {
		return nil, errors.New("manifest: registry says otherwise than the files do")
	}
	sessions, err := array("sessions")
	if err != nil {
		return nil, err
	}
	previous = ""
	for _, raw := range sessions {
		s, ok := raw.(vString)
		if !ok || s == "" || strings.ContainsAny(string(s), `/\`) || s == "." || s == ".." || string(s) <= previous {
			return nil, errors.New("manifest: sessions are not names of directories, in order, each once")
		}
		previous = string(s)
		m.sessions[string(s)] = true
	}
	for p := range m.files {
		if rest, ok := strings.CutPrefix(p, "store/receipts/"); ok {
			if session, _, _ := strings.Cut(rest, "/"); !m.sessions[session] {
				return nil, fmt.Errorf("manifest: %s is in a session the manifest does not name", p)
			}
		}
		if strings.HasPrefix(p, "decision-records/") && !m.decisionRecords {
			return nil, fmt.Errorf("manifest: %s is a decision record, and the manifest says there were none", p)
		}
	}
	descriptors, err := array("descriptors")
	if err != nil {
		return nil, err
	}
	for _, raw := range descriptors {
		d, ok := raw.(*vObject)
		if !ok || exactlyMembers(d, map[string]bool{"operation": false, "pin": true, "platform": true}, "manifest descriptor") != nil {
			return nil, errors.New("manifest: a descriptor is not {operation?, pin, platform}")
		}
		if raw, present := d.get("operation"); present {
			if operation, isString := raw.(vString); !isString || operation == "" {
				return nil, errors.New("manifest: a descriptor's operation is not an operation's name")
			}
		}
		pin, _ := memberString(d, "pin")
		if _, err := requireString(d, "platform"); err != nil || !isDigest(pin) {
			return nil, errors.New("manifest: a descriptor is not a platform's pin")
		}
		hexSum, _ := blobHex(pin)
		if _, listed := m.files["descriptors/"+hexSum+".json"]; !listed {
			return nil, fmt.Errorf("manifest: the snapshot %s is pinned and not among the files", pin)
		}
	}
	return m, nil
}

// exportPathWritten reports whether a path is one an export writes: clean,
// relative, slash-separated, under one of its places, and never the
// manifest itself.
func exportPathWritten(p string) bool {
	if p == "" || path.Clean(p) != p || path.IsAbs(p) || strings.HasPrefix(p, "../") || strings.Contains(p, `\`) {
		return false
	}
	if p == "registry" {
		return true
	}
	parts := strings.Split(p, "/")
	switch {
	case len(parts) == 4 && parts[0] == "store" && parts[1] == "receipts":
		return strings.HasSuffix(parts[3], ".json")
	case len(parts) == 3 && parts[0] == "store" && parts[1] == "artifacts":
		return isLowerHexOfLen(parts[2], 64)
	case len(parts) >= 2 && parts[0] == "decision-records":
		return true
	case len(parts) == 2 && parts[0] == "descriptors":
		hexSum, ok := strings.CutSuffix(parts[1], ".json")
		return ok && isLowerHexOfLen(hexSum, 64)
	case len(parts) == 2 && parts[0] == "observations":
		return strings.HasSuffix(parts[1], ".json")
	}
	return false
}

// checkExport holds an export, or a restore of one, to its manifest: every
// file it names there, of its size, digesting to its digest; nothing there
// it does not name; every session it names a directory, and no other.
// The report is a verdict, as verify's is: ok, and the findings, each a
// path and what is wrong with it. No verdict -- a manifest that cannot be
// read as one -- is an error.
func checkExport(dir string) (*vObject, error) {
	if info, err := os.Lstat(dir); err != nil {
		return nil, err
	} else if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	m, err := readExportManifest(dir)
	if err != nil {
		return nil, err
	}
	type finding struct{ path, status string }
	var findings []finding
	seen := map[string]bool{}
	sessionDirs := map[string]bool{}
	recordsThere := false
	err = filepath.WalkDir(dir, func(at string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, at)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." || rel == exportManifestName {
			return nil
		}
		switch {
		case d.IsDir():
			switch parts := strings.Split(rel, "/"); {
			case rel == "store", rel == "store/receipts", rel == "store/artifacts", rel == "descriptors", rel == "observations":
			case len(parts) == 3 && parts[0] == "store" && parts[1] == "receipts":
				sessionDirs[parts[2]] = true
			case parts[0] == "decision-records" && m.decisionRecords:
				recordsThere = true
			default:
				findings = append(findings, finding{rel, "unlisted"})
				return filepath.SkipDir
			}
		case d.Type().IsRegular():
			seen[rel] = true
			want, listed := m.files[rel]
			if !listed {
				findings = append(findings, finding{rel, "unlisted"})
				return nil
			}
			data, err := os.ReadFile(at)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			switch {
			case int64(len(data)) != want.size:
				findings = append(findings, finding{rel, "size-mismatch"})
			case "sha256:"+hex.EncodeToString(sum[:]) != want.digest:
				findings = append(findings, finding{rel, "digest-mismatch"})
			}
		default:
			// a link, or anything that is no file or directory: a reader of
			// the export would read something else through it
			seen[rel] = true
			findings = append(findings, finding{rel, "not-a-file"})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for p := range m.files {
		if !seen[p] {
			findings = append(findings, finding{p, "missing"})
		}
	}
	for s := range m.sessions {
		if !sessionDirs[s] {
			findings = append(findings, finding{"store/receipts/" + s, "missing"})
		}
	}
	for s := range sessionDirs {
		if !m.sessions[s] {
			findings = append(findings, finding{"store/receipts/" + s, "unlisted"})
		}
	}
	if m.decisionRecords && !recordsThere {
		findings = append(findings, finding{"decision-records", "missing"})
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].path != findings[j].path {
			return findings[i].path < findings[j].path
		}
		return findings[i].status < findings[j].status
	})
	list := vArray{}
	for _, f := range findings {
		o := newObject()
		o.set("path", vString(f.path))
		o.set("status", vString(f.status))
		list = append(list, o)
	}
	report := newObject()
	report.set("findings", list)
	report.set("ok", vBool(len(findings) == 0))
	return report, nil
}
