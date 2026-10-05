package main

// The witness vectors of corpus/witness/ (SPEC.md §8), and the rule that
// nothing lands in the corpus unread.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// witnessFamilies are the families of witness vectors this runner reads
// (corpus/README.md). A vector of any other family refuses the run: it would
// otherwise be a vector no reader was held to.
var witnessFamilies = map[string]bool{
	"valid": true, "begins-late": true, "equivocation": true, "head": true, "key": true,
	"signature": true, "trail": true, "malformed": true, "chain": true, "bound": true,
}

// witnessVector is one vector: the trail being verified, the keys supplied,
// the statements files and the head file, and the answer expected.
type witnessVector struct {
	Name     string         `json:"name"`
	Family   string         `json:"family"`
	Note     string         `json:"note"`
	Trail    string         `json:"trail"`
	Keys     []string       `json:"keys"`
	Witness  []witnessFile  `json:"witness"`
	Head     *witnessFile   `json:"head"`
	Expected map[string]any `json:"expected"`
}

// witnessFile is a file's bytes: a string, its text exactly, or
// {"parts": [{"text", "times"}]}, each part's text repeated times times, in
// order -- the form that states a file at the byte bound without landing it.
type witnessFile struct{ parts []witnessPart }

type witnessPart struct {
	Text  string `json:"text"`
	Times int    `json:"times"`
}

func (f *witnessFile) UnmarshalJSON(raw []byte) error {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		f.parts = []witnessPart{{Text: text, Times: 1}}
		return nil
	}
	var form struct {
		Parts []witnessPart `json:"parts"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&form); err != nil {
		return err
	}
	for _, part := range form.Parts {
		if part.Times < 1 {
			return fmt.Errorf("a part repeated %d times", part.Times)
		}
	}
	f.parts = form.Parts
	return nil
}

// write materializes the file at path, a part at a time.
func (f witnessFile) write(path string) error {
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	for _, part := range f.parts {
		chunk := []byte(part.Text)
		for left := part.Times; left > 0; {
			n := left
			if room := (1 << 20) / max(len(chunk), 1); n > room {
				n = max(room, 1)
			}
			if _, err := out.Write(bytes.Repeat(chunk, n)); err != nil {
				out.Close()
				return err
			}
			left -= n
		}
	}
	return out.Close()
}

// corpusEntries refuses a corpus holding anything the runner does not read:
// every entry is a family this runner reads, or one named here as read
// elsewhere.
func corpusEntries(corpusDir string) error {
	read := map[string]string{
		"README.md":       "",
		"TEST-SEED":       "",
		"TEST-PUBLIC-KEY": "",
		"canon.json":      "",
		// The signature layer's vectors, from an independent implementation:
		// read by each implementation's own tests (go/conformance_test.go,
		// verify-ts/test/corpus.test.ts), since the process contract carries
		// no raw signature.
		"ed25519-vectors.json": "",
		"stores":               "*.json",
		"v3":                   "stores",
		"witness":              "*.json",
		// The witness's own storage: read by this implementation's runner
		// alone (conform_witness_recovery.go), outside the process
		// contract, since no reader of a chain reads it.
		"witness-recovery": "*.json",
	}
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		inside, known := read[entry.Name()]
		if !known || entry.IsDir() != (inside != "") {
			return fmt.Errorf("%s holds %s, which this runner does not read", corpusDir, entry.Name())
		}
		if inside == "" {
			continue
		}
		dir := filepath.Join(corpusDir, entry.Name())
		children, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, child := range children {
			switch {
			case inside == "*.json" && !child.IsDir() && strings.HasSuffix(child.Name(), ".json"):
			case inside == "stores" && child.IsDir() && child.Name() == "stores":
				if err := corpusEntriesOf(filepath.Join(dir, "stores")); err != nil {
					return err
				}
			default:
				return fmt.Errorf("%s holds %s, which this runner does not read", dir, child.Name())
			}
		}
	}
	return nil
}

// corpusEntriesOf refuses a directory of vectors holding anything but
// vectors.
func corpusEntriesOf(dir string) error {
	children, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, child := range children {
		if child.IsDir() || !strings.HasSuffix(child.Name(), ".json") {
			return fmt.Errorf("%s holds %s, which this runner does not read", dir, child.Name())
		}
	}
	return nil
}

// readWitnessVector reads one vector, refusing a member this runner does not
// know and a family it does not read.
func readWitnessVector(path string) (witnessVector, error) {
	var vector witnessVector
	raw, err := os.ReadFile(path)
	if err != nil {
		return vector, err
	}
	if err := decodeVectorFile(raw, &vector, true); err != nil {
		return vector, fmt.Errorf("%s: %v", path, err)
	}
	if !witnessFamilies[vector.Family] {
		return vector, fmt.Errorf("%s: family %q is not one this runner reads", path, vector.Family)
	}
	if vector.Name != strings.TrimSuffix(filepath.Base(path), ".json") {
		return vector, fmt.Errorf("%s: named %q", path, vector.Name)
	}
	if len(vector.Keys) == 0 || vector.Expected == nil {
		return vector, fmt.Errorf("%s: no keys or no expected answer", path)
	}
	if err := checkWitnessExpected(vector.Expected); err != nil {
		return vector, fmt.Errorf("%s: expected: %v", path, err)
	}
	return vector, nil
}

// checkWitnessExpected holds an expected answer to the members of its form
// (corpus/README.md), each once and nothing else: {"refused"}; {"ok": false,
// "findings"}; or {"ok": true, "findings", "reading", "headIndex",
// "highestIndex", "latestCheckpoint", "conflicts", "retired"}, its
// latestCheckpoint {"index", "sequence", "witnessedAt"}. A member of no form
// would be an expectation no runner compares, so it refuses the run.
func checkWitnessExpected(expected map[string]any) error {
	exactly := func(object map[string]any, names ...string) error {
		for name := range object {
			if !slices.Contains(names, name) {
				return fmt.Errorf("a member %q no runner compares", name)
			}
		}
		for _, name := range names {
			if _, ok := object[name]; !ok {
				return fmt.Errorf("no member %q", name)
			}
		}
		return nil
	}
	if _, refused := expected["refused"]; refused {
		if _, ok := expected["refused"].(string); !ok {
			return errors.New("refused is not a reason")
		}
		return exactly(expected, "refused")
	}
	ok, isBool := expected["ok"].(bool)
	if !isBool {
		return errors.New("neither refused nor ok")
	}
	if _, isArray := expected["findings"].([]any); !isArray {
		return errors.New("findings is not an array")
	}
	if !ok {
		return exactly(expected, "ok", "findings")
	}
	if err := exactly(expected, "ok", "findings", "reading", "headIndex", "highestIndex", "latestCheckpoint", "conflicts", "retired"); err != nil {
		return err
	}
	latest, isObject := expected["latestCheckpoint"].(map[string]any)
	if !isObject {
		return errors.New("latestCheckpoint is not an object")
	}
	if err := exactly(latest, "index", "sequence", "witnessedAt"); err != nil {
		return fmt.Errorf("latestCheckpoint: %w", err)
	}
	return nil
}

// The README's sentences and table that state how many vectors each family
// holds (corpus/README.md).
var (
	statedCanon    = regexp.MustCompile("\\*\\*`canon\\.json`\\*\\* — (\\d+) vectors")
	statedStores   = regexp.MustCompile("\\*\\*`stores/\\*\\.json`\\*\\* — (\\d+) vectors")
	statedV3       = regexp.MustCompile("\\*\\*`v3/stores/\\*\\.json`\\*\\* — (\\d+) vectors")
	statedWitness  = regexp.MustCompile("\\*\\*`witness/\\*\\.json`\\*\\* — (\\d+) vectors")
	statedRecovery = regexp.MustCompile("\\*\\*`witness-recovery/\\*\\.json`\\*\\* — (\\d+) vectors")
	statedFamilies = regexp.MustCompile("(?m)^\\| `([a-z-]+)` \\| (\\d+) \\|")
)

// readmeSection is the README's section under a heading, up to the next
// heading of its level: each family table is read in its own section.
func readmeSection(readme, heading string) string {
	start := strings.Index(readme, "\n## "+heading+"\n")
	if start < 0 {
		return ""
	}
	rest := readme[start+1:]
	if end := strings.Index(rest[3:], "\n## "); end >= 0 {
		return rest[:end+3]
	}
	return rest
}

// corpusStatedCounts refuses a corpus whose README states another number of
// vectors than it holds: of canon.json, stores/, v3/stores/ and witness/,
// and of each witness family, by the README's table. A vector added without
// its count, or a count without its vectors, is caught by the runner, not
// only by a test.
func corpusStatedCounts(corpusDir string) error {
	raw, err := os.ReadFile(filepath.Join(corpusDir, "README.md"))
	if err != nil {
		return err
	}
	readme := string(raw)
	stated := func(re *regexp.Regexp, what string) (int, error) {
		match := re.FindStringSubmatch(readme)
		if match == nil {
			return 0, fmt.Errorf("corpus/README.md states no count of %s", what)
		}
		return strconv.Atoi(match[1])
	}
	var canonFile struct {
		Vectors []json.RawMessage `json:"vectors"`
	}
	canonRaw, err := os.ReadFile(filepath.Join(corpusDir, "canon.json"))
	if err != nil {
		return err
	}
	if err := decodeVectorFile(canonRaw, &canonFile, false); err != nil {
		return fmt.Errorf("canon.json: %v", err)
	}
	stores, _ := filepath.Glob(filepath.Join(corpusDir, "stores", "*.json"))
	v3, _ := filepath.Glob(filepath.Join(corpusDir, "v3", "stores", "*.json"))
	witness, err := witnessVectorPaths(corpusDir)
	if err != nil {
		return err
	}
	recovery, err := recoveryVectorPaths(corpusDir)
	if err != nil {
		return err
	}
	for _, c := range []struct {
		re     *regexp.Regexp
		what   string
		actual int
	}{
		{statedCanon, "canon.json vectors", len(canonFile.Vectors)},
		{statedStores, "stores/*.json vectors", len(stores)},
		{statedV3, "v3/stores/*.json vectors", len(v3)},
		{statedWitness, "witness/*.json vectors", len(witness)},
		{statedRecovery, "witness-recovery/*.json vectors", len(recovery)},
	} {
		n, err := stated(c.re, c.what)
		if err != nil {
			return err
		}
		if n != c.actual {
			return fmt.Errorf("corpus/README.md states %d %s, and the corpus holds %d", n, c.what, c.actual)
		}
	}
	actual := map[string]int{}
	for _, path := range witness {
		vector, err := readWitnessVector(path)
		if err != nil {
			return err
		}
		actual[vector.Family]++
	}
	if err := statedFamilyCounts(readmeSection(readme, "Witness vectors"), "witness", witnessFamilies, actual); err != nil {
		return err
	}
	publicKey, err := corpusPublicKey(corpusDir)
	if err != nil {
		return err
	}
	actual = map[string]int{}
	for _, path := range recovery {
		vector, err := readRecoveryVector(path, publicKey)
		if err != nil {
			return err
		}
		actual[vector.Family]++
	}
	return statedFamilyCounts(readmeSection(readme, "Witness recovery vectors"), "witness-recovery", recoveryFamilies, actual)
}

// statedFamilyCounts refuses a section whose family table states another
// count than the corpus holds, or a family no runner reads.
func statedFamilyCounts(section, what string, families map[string]bool, actual map[string]int) error {
	statedFamily := map[string]int{}
	for _, row := range statedFamilies.FindAllStringSubmatch(section, -1) {
		if !families[row[1]] {
			return fmt.Errorf("corpus/README.md states a %s family %q no runner reads", what, row[1])
		}
		statedFamily[row[1]], _ = strconv.Atoi(row[2])
	}
	for family := range families {
		if statedFamily[family] != actual[family] {
			return fmt.Errorf("corpus/README.md states %d %s vectors of family %s, and the corpus holds %d", statedFamily[family], what, family, actual[family])
		}
	}
	return nil
}

// materializeWitnessVector writes a vector's files as the process contract
// hands them over: a key file per key, its hex and a newline; a file per
// statements file; and the head file when the vector has one.
func materializeWitnessVector(vector witnessVector) (root string, keyPaths, statementPaths []string, headPath string, err error) {
	root, err = os.MkdirTemp("", "witness")
	if err != nil {
		return "", nil, nil, "", err
	}
	fail := func(err error) (string, []string, []string, string, error) {
		os.RemoveAll(root)
		return "", nil, nil, "", err
	}
	for i, key := range vector.Keys {
		path := filepath.Join(root, fmt.Sprintf("key-%d", i))
		if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
			return fail(err)
		}
		keyPaths = append(keyPaths, path)
	}
	for i, file := range vector.Witness {
		path := filepath.Join(root, fmt.Sprintf("statements-%d.jsonl", i))
		if err := file.write(path); err != nil {
			return fail(err)
		}
		statementPaths = append(statementPaths, path)
	}
	if vector.Head != nil {
		headPath = filepath.Join(root, "head.jsonl")
		if err := vector.Head.write(headPath); err != nil {
			return fail(err)
		}
	}
	return root, keyPaths, statementPaths, headPath, nil
}

// witnessVectorPaths lists the witness vectors, in a fixed order.
func witnessVectorPaths(corpusDir string) ([]string, error) {
	paths, err := filepath.Glob(filepath.Join(corpusDir, "witness", "*.json"))
	sort.Strings(paths)
	return paths, err
}

// runWitnessVectors holds an implementation to every witness vector.
func runWitnessVectors(corpusDir string, impl implementation) ([]string, int, error) {
	paths, err := witnessVectorPaths(corpusDir)
	if err != nil {
		return nil, 0, err
	}
	var failures []string
	for _, path := range paths {
		vector, err := readWitnessVector(path)
		if err != nil {
			return nil, 0, err
		}
		root, keyPaths, statementPaths, headPath, err := materializeWitnessVector(vector)
		if err != nil {
			return nil, 0, err
		}
		produced, err := impl.witness(vector.Trail, keyPaths, statementPaths, headPath)
		os.RemoveAll(root)
		if err != nil {
			return nil, 0, fmt.Errorf("witness %s: %w", vector.Name, err)
		}
		if disagreement := compareWitness(vector.Expected, produced); disagreement != "" {
			failures = append(failures, fmt.Sprintf("witness %s: %s", vector.Name, disagreement))
		}
	}
	return failures, len(paths), nil
}

// compareWitness says how an answer disagrees with the one expected, or "".
// A refusal is compared by its reason; findings as a set of names, how many
// times and where a reader reports one not being normative; and, for a
// reading with no finding, every member of what the chain read says.
func compareWitness(expected, produced map[string]any) string {
	show := func(v map[string]any) string {
		encoded, _ := json.Marshal(v)
		return string(encoded)
	}
	if _, refused := expected["refused"]; refused {
		if !reflect.DeepEqual(expected, produced) {
			return fmt.Sprintf("expected %s, produced %s", show(expected), show(produced))
		}
		return ""
	}
	if _, refused := produced["refused"]; refused {
		return fmt.Sprintf("expected %s, produced %s", show(expected), show(produced))
	}
	if expected["ok"] != produced["ok"] {
		return fmt.Sprintf("expected ok=%v, produced %s", expected["ok"], show(produced))
	}
	want, err1 := findingSet(expected["findings"])
	have, err2 := findingSet(produced["findings"])
	if err := errors.Join(err1, err2); err != nil {
		return err.Error()
	}
	if strings.Join(want, "|") != strings.Join(have, "|") {
		return fmt.Sprintf("findings disagree\n    expected: %v\n    produced: %v", want, have)
	}
	if expected["ok"] != true {
		return ""
	}
	for _, name := range []string{"reading", "headIndex", "highestIndex", "latestCheckpoint", "conflicts", "retired"} {
		if !reflect.DeepEqual(expected[name], produced[name]) {
			return fmt.Sprintf("%s: expected %v, produced %v", name, expected[name], produced[name])
		}
	}
	return ""
}

func findingSet(v any) ([]string, error) {
	items, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("findings are not an array: %v", v)
	}
	set := map[string]bool{}
	for _, item := range items {
		name, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("a finding is not a name: %v", item)
		}
		set[name] = true
	}
	return sortedKeys(set), nil
}
