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
	"sort"
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
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vector); err != nil {
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
	return vector, nil
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
