package main

// Run an implementation against the conformance corpus.
//
// The corpus is the arbiter, and it is FROZEN: it is hand-maintained normative
// data, not output regenerated from whichever implementation happens to exist.
// That distinction became load-bearing when this repository went to a single
// implementation -- a corpus regenerated from the only implementation is a mirror
// of it, and proves nothing. Changing a vector is a specification change.
//
//	gateway conform                    # this implementation, in process
//	gateway conform --impl ./other     # any implementation, via CONTRACT.md
//
// Every entry of the corpus is read, or the run is refused: a family of
// vectors the runner does not know cannot land in corpus/ and go unread
// (corpusEntries).
//
// Note this reads only public keys: corpus/TEST-PUBLIC-KEY, and the keys a
// witness vector supplies. Running the corpus never hands the runner a
// secret, which is the same property receipt version 2 gives a real verifier.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// decodeVectorFile reads a corpus file that is exactly one JSON value into
// dst: anything after that value but whitespace -- a second object, a stray
// byte -- refuses the file, and so does a member given twice in one object
// at any depth, so no corpus file holds material no runner reads. Every
// family's loader reads through it; with strict set, a member dst does not
// name refuses it too.
func decodeVectorFile(raw []byte, dst any, strict bool) error {
	if err := noMemberTwice(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("data follows the file's one JSON value")
	}
	return nil
}

// noMemberTwice is why a JSON text gives one member twice in an object, at
// any depth, or nil. encoding/json would keep the last of the two and pass
// the first over unread.
func noMemberTwice(raw []byte) error {
	type frame struct {
		object, key bool
		names       map[string]bool
	}
	var stack []*frame
	decoder := json.NewDecoder(bytes.NewReader(raw))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var top *frame
		if n := len(stack); n > 0 {
			top = stack[n-1]
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{', '[':
				if top != nil && top.object {
					top.key = true // after this value, a name
				}
				stack = append(stack, &frame{object: delim == '{', key: delim == '{', names: map[string]bool{}})
			default:
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if top == nil || !top.object {
			continue
		}
		if top.key {
			name, _ := token.(string)
			if top.names[name] {
				return fmt.Errorf("the member %q is given twice in one object", name)
			}
			top.names[name] = true
		}
		top.key = !top.key
	}
}

type canonVector struct {
	Note        string `json:"note"`
	InputJSON   string `json:"inputJson"`
	ExpectedHex string `json:"expectedHex"`
	Reject      bool   `json:"reject"`
}

type storeVector struct {
	Name      string            `json:"name"`
	Note      string            `json:"note"`
	Authority string            `json:"authority"`
	Files     map[string]string `json:"files"`
	Registry  string            `json:"registry"`
	// Version 3 only: the decision-record directory of SPEC.md §4 step 6,
	// materialized under its own root. Absent means the verifier is given
	// no directory, which is not the same as an empty one.
	DecisionRecords map[string]string `json:"decisionRecords"`
	// Optional, for cases the files map cannot express (SPEC.md §4.1).
	AbsentRegistry bool     `json:"absentRegistry"`
	EmptySessions  []string `json:"emptySessions"`
	Expected       struct {
		OK       bool             `json:"ok"`
		Findings []map[string]any `json:"findings"`
	} `json:"expected"`
}

// implementation is either this binary's own code or another process.
type implementation interface {
	canon(source string) ([]byte, bool)
	verify(storeRoot, registryPath, authority, decisionRecords string, publicKey []byte) (bool, []map[string]any, error)
	// witness reads one chain of witness statements (SPEC.md §8.6) from
	// files, and answers with the verdict the process contract gives.
	witness(trail string, keyPaths, statementPaths []string, headPath string) (map[string]any, error)
	label() string
}

type inProcess struct{}

func (inProcess) label() string { return "this implementation" }

func (inProcess) canon(source string) ([]byte, bool) {
	out, err := canonText([]byte(source))
	if err != nil {
		return nil, false
	}
	return out, true
}

func (inProcess) verify(storeRoot, registryPath, authority, decisionRecords string, publicKey []byte) (bool, []map[string]any, error) {
	rep, err := verifyWithRegistryAndRecords(storeRoot, registryPath, authority, decisionRecords, publicKey)
	if err != nil {
		return false, nil, err
	}
	raw, err := rep.marshal()
	if err != nil {
		return false, nil, err
	}
	var decoded struct {
		OK       bool             `json:"ok"`
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return false, nil, err
	}
	return decoded.OK, decoded.Findings, nil
}

func (inProcess) witness(trail string, keyPaths, statementPaths []string, headPath string) (map[string]any, error) {
	verdict, err := readWitnessFiles(trail, keyPaths, statementPaths, headPath)
	if err != nil {
		return nil, err
	}
	raw, err := verdict.marshal()
	if err != nil {
		return nil, err
	}
	var decoded map[string]any
	return decoded, json.Unmarshal(raw, &decoded)
}

type subprocess struct{ argv []string }

func (s subprocess) label() string { return strings.Join(s.argv, " ") }

func (s subprocess) canon(source string) ([]byte, bool) {
	cmd := exec.Command(s.argv[0], append(s.argv[1:], "canon")...)
	cmd.Stdin = strings.NewReader(source)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, false
	}
	return stdout.Bytes(), true
}

func (s subprocess) verify(storeRoot, registryPath, authority, decisionRecords string, publicKey []byte) (bool, []map[string]any, error) {
	args := append(s.argv[1:], "verify", storeRoot, registryPath, authority)
	if decisionRecords != "" {
		// The process contract's optional fourth argument (corpus/README.md):
		// passed exactly when the vector carries decision records.
		args = append(args, decisionRecords)
	}
	cmd := exec.Command(s.argv[0], args...)
	cmd.Stdin = bytes.NewReader(publicKey)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return false, nil, fmt.Errorf("verify produced no verdict: %s", stderr.String())
	}
	var decoded struct {
		OK       bool             `json:"ok"`
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		return false, nil, err
	}
	return decoded.OK, decoded.Findings, nil
}

// witnessArgs is the process contract's `witness` command line
// (corpus/README.md), its flags those of the runtime's `audit verify`.
func witnessArgs(trail string, keyPaths, statementPaths []string, headPath string) []string {
	args := []string{"witness", "--trail", trail}
	for _, path := range keyPaths {
		args = append(args, "--witness-key", path)
	}
	for _, path := range statementPaths {
		args = append(args, "--witness", path)
	}
	if headPath != "" {
		args = append(args, "--witness-head", headPath)
	}
	return args
}

func (s subprocess) witness(trail string, keyPaths, statementPaths []string, headPath string) (map[string]any, error) {
	cmd := exec.Command(s.argv[0], append(s.argv[1:], witnessArgs(trail, keyPaths, statementPaths, headPath)...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("witness produced no answer: %v: %s", err, stderr.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		return nil, fmt.Errorf("witness answered with no JSON object: %v", err)
	}
	return decoded, nil
}

// sortedFindings renders findings for comparison. Order is NOT normative, so
// they are compared as a multiset (see corpus/README.md).
func sortedFindings(findings []map[string]any) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		encoded, _ := json.Marshal(f)
		out = append(out, string(encoded))
	}
	sort.Strings(out)
	return out
}

func materializeVector(vector storeVector) (root, storeRoot, registryPath, decisionRecords string, err error) {
	root, err = os.MkdirTemp("", "corpus")
	if err != nil {
		return "", "", "", "", err
	}
	storeRoot = filepath.Join(root, "store")
	for path, text := range vector.Files {
		full := filepath.Join(storeRoot, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return "", "", "", "", err
		}
		// Bytes, never text: a newline translation would invalidate every
		// signature in the corpus.
		if err := os.WriteFile(full, []byte(text), 0o600); err != nil {
			return "", "", "", "", err
		}
	}
	if vector.DecisionRecords != nil {
		// Present, even when empty: a map with no entries is a directory with
		// no candidates, which is not the same input as no directory.
		decisionRecords = filepath.Join(root, "decisions")
		if err := os.MkdirAll(decisionRecords, 0o755); err != nil {
			return "", "", "", "", err
		}
		for path, text := range vector.DecisionRecords {
			full := filepath.Join(decisionRecords, filepath.FromSlash(path))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return "", "", "", "", err
			}
			if err := os.WriteFile(full, []byte(text), 0o600); err != nil {
				return "", "", "", "", err
			}
		}
	}
	for _, required := range []string{"receipts", "artifacts"} {
		if err := os.MkdirAll(filepath.Join(storeRoot, required), 0o755); err != nil {
			return "", "", "", "", err
		}
	}
	for _, name := range vector.EmptySessions {
		if err := os.MkdirAll(filepath.Join(storeRoot, "receipts", name), 0o755); err != nil {
			return "", "", "", "", err
		}
	}
	registryPath = filepath.Join(root, "registry.jsonl")
	if vector.AbsentRegistry {
		// Deliberately not created: a MISSING registry is a different input from
		// an empty one, and only one of them was previously covered.
		return root, storeRoot, registryPath, decisionRecords, nil
	}
	if err := os.WriteFile(registryPath, []byte(vector.Registry), 0o600); err != nil {
		return "", "", "", "", err
	}
	return root, storeRoot, registryPath, decisionRecords, nil
}

func corpusPublicKey(corpusDir string) ([]byte, error) {
	// .TrimSpace, not a newline trim: a checkout that converts line endings would
	// otherwise leave a \r inside the key, and every signature in the corpus would
	// fail for a reason that looks like a format disagreement.
	raw, err := os.ReadFile(filepath.Join(corpusDir, "TEST-PUBLIC-KEY"))
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(raw)))
}

// corpusCounts is how many vectors of each family a run read.
type corpusCounts struct{ canon, stores, witness, recovery int }

func runCorpus(corpusDir string, impl implementation) ([]string, corpusCounts, error) {
	var failures []string
	var counts corpusCounts
	if err := corpusEntries(corpusDir); err != nil {
		return nil, counts, err
	}
	if err := corpusStatedCounts(corpusDir); err != nil {
		return nil, counts, err
	}

	raw, err := os.ReadFile(filepath.Join(corpusDir, "canon.json"))
	if err != nil {
		return nil, counts, err
	}
	var canonFile struct {
		Vectors []canonVector `json:"vectors"`
	}
	if err := decodeVectorFile(raw, &canonFile, false); err != nil {
		return nil, counts, fmt.Errorf("canon.json: %v", err)
	}
	for _, vector := range canonFile.Vectors {
		produced, accepted := impl.canon(vector.InputJSON)
		if vector.Reject {
			if accepted {
				failures = append(failures, fmt.Sprintf(
					"canon %s: expected REFUSAL, produced %q (%s)",
					vector.InputJSON, produced, vector.Note))
			}
			continue
		}
		expected, err := hex.DecodeString(vector.ExpectedHex)
		if err != nil {
			return nil, counts, err
		}
		if !accepted {
			failures = append(failures, fmt.Sprintf(
				"canon %s: expected bytes, got a REFUSAL (%s)", vector.InputJSON, vector.Note))
		} else if !bytes.Equal(produced, expected) {
			failures = append(failures, fmt.Sprintf(
				"canon %s: expected %q, produced %q (%s)",
				vector.InputJSON, expected, produced, vector.Note))
		}
	}

	publicKey, err := corpusPublicKey(corpusDir)
	if err != nil {
		return nil, counts, err
	}
	// Both directories arbitrate: the version 2 vectors and, since the
	// version 3 verifier, the version 3 vectors staged beside them.
	paths, err := storeVectorPaths(corpusDir)
	if err != nil {
		return nil, counts, err
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, counts, err
		}
		var vector storeVector
		if err := decodeVectorFile(raw, &vector, false); err != nil {
			return nil, counts, fmt.Errorf("%s: %v", path, err)
		}
		root, storeRoot, registryPath, decisionRecords, err := materializeVector(vector)
		if err != nil {
			return nil, counts, err
		}
		ok, findings, err := impl.verify(storeRoot, registryPath, vector.Authority, decisionRecords, publicKey)
		os.RemoveAll(root)
		if err != nil {
			return nil, counts, err
		}
		if ok != vector.Expected.OK {
			failures = append(failures, fmt.Sprintf("store %s: expected ok=%v, got ok=%v",
				vector.Name, vector.Expected.OK, ok))
		}
		want, have := sortedFindings(vector.Expected.Findings), sortedFindings(findings)
		if strings.Join(want, "|") != strings.Join(have, "|") {
			failures = append(failures, fmt.Sprintf(
				"store %s: findings disagree\n    expected: %v\n    produced: %v",
				vector.Name, want, have))
		}
	}
	counts.canon, counts.stores = len(canonFile.Vectors), len(paths)

	witnessFailures, witnessCount, err := runWitnessVectors(corpusDir, impl)
	if err != nil {
		return nil, counts, err
	}
	counts.witness = witnessCount
	failures = append(failures, witnessFailures...)

	// The recovery vectors hold this implementation's own witness, so they
	// are run only when it is the implementation under test, and where a
	// witness keeps its files; otherwise they are read and held to their
	// form, and not run.
	_, own := impl.(inProcess)
	recoveryFailures, recoveryCount, err := runRecoveryVectors(corpusDir, own && witnessFilesKept)
	if err != nil {
		return nil, counts, err
	}
	counts.recovery = recoveryCount
	return append(failures, recoveryFailures...), counts, nil
}

// storeVectorPaths lists every store vector the runner answers to, in a fixed
// order: corpus/stores/ and corpus/v3/stores/.
func storeVectorPaths(corpusDir string) ([]string, error) {
	var paths []string
	for _, dir := range []string{filepath.Join(corpusDir, "stores"), filepath.Join(corpusDir, "v3", "stores")} {
		found, err := filepath.Glob(filepath.Join(dir, "*.json"))
		if err != nil {
			return nil, err
		}
		sort.Strings(found)
		paths = append(paths, found...)
	}
	return paths, nil
}

func cmdConform(args []string) int {
	corpusDir := filepath.Join("..", "corpus")
	var impl implementation = inProcess{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--impl":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--impl needs a command")
				return 2
			}
			impl = subprocess{argv: strings.Fields(args[i+1])}
			i++
		case "--corpus":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--corpus needs a directory")
				return 2
			}
			corpusDir = args[i+1]
			i++
		}
	}
	failures, counts, err := runCorpus(corpusDir, impl)
	if err != nil {
		fmt.Fprintln(os.Stderr, "corpus:", err)
		return 2
	}
	fmt.Printf("%s vs corpus: %d canon vectors, %d store vectors, %d witness vectors\n",
		impl.label(), counts.canon, counts.stores, counts.witness)
	if _, own := impl.(inProcess); own && witnessFilesKept {
		fmt.Printf("this implementation's witness vs corpus: %d witness recovery vectors\n", counts.recovery)
	} else if own {
		fmt.Printf("%d witness recovery vectors read and not run: a witness keeps its files only on Unix\n", counts.recovery)
	} else {
		fmt.Printf("%d witness recovery vectors read and not run: they hold this reference witness's own storage, outside the process contract\n", counts.recovery)
	}
	for _, failure := range failures {
		fmt.Printf("  FAIL %s\n", failure)
	}
	fmt.Printf("%d disagreement(s)\n", len(failures))
	if len(failures) > 0 {
		return 1
	}
	return 0
}
