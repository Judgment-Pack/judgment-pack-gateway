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
// Note this reads only corpus/TEST-PUBLIC-KEY. Running the corpus never hands
// the runner a secret, which is the same property receipt version 2 gives a real
// verifier.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

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
	verify(storeRoot, registryPath, authority string, publicKey []byte) (bool, []map[string]any, error)
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

func (inProcess) verify(storeRoot, registryPath, authority string, publicKey []byte) (bool, []map[string]any, error) {
	rep, err := verifyWithRegistry(storeRoot, registryPath, authority, publicKey)
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

func (s subprocess) verify(storeRoot, registryPath, authority string, publicKey []byte) (bool, []map[string]any, error) {
	cmd := exec.Command(s.argv[0], append(s.argv[1:], "verify", storeRoot, registryPath, authority)...)
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

func materializeVector(vector storeVector) (root, storeRoot, registryPath string, err error) {
	root, err = os.MkdirTemp("", "corpus")
	if err != nil {
		return "", "", "", err
	}
	storeRoot = filepath.Join(root, "store")
	for path, text := range vector.Files {
		full := filepath.Join(storeRoot, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return "", "", "", err
		}
		// Bytes, never text: a newline translation would invalidate every
		// signature in the corpus.
		if err := os.WriteFile(full, []byte(text), 0o600); err != nil {
			return "", "", "", err
		}
	}
	for _, required := range []string{"receipts", "artifacts"} {
		if err := os.MkdirAll(filepath.Join(storeRoot, required), 0o755); err != nil {
			return "", "", "", err
		}
	}
	for _, name := range vector.EmptySessions {
		if err := os.MkdirAll(filepath.Join(storeRoot, "receipts", name), 0o755); err != nil {
			return "", "", "", err
		}
	}
	registryPath = filepath.Join(root, "registry.jsonl")
	if vector.AbsentRegistry {
		// Deliberately not created: a MISSING registry is a different input from
		// an empty one, and only one of them was previously covered.
		return root, storeRoot, registryPath, nil
	}
	if err := os.WriteFile(registryPath, []byte(vector.Registry), 0o600); err != nil {
		return "", "", "", err
	}
	return root, storeRoot, registryPath, nil
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

func runCorpus(corpusDir string, impl implementation) ([]string, int, int, error) {
	var failures []string

	raw, err := os.ReadFile(filepath.Join(corpusDir, "canon.json"))
	if err != nil {
		return nil, 0, 0, err
	}
	var canonFile struct {
		Vectors []canonVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &canonFile); err != nil {
		return nil, 0, 0, err
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
			return nil, 0, 0, err
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
		return nil, 0, 0, err
	}
	paths, err := filepath.Glob(filepath.Join(corpusDir, "stores", "*.json"))
	if err != nil {
		return nil, 0, 0, err
	}
	sort.Strings(paths)
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, 0, 0, err
		}
		var vector storeVector
		if err := json.Unmarshal(raw, &vector); err != nil {
			return nil, 0, 0, err
		}
		root, storeRoot, registryPath, err := materializeVector(vector)
		if err != nil {
			return nil, 0, 0, err
		}
		ok, findings, err := impl.verify(storeRoot, registryPath, vector.Authority, publicKey)
		os.RemoveAll(root)
		if err != nil {
			return nil, 0, 0, err
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
	return failures, len(canonFile.Vectors), len(paths), nil
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
	failures, canonCount, storeCount, err := runCorpus(corpusDir, impl)
	if err != nil {
		fmt.Fprintln(os.Stderr, "corpus:", err)
		return 2
	}
	fmt.Printf("%s vs corpus: %d canon vectors, %d store vectors\n",
		impl.label(), canonCount, storeCount)
	for _, failure := range failures {
		fmt.Printf("  FAIL %s\n", failure)
	}
	fmt.Printf("%d disagreement(s)\n", len(failures))
	if len(failures) > 0 {
		return 1
	}
	return 0
}
