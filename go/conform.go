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
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// decodeVectorFile reads a corpus file that is exactly one JSON value into
// dst: anything after that value but whitespace -- a second object, a stray
// byte -- refuses the file, and so does a member given twice in one object
// at any depth, so no corpus file holds material no runner reads. Every
// family's loader reads through it. A member is read by its exact name
// (decodeExactly); with strict set, a member dst does not name -- one named
// in another case included -- refuses the file too, and without, it is
// passed over.
func decodeVectorFile(raw []byte, dst any, strict bool) error {
	if err := noMemberTwice(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var value json.RawMessage
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("data follows the file's one JSON value")
	}
	return decodeExactly(value, reflect.ValueOf(dst).Elem(), strict)
}

// decodeAnswer reads an implementation's answer -- a verdict, or a witness
// answer -- into dst: one JSON value, each member read by its exact name and
// any other passed over (decodeExactly), as a verdict may carry members no
// runner reads. An answer that gives a member twice in one object, at any
// depth, is answered memberTwice, a malformed answer and no reading of
// either occurrence; one that is no JSON value, as before, an error.
func decodeAnswer(raw []byte, dst any) error {
	var value json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	if err := noMemberTwice(value); err != nil {
		return err
	}
	return decodeExactly(value, reflect.ValueOf(dst).Elem(), false)
}

// memberTwice is a JSON text giving one member twice in an object: the
// member's name, as written.
type memberTwice struct{ name string }

func (e memberTwice) Error() string {
	return fmt.Sprintf("the member %q is given twice in one object", e.name)
}

// jsonMember is one member of a JSON object: its name and its value's bytes.
type jsonMember struct {
	name  string
	value json.RawMessage
}

// objectMembers is a JSON object's members in the order written, a name
// given twice kept twice, or why raw, one JSON value, is no object.
func objectMembers(raw json.RawMessage, t reflect.Type) ([]jsonMember, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if token != json.Delim('{') {
		return nil, notOfType(raw, t)
	}
	var members []jsonMember
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, _ := token.(string)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		members = append(members, jsonMember{name, value})
	}
	return members, nil
}

// notOfType is encoding/json's refusal of a value that is not of type t.
func notOfType(raw json.RawMessage, t reflect.Type) error {
	kind := "number"
	if trimmed := bytes.TrimSpace(raw); len(trimmed) > 0 {
		switch trimmed[0] {
		case '{':
			kind = "object"
		case '[':
			kind = "array"
		case '"':
			kind = "string"
		case 't', 'f':
			kind = "bool"
		}
	}
	return &json.UnmarshalTypeError{Value: kind, Type: t}
}

var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// readsMembers is whether encoding/json would read a struct's members by
// name to decode a value of type t: t is a struct, or a pointer, slice,
// array or map whose elements hold one, and reads no JSON of its own (a
// json.Unmarshaler reads its own).
func readsMembers(t reflect.Type) bool {
	if t.Implements(unmarshalerType) || reflect.PointerTo(t).Implements(unmarshalerType) {
		return false
	}
	switch t.Kind() {
	case reflect.Struct:
		return true
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		return readsMembers(t.Elem())
	}
	return false
}

// decodeExactly decodes raw, one JSON value, into v as encoding/json does,
// with one difference: a struct's member is read only under the name its
// field gives, exactly. encoding/json matches a name ignoring case, by
// Unicode's simple folding ("OK", and "o" and the Kelvin sign, are read as
// "ok"), and keeps the last of the members so matched. Here a member named
// otherwise is one the struct does not name: refused with strict set, as
// json.Decoder.DisallowUnknownFields refuses one, and passed over without.
// A map's keys and a json.Unmarshaler's own reading are encoding/json's,
// which are already exact.
func decodeExactly(raw json.RawMessage, v reflect.Value, strict bool) error {
	t := v.Type()
	if !readsMembers(t) {
		return json.Unmarshal(raw, v.Addr().Interface())
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		// As encoding/json: null makes a pointer, slice or map nil, and
		// leaves a struct as it is.
		if t.Kind() != reflect.Struct {
			v.SetZero()
		}
		return nil
	}
	switch t.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			v.Set(reflect.New(t.Elem()))
		}
		return decodeExactly(raw, v.Elem(), strict)
	case reflect.Slice:
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return notOfType(raw, t)
		}
		out := reflect.MakeSlice(t, len(items), len(items))
		for i, item := range items {
			if err := decodeExactly(item, out.Index(i), strict); err != nil {
				return err
			}
		}
		v.Set(out)
		return nil
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return fmt.Errorf("no exact reading of %s", t)
		}
		members, err := objectMembers(raw, t)
		if err != nil {
			return err
		}
		if v.IsNil() {
			v.Set(reflect.MakeMapWithSize(t, len(members)))
		}
		for _, m := range members {
			elem := reflect.New(t.Elem()).Elem()
			if err := decodeExactly(m.value, elem, strict); err != nil {
				return err
			}
			v.SetMapIndex(reflect.ValueOf(m.name).Convert(t.Key()), elem)
		}
		return nil
	case reflect.Struct:
		members, err := objectMembers(raw, t)
		if err != nil {
			return err
		}
		for _, m := range members {
			i, named, err := fieldNamed(t, m.name)
			if err != nil {
				return err
			}
			if !named {
				if strict {
					return fmt.Errorf("json: unknown field %q", m.name)
				}
				continue
			}
			if err := decodeExactly(m.value, v.Field(i), strict); err != nil {
				// Where it was, as encoding/json says it: the struct and
				// the path of members down to the value refused.
				var refused *json.UnmarshalTypeError
				if errors.As(err, &refused) {
					refused.Struct = t.Name()
					refused.Field = strings.TrimSuffix(m.name+"."+refused.Field, ".")
				}
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("no exact reading of %s", t)
}

// fieldNamed is the index of t's field encoding/json reads the member name
// into, matched exactly, and whether there is one. An embedded field, whose
// members encoding/json promotes, refuses: no type read here has one, and
// one added would not be read exactly unless this reads it.
func fieldNamed(t reflect.Type, name string) (int, bool, error) {
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Anonymous {
			return 0, false, fmt.Errorf("no exact reading of %s: its field %s is embedded", t, f.Name)
		}
		if !f.IsExported() {
			continue
		}
		tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if tag == "-" {
			continue
		}
		if tag == "" {
			tag = f.Name
		}
		if tag == name {
			return i, true, nil
		}
	}
	return 0, false, nil
}

// noMemberTwice is why a JSON text gives one member twice in an object, at
// any depth -- a memberTwice -- or why it is no JSON text, or nil.
// encoding/json would keep the last of the two and pass the first over
// unread.
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
				return memberTwice{name}
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
	// OrdinarySealsOnly runs the vector under --ordinary-seals-only
	// (SPEC.md §4, §7): the process contract passes the option first.
	OrdinarySealsOnly bool `json:"ordinarySealsOnly"`
	Expected          struct {
		OK       bool             `json:"ok"`
		Findings []map[string]any `json:"findings"`
		// Witnesses are SPEC.md §4's witnesses, compared as a set; absent
		// means none (ADR-0014).
		Witnesses []map[string]any `json:"witnesses"`
		// Rotations are SPEC.md §4's rotations, compared whole; absent
		// means the walk of the registry followed none (§3b).
		Rotations map[string]any `json:"rotations"`
		// Observations are SPEC.md §4's observations, compared as a
		// multiset where a vector states them; unlike witnesses and
		// rotations, absent means the vector is not compared on them at
		// all (§7). Kept as written, so a member given as null is told
		// from one not given (expectedObservations).
		Observations json.RawMessage `json:"observations"`
	} `json:"expected"`
}

// expectedObservations is the observations a vector states, and whether it
// states the member at all: without it, the vector is not compared on
// observations (SPEC.md §7). A member that is not an array of objects
// refuses the run, and so does one with an element that is not an object:
// given as null, the member would read as not stated and compare nothing,
// and an element given as null, which is no object, would decode as one
// with no members.
func (v storeVector) expectedObservations() ([]map[string]any, bool, error) {
	if v.Expected.Observations == nil {
		return nil, false, nil
	}
	refused := errors.New("expected observations are not an array of objects")
	var stated []map[string]any
	if err := json.Unmarshal(v.Expected.Observations, &stated); err != nil || stated == nil {
		return nil, false, refused
	}
	for _, observation := range stated {
		if observation == nil {
			return nil, false, refused
		}
	}
	return stated, true, nil
}

// contractVerdict is a verdict as the process contract gives it
// (corpus/README.md): ok, the findings, the observations, the witnesses,
// absent when none, and the rotations, absent when none was followed.
type contractVerdict struct {
	OK       bool             `json:"ok"`
	Findings []map[string]any `json:"findings"`
	// Observations are kept as written and read only for a vector that
	// states them, so what an implementation writes there is not read for
	// any other vector (SPEC.md §7).
	Observations json.RawMessage  `json:"observations"`
	Witnesses    []map[string]any `json:"witnesses"`
	Rotations    map[string]any   `json:"rotations"`
}

// implementation is either this binary's own code or another process.
type implementation interface {
	canon(source string) ([]byte, bool)
	// verify answers the verdict the process contract gives (SPEC.md §4),
	// under --ordinary-seals-only when ordinarySealsOnly is set.
	verify(storeRoot, registryPath, authority, decisionRecords string, ordinarySealsOnly bool, publicKey []byte) (contractVerdict, error)
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

func (inProcess) verify(storeRoot, registryPath, authority, decisionRecords string, ordinarySealsOnly bool, publicKey []byte) (contractVerdict, error) {
	rep, err := verifierFor(ordinarySealsOnly)(storeRoot, registryPath, authority, decisionRecords, publicKey)
	if err != nil {
		return contractVerdict{}, err
	}
	raw, err := rep.marshal()
	if err != nil {
		return contractVerdict{}, err
	}
	return decodeVerdict(raw)
}

// verifierFor is the verdict gateway verify gives, plain or under
// --ordinary-seals-only (SPEC.md §4).
func verifierFor(ordinarySealsOnly bool) func(storeRoot, registryPath, authority, decisionRecords string, publicKey []byte) (*report, error) {
	if ordinarySealsOnly {
		return verifyOrdinarySealsOnly
	}
	return verifyWithRegistryAndRecords
}

// decodeVerdict reads a verdict as the process contract gives it, its
// members by their exact names (decodeAnswer).
func decodeVerdict(raw []byte) (contractVerdict, error) {
	var decoded contractVerdict
	if err := decodeAnswer(raw, &decoded); err != nil {
		return contractVerdict{}, err
	}
	return decoded, nil
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
	if err := decodeAnswer(raw, &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
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

func (s subprocess) verify(storeRoot, registryPath, authority, decisionRecords string, ordinarySealsOnly bool, publicKey []byte) (contractVerdict, error) {
	args := append(append([]string{}, s.argv[1:]...), "verify")
	if ordinarySealsOnly {
		// The option first, before the store root, as gateway verify takes
		// it (corpus/README.md): passed exactly when the vector says so.
		args = append(args, "--ordinary-seals-only")
	}
	args = append(args, storeRoot, registryPath, authority)
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
		var exited *exec.ExitError
		if errors.As(err, &exited) {
			return contractVerdict{}, noVerdict{stderr: stderr.String()}
		}
		return contractVerdict{}, fmt.Errorf("verify produced no verdict: %s", stderr.String())
	}
	return decodeVerdict(stdout.Bytes())
}

// noVerdict is an implementation's verify that ran and exited non-zero: by
// the process contract it gave no verdict (corpus/README.md). Under
// --ordinary-seals-only that is its answer to the vector; otherwise it stops
// the run (SPEC.md §7).
type noVerdict struct{ stderr string }

func (e noVerdict) Error() string { return "verify produced no verdict: " + e.stderr }

// quotedBound is how much a disagreement quotes of what an implementation
// wrote: of its standard error, or of the name of a member its answer gives
// twice.
const quotedBound = 256

// boundedQuote is what an implementation wrote as a disagreement quotes it:
// at most quotedBound bytes of it, and quoted, so it reaches the report only
// as text.
func boundedQuote(s string) string {
	if len(s) <= quotedBound {
		return strconv.Quote(s)
	}
	return fmt.Sprintf("%s and %d bytes more", strconv.Quote(s[:quotedBound]), len(s)-quotedBound)
}

// boundedStderr is an implementation's standard error as a disagreement
// quotes it: trimmed of surrounding white space, and bounded (boundedQuote).
func boundedStderr(stderr string) string {
	return boundedQuote(strings.TrimSpace(stderr))
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
	if err := decodeAnswer(stdout.Bytes(), &decoded); err != nil {
		var twice memberTwice
		if errors.As(err, &twice) {
			// an answer, malformed: the runner's disagreement, not no answer
			return nil, twice
		}
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

// witnessSet renders the witnesses a report names for comparison, as a set
// (SPEC.md §4): order and repetition aside.
func witnessSet(witnesses []map[string]any) []string {
	seen := map[string]bool{}
	for _, w := range witnesses {
		encoded, _ := json.Marshal(w)
		seen[string(encoded)] = true
	}
	out := make([]string, 0, len(seen))
	for w := range seen {
		out = append(out, w)
	}
	sort.Strings(out)
	return out
}

// observationsDisagree is how the observations an implementation reported
// differ from those a vector states, compared as a multiset (SPEC.md §7):
// order aside, and how many counted. A report that leaves the member out
// reports none; one whose member is not an array of objects disagrees.
// Empty when they agree.
func observationsDisagree(stated []map[string]any, produced json.RawMessage) string {
	var reported []map[string]any
	if produced != nil {
		if err := json.Unmarshal(produced, &reported); err != nil {
			return fmt.Sprintf("    expected: %v\n    produced: no array of observations: %s", sortedFindings(stated), produced)
		}
	}
	want, have := sortedFindings(stated), sortedFindings(reported)
	if strings.Join(want, "|") == strings.Join(have, "|") {
		return ""
	}
	return fmt.Sprintf("    expected: %v\n    produced: %v", want, have)
}

// rotationsText renders the rotations a report names for comparison, whole
// (SPEC.md §4): "none" when absent.
func rotationsText(rotations map[string]any) string {
	if rotations == nil {
		return "none"
	}
	encoded, _ := json.Marshal(rotations)
	return string(encoded)
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

	storeFailures, storeCount, err := runStoreVectors(corpusDir, impl)
	if err != nil {
		return nil, counts, err
	}
	failures = append(failures, storeFailures...)
	counts.canon, counts.stores = len(canonFile.Vectors), storeCount

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

// runStoreVectors holds an implementation to every store vector, of both
// directories, and answers the disagreements and how many vectors it read.
func runStoreVectors(corpusDir string, impl implementation) ([]string, int, error) {
	var failures []string
	publicKey, err := corpusPublicKey(corpusDir)
	if err != nil {
		return nil, 0, err
	}
	// Both directories arbitrate: the version 2 vectors and, since the
	// version 3 verifier, the version 3 vectors staged beside them.
	paths, err := storeVectorPaths(corpusDir)
	if err != nil {
		return nil, 0, err
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, 0, err
		}
		// Strictly: a member storeVector does not name, at the top or in
		// expected, is an input no run is given or an answer no runner
		// compares, so it refuses the run rather than being passed over.
		var vector storeVector
		if err := decodeVectorFile(raw, &vector, true); err != nil {
			return nil, 0, fmt.Errorf("%s: %v", path, err)
		}
		observations, compareObservations, err := vector.expectedObservations()
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %v", path, err)
		}
		root, storeRoot, registryPath, decisionRecords, err := materializeVector(vector)
		if err != nil {
			return nil, 0, err
		}
		verdict, err := impl.verify(storeRoot, registryPath, vector.Authority, decisionRecords, vector.OrdinarySealsOnly, publicKey)
		os.RemoveAll(root)
		var refused noVerdict
		if err != nil && vector.OrdinarySealsOnly && errors.As(err, &refused) {
			// A verifier written before the option refuses one it does not
			// know: that is its answer to this vector, a disagreement, and
			// the run goes on (SPEC.md §7). No verdict for a vector run
			// without the option still stops it.
			failures = append(failures, fmt.Sprintf("store %s: no verdict under --ordinary-seals-only: %s",
				vector.Name, boundedStderr(refused.stderr)))
			continue
		}
		var twice memberTwice
		if errors.As(err, &twice) {
			// A verdict, from a verifier that ran, that is no conforming
			// answer: which of the two a reader keeps is no reading of it,
			// so it disagrees with this vector, and the run goes on
			// (SPEC.md §7).
			failures = append(failures, fmt.Sprintf("store %s: the verdict gives a member twice in one object: %s",
				vector.Name, boundedQuote(twice.name)))
			continue
		}
		if err != nil {
			return nil, 0, err
		}
		if want, have := witnessSet(vector.Expected.Witnesses), witnessSet(verdict.Witnesses); strings.Join(want, "|") != strings.Join(have, "|") {
			failures = append(failures, fmt.Sprintf(
				"store %s: witnesses disagree\n    expected: %v\n    produced: %v",
				vector.Name, want, have))
		}
		if want, have := rotationsText(vector.Expected.Rotations), rotationsText(verdict.Rotations); want != have {
			failures = append(failures, fmt.Sprintf(
				"store %s: rotations disagree\n    expected: %s\n    produced: %s",
				vector.Name, want, have))
		}
		// Only where the vector states them (SPEC.md §7): a vector without
		// the member reads nothing of what the implementation observed.
		if compareObservations {
			if disagreement := observationsDisagree(observations, verdict.Observations); disagreement != "" {
				failures = append(failures, fmt.Sprintf("store %s: observations disagree\n%s", vector.Name, disagreement))
			}
		}
		if verdict.OK != vector.Expected.OK {
			failures = append(failures, fmt.Sprintf("store %s: expected ok=%v, got ok=%v",
				vector.Name, vector.Expected.OK, verdict.OK))
		}
		want, have := sortedFindings(vector.Expected.Findings), sortedFindings(verdict.Findings)
		if strings.Join(want, "|") != strings.Join(have, "|") {
			failures = append(failures, fmt.Sprintf(
				"store %s: findings disagree\n    expected: %v\n    produced: %v",
				vector.Name, want, have))
		}
	}
	return failures, len(paths), nil
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
