package main

// The checkpoint witness's statement, and the reading of a chain of them
// (SPEC.md §8; docs/adr/0013-checkpoint-witness.md). A witness is a gateway,
// run by a party other than a decision trail's operator, that signs the
// runtime's audit checkpoints and chains its statements per trail. This file
// holds what a reader of those statements does: the statement's form, the
// key rule and the one equation, and the chain rule, within the bounds of
// one reading. Nothing here signs a statement or serves one: the witness
// service follows in a later release, and until then `gateway conform` is
// the only caller, reading corpus/witness/.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

const (
	// witnessPrefix is the domain of what a witness statement signs (§8.3):
	// neither a receipt's nor a seal's, so none of the three is replayed as
	// another.
	witnessPrefix = "judgment-pack-gateway/witness/1:"

	// The bounds of one reading (§8.7).
	maxWitnessKeys       = 16
	maxWitnessBytes      = 64 << 20
	maxWitnessStatements = 110000

	// maxWitnessInteger is the largest index or sequence a statement holds,
	// 2^53-2.
	maxWitnessInteger = maxSafeInteger - 1

	// witnessValueBudget bounds the values one statement line may hold
	// before it is parsed past them. A statement holds thirteen; a line
	// holding more is malformed whatever else it holds, so the budget
	// changes no verdict and keeps a 64 MiB line from becoming a large
	// value.
	witnessValueBudget = 64
)

// The refusals of a reading, made before any statement is read (§8.6, §8.7).
const (
	refusalKeysOverBound       = "keys-over-bound"
	refusalKeyNotCanonical     = "key-not-canonical"
	refusalKeySmallOrder       = "key-small-order"
	refusalKeyNotOnCurve       = "key-not-on-curve"
	refusalBytesOverBound      = "bytes-over-bound"
	refusalStatementsOverBound = "statements-over-bound"
)

// The findings of a reading (§8.6).
const (
	findingWitnessMalformed        = "witness-malformed"
	findingWitnessSignatureInvalid = "witness-signature-invalid"
	findingWitnessTrailMismatch    = "witness-trail-mismatch"
	findingWitnessEquivocation     = "witness-equivocation"
	findingWitnessChainBroken      = "witness-chain-broken"
	findingWitnessHeadUnreached    = "witness-head-unreached"
)

var (
	statementMembers = map[string]bool{
		"witnessVersion": true, "kind": true, "checkpoint": true, "index": true,
		"prevSignature": true, "witnessedAt": true, "keyId": true, "signature": true,
	}
	checkpointMembers = map[string]bool{
		"checkpointVersion": true, "trail": true, "sequence": true, "recordDigest": true,
	}
	statementKinds  = map[string]bool{"checkpoint": true, "conflict": true, "retirement": true}
	witnessTimeForm = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

// witnessKeyRefusal is why a reader may not trust 32 bytes as a witness key,
// as a refusal of the reading, or "" (§8.4).
func witnessKeyRefusal(raw []byte) string {
	switch publicKeyFault(raw) {
	case keySound:
		return ""
	case keySmallOrder:
		return refusalKeySmallOrder
	case keyNotOnCurve, keyWrongLength:
		return refusalKeyNotOnCurve
	default:
		return refusalKeyNotCanonical
	}
}

// witnessStatement is one statement that holds its form (§8.2).
type witnessStatement struct {
	kind  string
	trail string
	// sequence is the checkpoint's; checkpoint, its canonical bytes, which
	// is the checkpoint line without its newline.
	sequence    int64
	checkpoint  string
	index       int64
	prev        string // "" for null
	witnessedAt string
	keyID       string
	signature   string
	// whole is the statement's canonical bytes, by which two copies are one;
	// signed, what its signature covers (§8.3).
	whole  string
	signed []byte
}

// parseWitnessStatement reads one statement line by its JSON value and holds
// it to the form of §8.2, or reports that it is malformed.
func parseWitnessStatement(line []byte) (*witnessStatement, bool) {
	v, err := parseStatementJSON(line, witnessValueBudget)
	if err != nil {
		return nil, false
	}
	obj, ok := v.(*vObject)
	if !ok || exactlyMembers(obj, statementMembers, "statement") != nil {
		return nil, false
	}
	st := &witnessStatement{}
	version, _ := memberString(obj, "witnessVersion")
	st.kind, _ = memberString(obj, "kind")
	st.witnessedAt, _ = memberString(obj, "witnessedAt")
	st.keyID, _ = memberString(obj, "keyId")
	st.signature, _ = memberString(obj, "signature")
	if version != "1" || !statementKinds[st.kind] || !witnessTimeForm.MatchString(st.witnessedAt) ||
		!isLowerHexOfLen(st.keyID, 32) || !isLowerHexOfLen(st.signature, 128) {
		return nil, false
	}
	index, ok := witnessInteger(obj, "index", 0)
	if !ok {
		return nil, false
	}
	st.index = index
	switch prev, _ := obj.get("prevSignature"); p := prev.(type) {
	case vNull:
	case vString:
		if !isLowerHexOfLen(string(p), 128) {
			return nil, false
		}
		st.prev = string(p)
	default:
		return nil, false
	}
	cpV, _ := obj.get("checkpoint")
	cp, ok := cpV.(*vObject)
	if !ok || exactlyMembers(cp, checkpointMembers, "checkpoint") != nil {
		return nil, false
	}
	cpVersion, _ := memberString(cp, "checkpointVersion")
	st.trail, _ = memberString(cp, "trail")
	record, _ := memberString(cp, "recordDigest")
	sequence, ok := witnessInteger(cp, "sequence", 1)
	if cpVersion != "1" || !isLowerHexOfLen(st.trail, 32) || !isDigest(record) || !ok {
		return nil, false
	}
	st.sequence = sequence
	st.checkpoint = string(canon(cp))
	st.whole = string(canon(obj))
	unsigned := newObject()
	for _, name := range obj.names {
		if name != "signature" {
			member, _ := obj.get(name)
			unsigned.set(name, member)
		}
	}
	st.signed = append([]byte(witnessPrefix), canon(unsigned)...)
	return st, true
}

// witnessInteger is an integer member from least to 2^53-2. The statement
// parser has already refused a sign, a fraction and an exponent.
func witnessInteger(obj *vObject, name string, least int64) (int64, bool) {
	v, _ := obj.get(name)
	n, ok := v.(vInt)
	if !ok || int64(n) < least || int64(n) > maxWitnessInteger {
		return 0, false
	}
	return int64(n), true
}

// witnessSignatureValid is the equation of §8.4, under a key that has passed
// the key rule: S below L, and the canonical encoding of [S]B - [h]A equal to
// R byte for byte. crypto/ed25519 verifies exactly so; the key rule, applied
// before, is what keeps its lenient decoding of a key from mattering.
func witnessSignatureValid(key ed25519.PublicKey, st *witnessStatement) bool {
	signature, err := hex.DecodeString(st.signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(key, st.signed, signature)
}

// witnessReading is what one reading takes: the trail being verified, the
// keys the reader trusts, in the order given, the statements files' bytes,
// and the head file's, or nil for no head.
type witnessReading struct {
	trail string
	keys  [][]byte
	files [][]byte
	head  []byte
}

// witnessLatest is the latest witnessed checkpoint of a chain read.
type witnessLatest struct {
	Index       int64  `json:"index"`
	Sequence    int64  `json:"sequence"`
	WitnessedAt string `json:"witnessedAt"`
}

// witnessVerdict is a reading's answer: a refusal, or findings, or, with
// none, what the chain read says.
type witnessVerdict struct {
	refused  string
	findings []string
	reading  string // "current" or "historical"
	head     *int64
	highest  int64
	latest   witnessLatest
	conflict []int64
	retired  bool
}

// marshal is the verdict as `gateway conform` and the process contract give
// it (corpus/README.md): {"refused"}; {"ok": false, "findings"}; or, for a
// reading with no finding, what the chain read says.
func (v witnessVerdict) marshal() ([]byte, error) {
	if v.refused != "" {
		return json.Marshal(map[string]any{"refused": v.refused})
	}
	if len(v.findings) > 0 {
		return json.Marshal(map[string]any{"ok": false, "findings": v.findings})
	}
	conflicts := v.conflict
	if conflicts == nil {
		conflicts = []int64{}
	}
	return json.Marshal(map[string]any{
		"ok": true, "findings": []string{}, "reading": v.reading, "headIndex": v.head,
		"highestIndex": v.highest, "latestCheckpoint": v.latest, "conflicts": conflicts, "retired": v.retired,
	})
}

// statementLines is a file's statement lines: its lines, ended by 0x0A, the
// piece after the last one included, less those that are empty or hold only
// spaces, tabs and carriage returns.
func statementLines(file []byte) [][]byte {
	var lines [][]byte
	for len(file) > 0 {
		line := file
		if i := bytes.IndexByte(file, '\n'); i >= 0 {
			line, file = file[:i], file[i+1:]
		} else {
			file = nil
		}
		if len(bytes.Trim(line, " \t\r")) > 0 {
			lines = append(lines, line)
		}
	}
	return lines
}

// readWitness reads one chain (§8.6) within the bounds of §8.7.
func readWitness(in witnessReading) witnessVerdict {
	if len(in.keys) > maxWitnessKeys {
		return witnessVerdict{refused: refusalKeysOverBound}
	}
	keys := map[string]ed25519.PublicKey{}
	for _, key := range in.keys {
		if refusal := witnessKeyRefusal(key); refusal != "" {
			return witnessVerdict{refused: refusal}
		}
		keys[keyIDFor(key)] = ed25519.PublicKey(key)
	}
	total := len(in.head)
	for _, file := range in.files {
		total += len(file)
	}
	if total > maxWitnessBytes {
		return witnessVerdict{refused: refusalBytesOverBound}
	}
	var lines [][]byte
	for _, file := range in.files {
		lines = append(lines, statementLines(file)...)
	}
	var headLines [][]byte
	if in.head != nil {
		headLines = statementLines(in.head)
	}
	if len(lines)+len(headLines) > maxWitnessStatements {
		return witnessVerdict{refused: refusalStatementsOverBound}
	}

	findings := map[string]bool{}
	// Step 1: the set, each statement once by its canonical bytes, each held
	// to its form, its signature and its trail, the first failure its one
	// finding.
	seen := map[string]*witnessStatement{}
	// byLine is each line already read, by its bytes: a line given again is
	// the statement it was, or as malformed as it was, without reading it
	// twice.
	byLine := map[string]*witnessStatement{}
	var set []*witnessStatement
	add := func(line []byte) *witnessStatement {
		if st, ok := byLine[string(line)]; ok {
			if st == nil {
				findings[findingWitnessMalformed] = true
			}
			return st
		}
		st := readStatementOnce(line, seen, &set)
		byLine[string(line)] = st
		if st == nil {
			findings[findingWitnessMalformed] = true
		}
		return st
	}
	for _, line := range lines {
		add(line)
	}
	var head *witnessStatement
	if in.head != nil {
		if len(headLines) != 1 {
			findings[findingWitnessMalformed] = true
		} else {
			head = add(headLines[0])
		}
	}
	var passing []*witnessStatement
	for _, st := range set {
		key, ok := keys[st.keyID]
		switch {
		case !ok || !witnessSignatureValid(key, st):
			findings[findingWitnessSignatureInvalid] = true
		case st.trail != in.trail:
			findings[findingWitnessTrailMismatch] = true
		default:
			passing = append(passing, st)
		}
	}
	// Step 2: two that passed, of one index, that differ.
	byIndex := map[int64]bool{}
	for _, st := range passing {
		if byIndex[st.index] {
			findings[findingWitnessEquivocation] = true
		}
		byIndex[st.index] = true
	}
	if len(findings) > 0 {
		return witnessVerdict{findings: sortedKeys(findings)}
	}

	// Step 3: the chain, less a head more than one index past every other
	// statement, walked in index order.
	highestOther := int64(-1)
	for _, st := range passing {
		if st != head && st.index > highestOther {
			highestOther = st.index
		}
	}
	chain := passing
	unreached := head != nil && head.index > highestOther+1
	if unreached {
		chain = nil
		for _, st := range passing {
			if st != head {
				chain = append(chain, st)
			}
		}
	}
	sort.Slice(chain, func(i, j int) bool { return chain[i].index < chain[j].index })
	var latest *witnessStatement
	var conflicts []int64
	broken := len(chain) == 0
	for i, st := range chain {
		if i == 0 {
			broken = broken || st.index != 0 || st.prev != ""
		} else {
			broken = broken || st.index != chain[i-1].index+1 || st.prev != chain[i-1].signature
		}
		switch st.kind {
		case "checkpoint":
			broken = broken || (latest != nil && st.sequence <= latest.sequence)
			latest = st
		case "conflict":
			broken = broken || latest == nil || st.sequence > latest.sequence
			conflicts = append(conflicts, st.sequence)
		case "retirement":
			broken = broken || latest == nil || st.checkpoint != latest.checkpoint || i != len(chain)-1
		}
	}
	if broken {
		findings[findingWitnessChainBroken] = true
	}
	// Step 4: a head set aside is a head the chain supplied does not reach.
	if unreached {
		findings[findingWitnessHeadUnreached] = true
	}
	if len(findings) > 0 {
		return witnessVerdict{findings: sortedKeys(findings)}
	}

	verdict := witnessVerdict{
		reading:  "historical",
		highest:  chain[len(chain)-1].index,
		latest:   witnessLatest{Index: latest.index, Sequence: latest.sequence, WitnessedAt: latest.witnessedAt},
		conflict: conflicts,
		retired:  chain[len(chain)-1].kind == "retirement",
	}
	if head != nil {
		verdict.reading = "current"
		index := head.index
		verdict.head = &index
	}
	return verdict
}

// readStatementOnce reads a line as a statement, or nil for one malformed,
// and adds it to the set unless a statement of the same canonical bytes is
// there, which it then is.
func readStatementOnce(line []byte, seen map[string]*witnessStatement, set *[]*witnessStatement) *witnessStatement {
	st, ok := parseWitnessStatement(line)
	if !ok {
		return nil
	}
	if earlier, ok := seen[st.whole]; ok {
		return earlier
	}
	seen[st.whole] = st
	*set = append(*set, st)
	return st
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// errWitnessInput is an input a reading cannot be made of: a key file not of
// its form, or a file that cannot be read. It is no answer, never a refusal.
var errWitnessInput = errors.New("witness input")

// readWitnessFiles reads a chain from files, as the process contract's
// `witness` command names them (corpus/README.md): a key file is 64
// hexadecimal characters with whitespace around them allowed; the files'
// sizes are held to the byte bound before any of them is read.
func readWitnessFiles(trail string, keyPaths, statementPaths []string, headPath string) (witnessVerdict, error) {
	if len(keyPaths) > maxWitnessKeys {
		return witnessVerdict{refused: refusalKeysOverBound}, nil
	}
	in := witnessReading{trail: trail}
	for _, path := range keyPaths {
		raw, err := readBoundedFile(path, 4096)
		if err != nil {
			return witnessVerdict{}, err
		}
		text := strings.TrimSpace(string(raw))
		key, err := hex.DecodeString(text)
		if err != nil || len(text) != 64 {
			return witnessVerdict{}, fmt.Errorf("%w: %s is not 64 hexadecimal characters", errWitnessInput, path)
		}
		in.keys = append(in.keys, key)
	}
	for _, key := range in.keys {
		if refusal := witnessKeyRefusal(key); refusal != "" {
			return witnessVerdict{refused: refusal}, nil
		}
	}
	paths := append([]string(nil), statementPaths...)
	if headPath != "" {
		paths = append(paths, headPath)
	}
	var total int64
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return witnessVerdict{}, fmt.Errorf("%w: %v", errWitnessInput, err)
		}
		if !info.Mode().IsRegular() {
			return witnessVerdict{}, fmt.Errorf("%w: %s is not a regular file", errWitnessInput, path)
		}
		total += info.Size()
	}
	if total > maxWitnessBytes {
		return witnessVerdict{refused: refusalBytesOverBound}, nil
	}
	read := 0
	for i, path := range paths {
		data, err := readBoundedFile(path, maxWitnessBytes-read)
		if errors.Is(err, errOverBound) {
			// The file grew after it was measured: still over the bound.
			return witnessVerdict{refused: refusalBytesOverBound}, nil
		}
		if err != nil {
			return witnessVerdict{}, err
		}
		read += len(data)
		if headPath != "" && i == len(paths)-1 {
			in.head = data
		} else {
			in.files = append(in.files, data)
		}
	}
	return readWitness(in), nil
}

var errOverBound = errors.New("over the bound")

// readBoundedFile is a file's bytes, or errOverBound past limit bytes.
func readBoundedFile(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errWitnessInput, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errWitnessInput, err)
	}
	if len(data) > limit {
		return nil, errOverBound
	}
	if data == nil {
		data = []byte{}
	}
	return data, nil
}
