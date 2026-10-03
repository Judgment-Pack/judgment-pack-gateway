package main

// Receipt version 3 (SPEC.md §1.2a, §4 steps 5 to 8): the structural checks
// order 1 applies to a version 3 receipt, and the candidates a decision-record
// directory yields for the decision-record check. The citation and
// decision-record findings themselves are produced in verifyWithRegistry,
// after every session has been verified, because a citation may name any
// session in the store.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	receiptContext3 = "judgment-pack-gateway/receipt/3:"
	receiptVersion3 = "3"
)

// citation is one entry of an action receipt's cites, as read from the receipt.
type citation struct {
	sessionID string
	callIndex int64
	signature string
}

// isDigest is SPEC.md §1.2a's digest form: "sha256:" and exactly 64 lowercase
// hex characters.
func isDigest(s string) bool {
	h, ok := strings.CutPrefix(s, "sha256:")
	return ok && isLowerHexOfLen(h, 64)
}

// isSignature3 is SPEC.md §1.2a's signature form: exactly 128 lowercase hex
// characters, the 64 bytes of an Ed25519 signature.
func isSignature3(s string) bool { return isLowerHexOfLen(s, 128) }

// validateVersion3 checks every structural constraint §1.2a states on a parsed
// version 3 receipt whose common members receiptFrom has already read, and
// fills in the version 3 members of r. Any failure is an order-1 refusal:
// receiptFrom's caller reports malformed and nothing else is looked at.
func validateVersion3(obj *vObject, r *receipt) error {
	if !isSignature3(r.signature) {
		return errors.New("version 3 signature is not 128 lowercase hex characters")
	}
	// The common members version 3 inherits from §1.2 keep their stated forms
	// and are held to them here, where version 2 left them to later stages: a
	// session id is a flat token (§3a) and a key id is 32 lowercase hex.
	if err := requireSession(r.sessionID); err != nil {
		return errors.New("version 3 sessionId is not a flat token")
	}
	if !isLowerHexOfLen(r.keyID, 32) {
		return errors.New("version 3 keyId is not 32 lowercase hex characters")
	}
	if _, present := obj.get("argumentsDigest"); present {
		return errors.New("argumentsDigest does not exist in version 3")
	}
	if err := requireDigest(obj, "argumentsCommitment"); err != nil {
		return err
	}
	callerV, ok := obj.get("caller")
	if !ok {
		return errors.New(`missing member "caller"`)
	}
	if _, isNull := callerV.(vNull); !isNull {
		if err := validateIdentity(callerV, "caller"); err != nil {
			return err
		}
	}
	kind, ok := memberString(obj, "kind")
	if !ok {
		return errors.New(`missing member "kind"`)
	}
	acquisitionV, hasAcquisition := obj.get("acquisition")
	actionV, hasAction := obj.get("action")
	switch kind {
	case "acquisition":
		if !hasAcquisition || hasAction {
			return errors.New(`kind "acquisition" requires "acquisition" and forbids "action"`)
		}
		if err := validateAcquisition(acquisitionV); err != nil {
			return err
		}
	case "action":
		if !hasAction || hasAcquisition {
			return errors.New(`kind "action" requires "action" and forbids "acquisition"`)
		}
		if err := validateAction(actionV, r); err != nil {
			return err
		}
	default:
		return fmt.Errorf("kind %q is neither acquisition nor action", kind)
	}
	r.kind = kind
	return nil
}

func requireObject(v value, name string) (*vObject, error) {
	obj, ok := v.(*vObject)
	if !ok {
		return nil, fmt.Errorf("member %q is not an object", name)
	}
	return obj, nil
}

func requireString(obj *vObject, name string) (string, error) {
	s, ok := memberString(obj, name)
	if !ok {
		return "", fmt.Errorf("member %q is missing or not a string", name)
	}
	return s, nil
}

func requireDigest(obj *vObject, name string) error {
	s, err := requireString(obj, name)
	if err != nil {
		return err
	}
	if !isDigest(s) {
		return fmt.Errorf("member %q is not a digest", name)
	}
	return nil
}

// nullableString accepts null or a string, and refuses anything else --
// including absence, which §1.2a forbids for a nullable member.
func nullableString(obj *vObject, name string, form func(string) bool) error {
	v, ok := obj.get(name)
	if !ok {
		return fmt.Errorf("missing member %q", name)
	}
	switch s := v.(type) {
	case vNull:
		return nil
	case vString:
		if form != nil && !form(string(s)) {
			return fmt.Errorf("member %q is not of its stated form", name)
		}
		return nil
	}
	return fmt.Errorf("member %q is neither null nor a string", name)
}

func validateIdentity(v value, name string) error {
	obj, err := requireObject(v, name)
	if err != nil {
		return err
	}
	for _, member := range []string{"issuer", "subject"} {
		if _, err := requireString(obj, member); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if err := requireDigest(obj, "tokenDigest"); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func validateAdapter(v value, name string) error {
	obj, err := requireObject(v, name)
	if err != nil {
		return err
	}
	for _, member := range []string{"name", "version"} {
		if _, err := requireString(obj, member); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if err := requireDigest(obj, "digest"); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

var acquisitionShapes = map[string]bool{"airbyte": true, "mcp": true, "http": true, "command": true}

func validateAcquisition(v value) error {
	obj, err := requireObject(v, "acquisition")
	if err != nil {
		return err
	}
	adapter, ok := obj.get("adapter")
	if !ok {
		return errors.New(`acquisition: missing member "adapter"`)
	}
	if err := validateAdapter(adapter, "acquisition.adapter"); err != nil {
		return err
	}
	shape, err := requireString(obj, "shape")
	if err != nil {
		return fmt.Errorf("acquisition: %w", err)
	}
	if !acquisitionShapes[shape] {
		return fmt.Errorf("acquisition: shape %q is outside its enumeration", shape)
	}
	if err := nullableString(obj, "endpoint", nil); err != nil {
		return fmt.Errorf("acquisition: %w", err)
	}
	if err := nullableString(obj, "statement", isDigest); err != nil {
		return fmt.Errorf("acquisition: %w", err)
	}
	if err := nullableString(obj, "snapshot", nil); err != nil {
		return fmt.Errorf("acquisition: %w", err)
	}
	if err := nullableString(obj, "peerIdentity", nil); err != nil {
		return fmt.Errorf("acquisition: %w", err)
	}
	if err := nullableString(obj, "schema", isDigest); err != nil {
		return fmt.Errorf("acquisition: %w", err)
	}
	if err := nullableString(obj, "upstreamToken", nil); err != nil {
		return fmt.Errorf("acquisition: %w", err)
	}
	if items, present := obj.get("pageItems"); present {
		arr, ok := items.(vArray)
		if !ok {
			return errors.New("acquisition: pageItems is not an array")
		}
		for _, item := range arr {
			s, ok := item.(vString)
			if !ok || !isDigest(string(s)) {
				return errors.New("acquisition: a pageItems element is not a digest")
			}
		}
	}
	if _, err := requireString(obj, "observedAt"); err != nil {
		return fmt.Errorf("acquisition: %w", err)
	}
	return nil
}

// validateAction holds an action object to §1.2a and fills in what the
// later steps compare: the citations, and the decision's two digests.
func validateAction(v value, r *receipt) error {
	obj, err := requireObject(v, "action")
	if err != nil {
		return err
	}
	requester, ok := obj.get("requester")
	if !ok {
		return errors.New(`action: missing member "requester"`)
	}
	if _, isNull := requester.(vNull); isNull {
		return errors.New("action: requester is null")
	}
	if err := validateIdentity(requester, "action.requester"); err != nil {
		return err
	}
	decisionV, ok := obj.get("decision")
	if !ok {
		return errors.New(`action: missing member "decision"`)
	}
	decision, err := requireObject(decisionV, "action.decision")
	if err != nil {
		return err
	}
	for _, member := range []string{"recordDigest", "packDigest"} {
		if err := requireDigest(decision, member); err != nil {
			return fmt.Errorf("action.decision: %w", err)
		}
	}
	// How the record was found (ADR-0012): optional, and "exact" when
	// present, the one reading a receipt names.
	if recordBytes, present := decision.get("recordBytes"); present {
		if s, ok := recordBytes.(vString); !ok || s != "exact" {
			return errors.New(`action.decision: recordBytes, when present, is "exact"`)
		}
		r.exactRecord = true
	}
	citesV, ok := obj.get("cites")
	if !ok {
		return errors.New(`action: missing member "cites"`)
	}
	cites, err := parseCitations(citesV, "action")
	if err != nil {
		return err
	}
	toolV, ok := obj.get("tool")
	if !ok {
		return errors.New(`action: missing member "tool"`)
	}
	tool, err := requireObject(toolV, "action.tool")
	if err != nil {
		return err
	}
	for _, member := range []string{"shape", "name"} {
		if _, err := requireString(tool, member); err != nil {
			return fmt.Errorf("action.tool: %w", err)
		}
	}
	if err := nullableString(tool, "endpoint", nil); err != nil {
		return fmt.Errorf("action.tool: %w", err)
	}
	if err := requireDigest(obj, "request"); err != nil {
		return fmt.Errorf("action: %w", err)
	}
	// The policy the write was held to (ADR-0011) is optional; present, it
	// is a digest, and nothing else about it is checked: a verifier holds
	// no configuration to recompute it against.
	if _, present := obj.get("policy"); present {
		if err := requireDigest(obj, "policy"); err != nil {
			return fmt.Errorf("action: %w", err)
		}
	}
	adapter, ok := obj.get("adapter")
	if !ok {
		return errors.New(`action: missing member "adapter"`)
	}
	if err := validateAdapter(adapter, "action.adapter"); err != nil {
		return err
	}
	if _, err := requireString(obj, "observedAt"); err != nil {
		return fmt.Errorf("action: %w", err)
	}
	r.cites = cites
	r.recordDigest, _ = memberString(decision, "recordDigest")
	r.packDigest, _ = memberString(decision, "packDigest")
	return nil
}

// decisionCandidates walks the decision-record directory of SPEC.md §4 step 6
// and reports which of the wanted digests some candidate hashes to, and
// whether the directory was present at all. An empty dir means the verifier
// was given none, which is absent. Absent and present-but-unreadable are told
// apart exactly as they are for the registry (§4.1): absent fails closed
// later, unreadable is no verdict here -- and the directory is judged whether
// or not any action receipt needs it, since an unreadable input is no verdict
// regardless. Only the wanted digests are retained, so a large archive costs
// its bytes once and its digests never; a candidate that cites (step 7) is
// handed to onRecord as it is found and retained no more than the rest.
func decisionCandidates(dir string, wanted map[string]bool, onRecord func(citingRecord)) (map[string]bool, bool, error) {
	return decisionCandidatesReading(dir, wanted, onRecord, nil)
}

// decisionCandidatesReading is decisionCandidates that also hands onWanted
// the bytes of a candidate found for each wanted digest, once, with the
// digest's hex -- the record an action names, for the executor's policy
// (ADR-0011) and for §4 step 8. A record is a regular file whole or a line
// of a .jsonl file, never a .jsonl file whole, which is a candidate for
// step 6 and is handed to nobody, as step 7 reads it for nothing. The bytes
// handed over are the bytes that hashed to the digest; a line is a slice of
// the file's buffer, for onWanted to copy if it keeps it.
func decisionCandidatesReading(dir string, wanted map[string]bool, onRecord func(citingRecord), onWanted func(digestHex string, data []byte)) (map[string]bool, bool, error) {
	hooks := decisionWalk{onRecord: onRecord}
	if onWanted != nil {
		hooks.onWanted = func(h string, exact bool, data []byte) {
			if !exact {
				onWanted(h, data)
			}
		}
	}
	found, _, present, err := walkDecisionRecords(dir, wanted, hooks)
	return found, present, err
}

// decisionWalk is what a walk of the decision-record directory looks for
// and hands on as it goes, each optional.
//
// Two readings of a .jsonl file's lines are looked for. Under §4 step 6's,
// each line has one trailing 0x0D removed; the digests wanted that way are
// walkDecisionRecords' wanted. Under the exact reading, a line is all its
// bytes before the 0x0A, a 0x0D among them -- the bytes the runtime wrote
// and signed, for an action receipt whose decision.recordBytes is "exact"
// and for /act under a policy that requires a signed record; the digests
// wanted that way are exact. Any other candidate, a regular file whole, is
// the same under both.
//
// It hands on: a candidate that cites, under step 6's reading (onRecord);
// the bytes of a wanted record, once per reading (onWanted); the path of
// every file a wanted record is found in as a record -- a line of it, or the
// file whole when it is no .jsonl file -- each time it is found (onWantedIn);
// and the path and bytes of every regular file the walk reads (onFile),
// which is how a record's sidecar is found the way the record is.
type decisionWalk struct {
	onRecord   func(citingRecord)
	exact      map[string]bool
	onWanted   func(digestHex string, exact bool, data []byte)
	onWantedIn func(digestHex string, exact bool, path string)
	onFile     func(path string, data []byte)
}

// walkDecisionRecords walks the decision-record directory (SPEC.md §4 step
// 6) and reports which wanted digests some candidate hashes to under step
// 6's reading (found), which exact digests some candidate hashes to under
// the exact reading (foundExact), and whether the directory was there at
// all. The walk holds its root first, as the directory it was named by, and
// enumerates and reads everything beneath it through that held root and the
// directories it holds below it (heldTree), never by a path a link could be
// put in since.
func walkDecisionRecords(dir string, wanted map[string]bool, hooks decisionWalk) (map[string]bool, map[string]bool, bool, error) {
	onRecord, onWanted := hooks.onRecord, hooks.onWanted
	if dir == "" {
		return nil, nil, false, nil
	}
	if err := requirePlainSpelling(dir, false); err != nil {
		return nil, nil, false, fmt.Errorf("decision-record directory: %w", err)
	}
	if there, err := registryContainerReachable(dir); err != nil {
		return nil, nil, false, fmt.Errorf("decision-record directory: %w", err)
	} else if !there {
		return nil, nil, false, nil
	}
	// a link that leads nowhere is there and cannot be read, at the
	// directory as above it (§4.1), never the absence it would be taken for
	info, err := statInput(dir, "the decision-record directory is a link that leads nowhere")
	if err != nil {
		return nil, nil, false, err
	}
	if info == nil {
		return nil, nil, false, nil
	}
	if !info.IsDir() {
		return nil, nil, false, fmt.Errorf("decision-record path is not a directory: %s", dir)
	}
	found, foundExact := map[string]bool{}, map[string]bool{}
	handed, handedExact := map[string]bool{}, map[string]bool{}
	// note hashes a candidate for step 6 under one reading; a record --
	// which a .jsonl file's lines are and the file whole is not, so that a
	// record is judged once and not also as the file it is the only line of
	// -- is handed on as well.
	note := func(path string, data []byte, record, exact bool) {
		want, got, gave := wanted, found, handed
		if exact {
			want, got, gave = hooks.exact, foundExact, handedExact
		}
		if len(want) == 0 {
			return
		}
		sum := sha256.Sum256(data)
		if h := hex.EncodeToString(sum[:]); want[h] {
			got[h] = true
			if record && hooks.onWantedIn != nil {
				hooks.onWantedIn(h, exact, path)
			}
			if record && onWanted != nil && !gave[h] {
				gave[h] = true
				onWanted(h, exact, data)
			}
		}
	}
	// read reads a record under step 6's reading for step 7.
	read := func(path string, data []byte) {
		note(path, data, true, false)
		if onRecord == nil {
			return
		}
		if cites, cited, malformed := recordCitations(data); cited {
			sum := sha256.Sum256(data)
			onRecord(citingRecord{digest: "sha256:" + hex.EncodeToString(sum[:]), cites: cites, malformed: malformed})
		}
	}
	tree, err := holdRoot(dir)
	if err != nil {
		return nil, nil, false, err
	}
	if tree == nil {
		// The directory is named by a link, which is never followed: it is
		// there, and nothing under it is a candidate.
		return found, foundExact, true, nil
	}
	defer tree.close()
	err = tree.walk(func(path, name string, data []byte) error {
		if hooks.onFile != nil {
			hooks.onFile(path, data)
		}
		if !strings.HasSuffix(name, ".jsonl") {
			read(path, data)
			note(path, data, true, true)
			return nil
		}
		note(path, data, false, false)
		note(path, data, false, true)
		// One candidate per line: split on 0x0A, one trailing 0x0D removed
		// under step 6's reading and none under the exact one, empty pieces
		// skipped, the unterminated final piece kept. Walked by index so a
		// file of newlines allocates nothing per line.
		rest := data
		for len(rest) > 0 {
			line := rest
			if i := bytes.IndexByte(rest, '\n'); i >= 0 {
				line, rest = rest[:i], rest[i+1:]
			} else {
				rest = nil
			}
			if len(line) > 0 {
				note(path, line, true, true)
			}
			if line = bytes.TrimSuffix(line, []byte{'\r'}); len(line) > 0 {
				read(path, line)
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, false, err
	}
	return found, foundExact, true, nil
}

// parseCitations holds a cites member to the shape §1.2a gives action.cites
// -- an array of objects each with a sessionId that is a flat token, a
// callIndex that is a non-negative integer, and a signature of 128
// lowercase hex characters -- and returns the citations. The same shape
// is what a decision record cites in (§4 step 7), read by the same code.
func parseCitations(citesV value, what string) ([]citation, error) {
	citesArr, ok := citesV.(vArray)
	if !ok {
		return nil, fmt.Errorf("%s: cites is not an array", what)
	}
	cites := make([]citation, 0, len(citesArr))
	for _, entry := range citesArr {
		c, err := requireObject(entry, what+".cites[]")
		if err != nil {
			return nil, err
		}
		sessionID, err := requireString(c, "sessionId")
		if err != nil {
			return nil, fmt.Errorf("%s.cites[]: %w", what, err)
		}
		if err := requireSession(sessionID); err != nil {
			return nil, fmt.Errorf("%s.cites[]: sessionId is not a flat token", what)
		}
		indexV, ok := c.get("callIndex")
		if !ok {
			return nil, fmt.Errorf(`%s.cites[]: missing member "callIndex"`, what)
		}
		index, ok := indexV.(vInt)
		if !ok || index < 0 {
			return nil, fmt.Errorf("%s.cites[]: callIndex is not a non-negative integer", what)
		}
		signature, err := requireString(c, "signature")
		if err != nil {
			return nil, fmt.Errorf("%s.cites[]: %w", what, err)
		}
		if !isSignature3(signature) {
			return nil, fmt.Errorf("%s.cites[]: signature is not 128 lowercase hex characters", what)
		}
		cites = append(cites, citation{sessionID: sessionID, callIndex: int64(index), signature: signature})
	}
	return cites, nil
}

// citingRecord is a decision-record candidate that carries a cites member
// (SPEC.md §4 step 7): the digest of the candidate's bytes, and its
// citations as read -- or malformed, when the member is not of the stated
// shape or is given twice.
type citingRecord struct {
	digest    string
	cites     []citation
	malformed bool
}

// recordCitations reads a candidate for its cites member and for nothing
// else. One JSON object carrying a top-level cites member is a decision
// record that cites; anything that is not one JSON object, or carries no
// cites, is not interpreted. The object is walked by a scanner over the
// bytes as they lie -- a record's facts may be large and may carry what
// its writer chose, floats included, which the canonical parser refuses --
// and nothing but the member names is ever decoded: a value is passed
// over by its extent, a string's bytes validated and never copied, the
// nesting bounded as the canonical parser bounds it. The cites member is
// then read by the canonical parser and held to the shape an action
// receipt's citations take, so a member twice, a member by another case,
// or a number that is not an integer literal is malformed, not read
// leniently.
func recordCitations(data []byte) (cites []citation, cited bool, malformed bool) {
	pos := skipSpace(data, 0)
	if pos >= len(data) || data[pos] != '{' {
		return nil, false, false
	}
	pos++
	var raw []byte
	seen, twice := false, false
	for {
		pos = skipSpace(data, pos)
		if pos >= len(data) {
			return nil, false, false
		}
		if data[pos] == '}' {
			pos++
			break
		}
		keyEnd, ok := scanString(data, pos)
		if !ok {
			return nil, false, false
		}
		var key string
		if json.Unmarshal(data[pos:keyEnd], &key) != nil {
			return nil, false, false
		}
		pos = skipSpace(data, keyEnd)
		if pos >= len(data) || data[pos] != ':' {
			return nil, false, false
		}
		valueStart := skipSpace(data, pos+1)
		valueEnd, ok := scanValue(data, valueStart, 1)
		if !ok {
			return nil, false, false
		}
		if key == "cites" {
			if seen {
				twice = true
			}
			seen = true
			raw = data[valueStart:valueEnd]
		}
		pos = skipSpace(data, valueEnd)
		if pos >= len(data) {
			return nil, false, false
		}
		switch data[pos] {
		case ',':
			pos++
			// A comma must be followed by a member, not the closing brace.
			if next := skipSpace(data, pos); next < len(data) && data[next] == '}' {
				return nil, false, false
			}
		case '}':
		default:
			return nil, false, false
		}
	}
	if skipSpace(data, pos) != len(data) {
		return nil, false, false
	}
	if !seen {
		return nil, false, false
	}
	if twice {
		return nil, true, true
	}
	v, err := parseJSON(raw)
	if err != nil {
		return nil, true, true
	}
	cites, err = parseCitations(v, "record")
	if err != nil {
		return nil, true, true
	}
	return cites, true, false
}

// skipSpace is the position of the first byte at or after pos that is not
// JSON whitespace.
func skipSpace(data []byte, pos int) int {
	for pos < len(data) && (data[pos] == ' ' || data[pos] == '\t' || data[pos] == '\r' || data[pos] == '\n') {
		pos++
	}
	return pos
}

// scanString is the position just past the JSON string starting at pos,
// its escapes well formed, no raw control character in it and its bytes
// valid UTF-8; nothing is copied.
func scanString(data []byte, pos int) (int, bool) {
	if pos >= len(data) || data[pos] != '"' {
		return 0, false
	}
	start := pos + 1
	pos++
	for pos < len(data) {
		c := data[pos]
		switch {
		case c == '"':
			return pos + 1, utf8.Valid(data[start:pos])
		case c == '\\':
			if pos+1 >= len(data) {
				return 0, false
			}
			switch data[pos+1] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				pos += 2
			case 'u':
				if pos+5 >= len(data) || !isHex4(data[pos+2:pos+6]) {
					return 0, false
				}
				pos += 6
			default:
				return 0, false
			}
		case c < 0x20:
			return 0, false
		default:
			pos++
		}
	}
	return 0, false
}

func isHex4(b []byte) bool {
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// scanValue is the position just past the JSON value starting at pos --
// a string, a number, a literal, an object or an array -- with the
// nesting from depth bounded as the canonical parser bounds it
// (maxNesting); false when it is not one, or nests deeper.
func scanValue(data []byte, pos int, depth int) (int, bool) {
	if pos >= len(data) {
		return 0, false
	}
	switch c := data[pos]; {
	case c == '"':
		return scanString(data, pos)
	case c == '{' || c == '[':
		if depth >= maxNesting {
			return 0, false
		}
		closing := byte('}')
		if c == '[' {
			closing = ']'
		}
		pos = skipSpace(data, pos+1)
		if pos < len(data) && data[pos] == closing {
			return pos + 1, true
		}
		for {
			if c == '{' {
				keyEnd, ok := scanString(data, pos)
				if !ok {
					return 0, false
				}
				pos = skipSpace(data, keyEnd)
				if pos >= len(data) || data[pos] != ':' {
					return 0, false
				}
				pos = skipSpace(data, pos+1)
			}
			end, ok := scanValue(data, pos, depth+1)
			if !ok {
				return 0, false
			}
			pos = skipSpace(data, end)
			if pos >= len(data) {
				return 0, false
			}
			if data[pos] == closing {
				return pos + 1, true
			}
			if data[pos] != ',' {
				return 0, false
			}
			pos = skipSpace(data, pos+1)
		}
	case c == 't':
		return literal(data, pos, "true")
	case c == 'f':
		return literal(data, pos, "false")
	case c == 'n':
		return literal(data, pos, "null")
	case c == '-' || (c >= '0' && c <= '9'):
		return scanNumber(data, pos)
	}
	return 0, false
}

func literal(data []byte, pos int, word string) (int, bool) {
	if len(data)-pos < len(word) || string(data[pos:pos+len(word)]) != word {
		return 0, false
	}
	return pos + len(word), true
}

// scanNumber is the position just past a JSON number (RFC 8259 §6) at pos.
func scanNumber(data []byte, pos int) (int, bool) {
	digits := func(p int) int {
		for p < len(data) && data[p] >= '0' && data[p] <= '9' {
			p++
		}
		return p
	}
	if pos < len(data) && data[pos] == '-' {
		pos++
	}
	if pos >= len(data) {
		return 0, false
	}
	if data[pos] == '0' {
		pos++
	} else if data[pos] >= '1' && data[pos] <= '9' {
		pos = digits(pos)
	} else {
		return 0, false
	}
	if pos < len(data) && data[pos] == '.' {
		next := digits(pos + 1)
		if next == pos+1 {
			return 0, false
		}
		pos = next
	}
	if pos < len(data) && (data[pos] == 'e' || data[pos] == 'E') {
		pos++
		if pos < len(data) && (data[pos] == '+' || data[pos] == '-') {
			pos++
		}
		next := digits(pos)
		if next == pos {
			return 0, false
		}
		pos = next
	}
	return pos, true
}
