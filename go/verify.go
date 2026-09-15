package main

// Registry-anchored verification of a receipt store (SPEC.md §1-§3).
//
// The shape is: run the inline per-receipt verification over every session in
// the store, reconstruct each session's callIndex sequence and prevSignature
// chain from the receipts that passed, then anchor the whole thing against the
// seals in the registry -- which are themselves dropped unless they verify
// under the public key.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// Domain separation. SPEC.md §2: the context prefix is what stops a seal
// signature being replayed as a receipt signature or vice versa.
const (
	receiptContext = "judgment-pack-gateway/receipt/2:"
	sealContext    = "judgment-pack-gateway/seal/2:"
	receiptVersion = "2"
)

type finding map[string]any

type report struct {
	OK       bool      `json:"ok"`
	Findings []finding `json:"findings"`
}

func (r *report) marshal() ([]byte, error) {
	if r.Findings == nil {
		r.Findings = []finding{}
	}
	return json.Marshal(r)
}

// keyIDFor is the identifier a receipt carries so an implementation can tell
// "signed by a key I do not hold" from "signed by my key and tampered with",
// without the receipt ever carrying a key (SPEC.md §4).
func keyIDFor(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])[:32]
}

// --- receipts -------------------------------------------------------------

type receipt struct {
	obj           *vObject
	version       string
	sessionID     string
	callIndex     int64
	keyID         string
	authority     string
	resultDigest  string
	signature     string
	prevSignature string
	hasPrev       bool // false means the member was null: this is a session head
	// Version 3 only (verify_v3.go).
	kind         string
	cites        []citation
	recordDigest string
}

func receiptFrom(obj *vObject) (*receipt, error) {
	r := &receipt{obj: obj}
	str := func(name string) (string, error) {
		v, ok := obj.get(name)
		if !ok {
			return "", fmt.Errorf("missing member %q", name)
		}
		s, ok := v.(vString)
		if !ok {
			return "", fmt.Errorf("member %q is not a string", name)
		}
		return string(s), nil
	}
	var err error
	for _, f := range []struct {
		name string
		dst  *string
	}{
		{"receiptVersion", &r.version},
		{"sessionId", &r.sessionID},
		{"keyId", &r.keyID},
		{"authority", &r.authority},
		{"resultDigest", &r.resultDigest},
		{"signature", &r.signature},
		{"source", new(string)},
		{"servedAt", new(string)},
	} {
		if *f.dst, err = str(f.name); err != nil {
			return nil, err
		}
	}
	// The members the version adds. A version this verifier does not know is
	// left for order 2 to name; the two it knows are held to their own sets.
	switch r.version {
	case receiptVersion:
		if _, err = str("argumentsDigest"); err != nil {
			return nil, err
		}
	case receiptVersion3:
		if err := validateVersion3(obj, r); err != nil {
			return nil, err
		}
	}
	ci, ok := obj.get("callIndex")
	if !ok {
		return nil, errors.New(`missing member "callIndex"`)
	}
	n, ok := ci.(vInt)
	if !ok {
		return nil, errors.New(`member "callIndex" is not an integer`)
	}
	if n < 0 {
		return nil, errors.New(`member "callIndex" is negative`)
	}
	r.callIndex = int64(n)

	prev, ok := obj.get("prevSignature")
	if !ok {
		return nil, errors.New(`missing member "prevSignature"`)
	}
	switch p := prev.(type) {
	case vNull:
	case vString:
		r.prevSignature, r.hasPrev = string(p), true
	default:
		return nil, errors.New(`member "prevSignature" is neither a string nor null`)
	}
	return r, nil
}

// signingInput is the byte string a receipt's signature covers: the context
// prefix, then the canonical form of every member of the receipt except the
// signature itself.
func (r *receipt) signingInput() []byte {
	covered := newObject()
	for _, name := range r.obj.names {
		if name == "signature" {
			continue
		}
		v, _ := r.obj.get(name)
		covered.set(name, v)
	}
	prefix := receiptContext
	if r.version == receiptVersion3 {
		prefix = receiptContext3
	}
	return append([]byte(prefix), canon(covered)...)
}

// --- seals ----------------------------------------------------------------

type seal struct {
	sessionID  string
	finalCount int64
}

// sealSigningInput is spelled out by SPEC.md §2: the seal context prefix, then
// canon over exactly these four members.
func sealSigningInput(sessionID string, finalCount int64, sealedAt, keyID string) []byte {
	covered := newObject()
	covered.set("sessionId", vString(sessionID))
	covered.set("finalCount", vInt(finalCount))
	covered.set("sealedAt", vString(sealedAt))
	covered.set("keyId", vString(keyID))
	return append([]byte(sealContext), canon(covered)...)
}

// stat and lstat are os.Stat and os.Lstat. A test stands in a failure for
// either: for the second look at a path the first found absent, which no
// settled filesystem makes disagree, only a change between them; and for an
// answer only a network share that has gone away gives.
var (
	stat  = os.Stat
	lstat = os.Lstat
)

// errorFileNotFound is ERROR_FILE_NOT_FOUND: the answer by which Windows says
// a name in a directory it reached has nothing at it.
const errorFileNotFound = syscall.Errno(2)

// absent reports whether err, from a look at a path whose parent is a
// directory, confirms that nothing is there. os.IsNotExist is not enough on
// Windows, where it also answers true for ERROR_PATH_NOT_FOUND and
// ERROR_BAD_NETPATH: a directory, a drive or a server on the way could not
// be reached, which is not the absence of the path. A registry on a share
// that has gone away is there, and cannot be read -- taken for absent, it
// would load no seals, and a session sealed on the share would take a read.
func absent(err error) bool {
	if !errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if runtime.GOOS != "windows" {
		return true
	}
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == errorFileNotFound
}

// requirePlainSpelling refuses an input path -- the registry (a file), the
// decision-record directory (not a file) -- whose spelling the platform could
// resolve to another file than the one its spelling names, before anything is
// read or made (SPEC.md §4.1). What is left names one file for every reader
// and writer of it: the walk above it (pathAncestors), the look at it, the
// walk below it and the directories made for it all take the path as
// spelled, and so does the platform.
//
//   - a ".." after a named component: Linux and macOS step back from where
//     the component leads -- through a link, from the link's target -- and a
//     reading of the spelling steps back from the component;
//   - for a file, a trailing separator, which names a directory;
//   - on Windows, a path in the \\?\ or \??\ namespace, which Windows takes
//     literally, or the \\.\ namespace, which it reads as a device path; and a
//     component, the server and share of a UNC path included, that Windows
//     would not read as spelled (windowsReadsAsSpelled).
//
// A leading "..", a "." component, a repeated separator and a directory's
// trailing separator name the same file either way, and are taken.
func requirePlainSpelling(path string, file bool) error {
	refuse := func(why string) error { return fmt.Errorf("path spelling refused (%s): %s", why, path) }
	volume := filepath.VolumeName(path)
	components := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return r < 0x80 && os.IsPathSeparator(byte(r)) })
	}
	if runtime.GOOS == "windows" {
		if lead := strings.ReplaceAll(path[:min(len(path), 4)], "/", `\`); lead == `\\?\` || lead == `\??\` || lead == `\\.\` {
			return refuse(`Windows reads a path in the \\?\, \??\ or \\.\ namespace otherwise than a plain one`)
		}
		// a UNC path's server and share, which its volume names -- not a
		// drive's volume, whose colon is the drive's and no stream's
		if len(volume) > 2 && os.IsPathSeparator(volume[0]) && os.IsPathSeparator(volume[1]) {
			for _, component := range components(volume) {
				if !windowsReadsAsSpelled(component) {
					return refuse("Windows would not read a component as spelled")
				}
			}
		}
	}
	rest := path[len(volume):]
	if file && (rest == "" || os.IsPathSeparator(rest[len(rest)-1])) {
		return refuse("a file's path cannot end in a separator")
	}
	named := false
	for _, component := range components(rest) {
		switch component {
		case "..":
			if named {
				return refuse(`a ".." after a named component can resolve through a link`)
			}
		case ".":
		default:
			named = true
			if runtime.GOOS == "windows" && !windowsReadsAsSpelled(component) {
				return refuse("Windows would not read a component as spelled")
			}
		}
	}
	return nil
}

// windowsReadsAsSpelled reports whether Windows opens a path component by the
// name it is spelled with: not one ending in a space or a period, which
// Windows trims; not one holding a colon, which names a stream of a file; and
// not a reserved device name -- CON, PRN, AUX, NUL, CONIN$, CONOUT$, COM and
// LPT with a digit (superscript 1, 2 and 3 included) -- with or without an
// extension, which names the device.
func windowsReadsAsSpelled(component string) bool {
	if strings.HasSuffix(component, " ") || strings.HasSuffix(component, ".") || strings.Contains(component, ":") {
		return false
	}
	base := strings.ToUpper(component)
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	base = strings.TrimRight(base, " ")
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return false
	}
	if len(base) >= 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) {
		switch base[3:] {
		case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
			return false
		}
	}
	return true
}

// pathAncestors returns the directories the platform passes through on its way
// to path, deepest last, each spelled as the prefix of the path that ends
// before a separator -- never cleaned, so that each resolves exactly as that
// part of the whole path does. The root and the volume are left out, and so
// is the prefix before a repeated separator, which names no further directory.
// Prefixes are cut from the path as given rather than taken by filepath.Dir,
// which on Windows reads a repeated separator after the volume as the start of
// a UNC path, and stops climbing.
func pathAncestors(path string) []string {
	volume := len(filepath.VolumeName(path))
	var dirs []string
	for i := volume; i < len(path); i++ {
		if os.IsPathSeparator(path[i]) && i > volume && !os.IsPathSeparator(path[i-1]) {
			dirs = append(dirs, path[:i])
		}
	}
	return dirs
}

// absentOrLink judges a path a stat that follows links found not there. It is
// absent only when a look at the path itself confirms it: a link that leads
// nowhere is there and cannot be read, and a second look that fails for any
// other reason establishes nothing, so both are refusals. The caller has
// established that the path's parent is a directory, so the look is answered
// about the last component alone.
func absentOrLink(path, link string) error {
	_, err := lstat(path)
	switch {
	case err == nil:
		return fmt.Errorf("%s: %s", link, path)
	case absent(err):
		return nil
	default:
		return err
	}
}

// registryContainerReachable checks the directories that must exist above an
// input -- the registry file, the decision-record directory -- walking them
// from the filesystem root downward so that every stat is taken against a
// parent already known to be a directory. At each step the only outcomes are
// an existing directory, an existing non-directory (a refusal, naming the
// component), a link that leads nowhere (a refusal too), and a component that
// is not there at all (the input is then genuinely absent, and the caller's
// stat of it says so) -- which only the plain answer for a missing name
// establishes (absent): a directory, drive or share that cannot be reached is
// a refusal. The caller has refused a spelling the platform could
// resolve otherwise (requirePlainSpelling), so the directories walked, the
// prefixes of the path as spelled, are the ones the platform resolves.
//
// Walking downward is what keeps the classification off the platform's error
// mapping. Statting the registry path — or only its immediate parent — cannot do
// it: Windows answers ERROR_PATH_NOT_FOUND for any non-directory path component,
// at any depth, and os.IsNotExist reports that as absence.
//
// It reports whether every directory above the input is there. When one is
// confirmed absent the input is absent too, and the caller does not look at it:
// on Windows a look at a name under a missing directory answers
// ERROR_PATH_NOT_FOUND, which is not the plain answer absent() takes.
func registryContainerReachable(path string) (bool, error) {
	for _, dir := range pathAncestors(path) {
		info, err := stat(dir)
		if err != nil {
			if absent(err) {
				// nothing reachable from here down -- unless the component
				// is there as a link that leads nowhere, which a stat that
				// follows it reports as absent
				return false, absentOrLink(dir, "registry parent path component is a link that leads nowhere")
			}
			return false, err
		}
		if !info.IsDir() {
			return false, fmt.Errorf("registry parent path component is not a directory: %s", dir)
		}
	}
	return true, nil
}

// statInput stats an input the verifier reads -- the registry file, the
// decision-record directory -- once the directories above it are known to be
// reachable. It returns nil info and a nil error only for an input that is
// genuinely not there; a link that leads nowhere is there and cannot be read,
// never the absence a stat that follows the link would make of it.
func statInput(path, link string) (os.FileInfo, error) {
	info, err := stat(path)
	if err != nil {
		if absent(err) {
			return nil, absentOrLink(path, link)
		}
		return nil, err
	}
	return info, nil
}

// readRegistryBytes returns the registry's raw bytes and whether the registry is
// there at all. It is the one place that decides what an unreadable registry
// path means, so the verifier and the /registry endpoint cannot answer
// differently.
//
// SPEC.md §4.1: only a registry file that is genuinely not there is absent. A
// registry path that exists but cannot be read, that has an existing parent
// path component which is not a directory, or that is -- or lies under -- a
// link that leads nowhere, is a present and unreachable anchor: the caller must
// refuse rather than treat the anchor as empty.
func readRegistryBytes(path string) ([]byte, bool, error) {
	if err := requirePlainSpelling(path, true); err != nil {
		return nil, false, err
	}
	if there, err := registryContainerReachable(path); err != nil || !there {
		return nil, false, err
	}
	info, err := statInput(path, "the registry is a link that leads nowhere")
	if err != nil || info == nil {
		return nil, false, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// loadSeals reads the append-only registry and drops any seal whose keyId is not
// the verifier's own or whose signature does not verify under the public key. A malformed line is
// likewise not a seal, so it is dropped too.
//
// An absent registry loads no seals, which grades every session in the store
// `unregistered-session`. A registry that is present and unreachable is not
// absent: readRegistryBytes tells the two apart, and this refuses on the second.
func loadSeals(path string, publicKey []byte) (map[string]seal, []string, error) {
	seals := map[string]seal{}
	var order []string

	data, present, err := readRegistryBytes(path)
	if err != nil {
		return nil, nil, err
	}
	if !present {
		return seals, order, nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		v, err := parseJSON([]byte(line))
		if err != nil {
			continue
		}
		obj, ok := v.(*vObject)
		if !ok {
			continue
		}
		sessionID, ok1 := memberString(obj, "sessionId")
		sealedAt, ok2 := memberString(obj, "sealedAt")
		keyID, ok3 := memberString(obj, "keyId")
		sigHex, ok4 := memberString(obj, "signature")
		countV, ok5 := obj.get("finalCount")
		if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
			continue
		}
		count, ok := countV.(vInt)
		if !ok || count < 0 {
			continue
		}
		sig, err := hex.DecodeString(sigHex)
		if err != nil || len(sig) != ed25519.SignatureSize {
			continue
		}
		// The keyId must name the verifier's own key. It sits INSIDE the signed
		// payload, so the signature alone cannot establish it -- a seal signed by
		// this key while naming a foreign keyId verifies happily. SPEC.md §4 step 2
		// originally said "signature" and nothing else, and following that literally
		// is what surfaced the gap; the rule is now explicit and matches the
		// receipt-level key-id check.
		if keyID != keyIDFor(publicKey) {
			continue
		}
		if !ed25519.Verify(publicKey, sealSigningInput(sessionID, int64(count), sealedAt, keyID), sig) {
			continue
		}
		if _, seen := seals[sessionID]; seen {
			// SPEC.md §2 says re-sealing a session is refused, so a second
			// seal for one session should not exist. See AMBIGUITIES.md.
			continue
		}
		seals[sessionID] = seal{sessionID: sessionID, finalCount: int64(count)}
		order = append(order, sessionID)
	}
	return seals, order, nil
}

// topLevelSignature reads a receipt file's own signature member as written:
// through the canonical parser when the file is in the domain, and otherwise
// through a plain JSON decode that tolerates what the domain refuses in other
// members, refusing only text that is not one JSON object or whose top-level
// signature is not exactly one string. Duplicate top-level members are
// refused as ambiguous.
func topLevelSignature(data []byte) (string, bool) {
	if v, err := parseJSON(data); err == nil {
		if obj, ok := v.(*vObject); ok {
			return memberString(obj, "signature")
		}
		return "", false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return "", false
	}
	signature, seen := "", 0
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return "", false
		}
		key, _ := keyToken.(string)
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return "", false
		}
		if key == "signature" {
			seen++
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return "", false
			}
			signature = s
		}
	}
	// One complete object and nothing after it: the closing brace, then end
	// of input. A second value, trailing bytes, or a truncated object is not
	// a receipt file whose signature can be read as written.
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return "", false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return "", false
	}
	if seen != 1 {
		return "", false
	}
	return signature, true
}

func memberString(obj *vObject, name string) (string, bool) {
	v, ok := obj.get(name)
	if !ok {
		return "", false
	}
	s, ok := v.(vString)
	return string(s), ok
}

// --- verification ---------------------------------------------------------

// verifyWithRegistry verifies with no decision-record directory: the version 2
// call, under which every version 3 action receipt that passes the ladder is
// decision-record-mismatch (SPEC.md §4 step 6, fail closed).
func verifyWithRegistry(storeRoot, registryPath, authority string, publicKey []byte) (*report, error) {
	return verifyWithRegistryAndRecords(storeRoot, registryPath, authority, "", publicKey)
}

// verifyWithRegistryAndRecords is the whole of SPEC.md §4: the per-receipt and
// per-session findings, the registry anchor, and for version 3 action receipts
// the citation and decision-record checks of steps 5 and 6.
func verifyWithRegistryAndRecords(storeRoot, registryPath, authority, decisionRecords string, publicKey []byte) (*report, error) {
	// the inputs' spellings are judged before anything is read (SPEC.md §4.1)
	if err := requirePlainSpelling(registryPath, true); err != nil {
		return nil, err
	}
	if decisionRecords != "" {
		if err := requirePlainSpelling(decisionRecords, false); err != nil {
			return nil, fmt.Errorf("decision-record directory: %w", err)
		}
	}
	// SPEC.md §4.1: A store root that exists but is not a directory is an unreadable evidence container (refusal).
	if info, err := os.Stat(storeRoot); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	} else if !info.IsDir() {
		return nil, fmt.Errorf("store root is not a directory: %s", storeRoot)
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize)
	}
	rep := &report{OK: true, Findings: []finding{}}

	sessions, err := listSessions(storeRoot)
	if err != nil {
		return nil, err
	}
	counts := map[string]int64{}
	signatures := map[string]map[string]string{}
	var actions []*receipt
	for _, sessionID := range sessions {
		result, err := verifySession(storeRoot, sessionID, authority, publicKey)
		if err != nil {
			return nil, err
		}
		counts[sessionID] = result.count
		signatures[sessionID] = result.signatures
		actions = append(actions, result.actions...)
		rep.Findings = append(rep.Findings, result.findings...)
	}

	seals, sealOrder, err := loadSeals(registryPath, publicKey)
	if err != nil {
		return nil, err
	}

	// SPEC.md §3 step 3: every session in the store must be anchored.
	for _, sessionID := range sessions {
		s, sealed := seals[sessionID]
		have := counts[sessionID]
		switch {
		case !sealed:
			rep.Findings = append(rep.Findings, finding{
				"sessionId": sessionID, "status": "unregistered-session",
			})
		case have < s.finalCount:
			rep.Findings = append(rep.Findings, finding{
				"sessionId": sessionID, "status": "tail-rollback",
				"have": have, "sealed": s.finalCount,
			})
		case have > s.finalCount:
			rep.Findings = append(rep.Findings, finding{
				"sessionId": sessionID, "status": "count-exceeds-seal",
				"have": have, "sealed": s.finalCount,
			})
		}
	}
	// SPEC.md §3 step 4: every sealed session must still be in the store.
	inStore := map[string]bool{}
	for _, s := range sessions {
		inStore[s] = true
	}
	for _, sessionID := range sealOrder {
		if !inStore[sessionID] {
			rep.Findings = append(rep.Findings, finding{
				"sessionId": sessionID, "status": "sealed-session-missing",
			})
		}
	}

	// SPEC.md §4 steps 5 and 6: for each version 3 action receipt that passed
	// the ladder, its citations resolve against what was enumerated -- never
	// against the filesystem, which may fold case -- and its decision record
	// exists as some candidate's bytes. Both are reported beside the receipt's
	// ok, once each, and independently.
	wanted := map[string]bool{}
	for _, r := range actions {
		wanted[strings.TrimPrefix(r.recordDigest, "sha256:")] = true
	}
	// SPEC.md §4 step 7, resolved as each citing record is found -- the
	// enumeration the citations resolve against is complete by now -- so
	// nothing of the archive is retained but the findings: a record that
	// cites -- a candidate that is one JSON object carrying a cites member
	// -- has each citation resolved exactly as an action's is, against the
	// same enumeration; a member not of the shape is malformed. Once per
	// record, by the digest of its bytes.
	var recordFindings []finding
	onRecord := func(r citingRecord) {
		if r.malformed {
			recordFindings = append(recordFindings, finding{"recordDigest": r.digest, "status": "record-citation-malformed"})
			return
		}
		for _, c := range r.cites {
			stem := strconv.FormatInt(c.callIndex, 10)
			if signature, ok := signatures[c.sessionID][stem]; !ok || signature != c.signature {
				recordFindings = append(recordFindings, finding{"recordDigest": r.digest, "status": "record-citation-unresolved"})
				return
			}
		}
	}
	candidates, recordsPresent, err := decisionCandidates(decisionRecords, wanted, onRecord)
	if err != nil {
		return nil, err
	}
	for _, r := range actions {
		for _, c := range r.cites {
			stem := strconv.FormatInt(c.callIndex, 10)
			if signature, ok := signatures[c.sessionID][stem]; !ok || signature != c.signature {
				rep.Findings = append(rep.Findings, finding{
					"sessionId": r.sessionID, "callIndex": r.callIndex, "status": "citation-unresolved",
				})
				break
			}
		}
		if !recordsPresent || !candidates[strings.TrimPrefix(r.recordDigest, "sha256:")] {
			rep.Findings = append(rep.Findings, finding{
				"sessionId": r.sessionID, "callIndex": r.callIndex, "status": "decision-record-mismatch",
			})
		}
	}

	rep.Findings = append(rep.Findings, recordFindings...)

	for _, f := range rep.Findings {
		if f["status"] != "ok" {
			rep.OK = false
			break
		}
	}
	return rep, nil
}

// listSessions enumerates the session directories under the store's receipts
// root (SPEC.md §3a: a session id names a directory and a verifier discovers
// sessions by enumerating). A store with no receipts root simply has none; a receipts path that exists but is not a directory is a refusal, not zero sessions.
func listSessions(storeRoot string) ([]string, error) {
	receiptsPath := filepath.Join(storeRoot, "receipts")
	info, err := os.Stat(receiptsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("receipts path is not a directory: %s", receiptsPath)
	}

	entries, err := os.ReadDir(receiptsPath)
	if err != nil {
		return nil, err
	}
	var sessions []string
	for _, e := range entries {
		if e.IsDir() {
			sessions = append(sessions, e.Name())
		}
	}
	sort.Strings(sessions)
	return sessions, nil
}

// sessionResult is what verifying one session establishes: its findings; the
// number of receipt files it holds -- the "store count" the seal is compared
// against, which counts files present, not the highest callIndex; the
// signature member of every file that parsed to one, by filename stem, which
// is what a citation resolves against (SPEC.md §4 step 5); and the version 3
// action receipts that passed the ladder, for steps 5 and 6.
type sessionResult struct {
	findings   []finding
	count      int64
	signatures map[string]string
	actions    []*receipt
}

func verifySession(storeRoot, sessionID, authority string, publicKey []byte) (*sessionResult, error) {
	dir := filepath.Join(storeRoot, "receipts", sessionID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	result := &sessionResult{signatures: map[string]string{}}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	// Filename string order. SPEC.md does not make finding order normative;
	// corpus/README.md records that as an open question.
	sort.Strings(names)

	var findings []finding
	var valid []*receipt
	expectedKeyID := keyIDFor(publicKey)

	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		// What a citation resolves against is the file's signature member as
		// written, whatever the file's status: a cited receipt that fails is
		// resolved and then judged by its own finding (SPEC.md §4 step 5). So
		// the member is read even from a file the canonical parser refuses --
		// a float in an unrelated member -- as long as the text is JSON with
		// one unambiguous top-level string under that name.
		if signature, ok := topLevelSignature(data); ok {
			result.signatures[strings.TrimSuffix(name, ".json")] = signature
		}
		r, status := checkReceipt(data, storeRoot, sessionID, name, authority, publicKey, expectedKeyID)
		if r == nil {
			findings = append(findings, finding{
				"sessionId": sessionID, "file": name, "status": status,
			})
			continue
		}
		findings = append(findings, finding{
			"sessionId": sessionID, "callIndex": r.callIndex, "status": status,
		})
		if status == "ok" {
			valid = append(valid, r)
			if r.kind == "action" {
				result.actions = append(result.actions, r)
			}
		}
	}

	// A receipt that failed is excluded from the reconstruction, so the
	// sequence and chain are checked over what survived.
	sort.Slice(valid, func(i, j int) bool { return valid[i].callIndex < valid[j].callIndex })
	contiguous := true
	for i, r := range valid {
		if r.callIndex != int64(i) {
			contiguous = false
			break
		}
	}
	if !contiguous {
		findings = append(findings, finding{
			"sessionId": sessionID, "callIndex": nil, "status": "sequence-broken",
		})
	} else {
		// A session is of one version (SPEC.md §1.3): a receipt whose version
		// differs from the head's breaks the chain exactly as a prevSignature
		// that names the wrong signature does, and the first break of either
		// kind reports the one chain-broken.
		for i, r := range valid {
			var want string
			var wantSet bool
			if i > 0 {
				want, wantSet = valid[i-1].signature, true
			}
			versionDiffers := i > 0 && r.version != valid[0].version
			if r.hasPrev != wantSet || (wantSet && r.prevSignature != want) || versionDiffers {
				findings = append(findings, finding{
					"sessionId": sessionID, "callIndex": nil, "status": "chain-broken",
				})
				break
			}
		}
	}
	result.findings, result.count = findings, int64(len(names))
	return result, nil
}

// checkReceipt runs the per-receipt checks in the order SPEC.md §1 lists them:
// SPEC 1.4's normative order, exactly: lexical form (order 1), then
// unsupported-version, key-mismatch, signature-mismatch, misfiled,
// authority-mismatch, artifact-missing, artifact-mismatch. The first failure is
// the receipt's status; a receipt reports one status, not a list. A nil receipt
// means the file never became a receipt at all, which includes a receipt that
// parsed but failed order 1.
func checkReceipt(data []byte, storeRoot, sessionID, fileName, authority string, publicKey []byte, expectedKeyID string) (*receipt, string) {
	v, err := parseJSON(data)
	if err != nil {
		return nil, "malformed"
	}
	obj, ok := v.(*vObject)
	if !ok {
		return nil, "malformed"
	}
	r, err := receiptFrom(obj)
	if err != nil {
		return nil, "malformed"
	}
	// SPEC 1.4 order 1: every LEXICAL requirement, settled before the version,
	// the key id, or any cryptographic work. SPEC 1.2 fixes both forms --
	// resultDigest is "sha256:" + 64 lowercase hex, signature is Ed25519 in hex.
	// encoding/hex accepts uppercase, so lowercase is checked explicitly rather
	// than inferred from a successful decode.
	digestHex, ok := strings.CutPrefix(r.resultDigest, "sha256:")
	if !ok || !isLowerHexOfLen(digestHex, 64) {
		return nil, "malformed"
	}
	// A signature containing non-hex characters is malformed, not a mismatch:
	// nothing about it is a failed cryptographic check.
	if _, err := hex.DecodeString(r.signature); err != nil {
		return nil, "malformed"
	}

	if r.version != receiptVersion && r.version != receiptVersion3 {
		return r, "unsupported-version"
	}
	// key-mismatch precedes signature-mismatch (SPEC 1.4 orders 3 then 4), so a
	// receipt carrying both defects reports the earlier one. Verifying first
	// reported the later one and made the diagnostic depend on our own order.
	if subtle.ConstantTimeCompare([]byte(r.keyID), []byte(expectedKeyID)) != 1 {
		return r, "key-mismatch"
	}
	// Well-formed hex of the wrong length is NOT malformed: it is a signature
	// that cannot verify, which is order 4.
	sig, err := hex.DecodeString(r.signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return r, "signature-mismatch"
	}
	if !ed25519.Verify(publicKey, r.signingInput(), sig) {
		return r, "signature-mismatch"
	}
	// Location binding: the receipt has to sit where it says it does, so a
	// valid receipt cannot be moved within or between sessions.
	stem := strings.TrimSuffix(fileName, ".json")
	n, err := strconv.ParseInt(stem, 10, 64)
	if err != nil || n != r.callIndex || r.sessionID != sessionID {
		return r, "misfiled"
	}
	if r.authority != authority {
		return r, "authority-mismatch"
	}
	// Result re-digest: the retained artifact must still be the bytes the
	// receipt attested.
	artifact, err := os.ReadFile(filepath.Join(storeRoot, "artifacts", digestHex))
	if err != nil {
		return r, "artifact-missing"
	}
	sum := sha256.Sum256(artifact)
	if hex.EncodeToString(sum[:]) != digestHex {
		return r, "artifact-mismatch"
	}
	return r, "ok"
}

// isLowerHexOfLen reports whether s is exactly n lowercase hexadecimal
// characters. encoding/hex accepts uppercase and SPEC 1.2 does not, so a
// successful decode is not sufficient evidence of the stated form.
func isLowerHexOfLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
