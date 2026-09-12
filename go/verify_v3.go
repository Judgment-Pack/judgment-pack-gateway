package main

// Receipt version 3 (SPEC.md §1.2a, §4 steps 5 and 6): the structural checks
// order 1 applies to a version 3 receipt, and the candidates a decision-record
// directory yields for the decision-record check. The citation and
// decision-record findings themselves are produced in verifyWithRegistry,
// after every session has been verified, because a citation may name any
// session in the store.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
		cites, recordDigest, err := validateAction(actionV)
		if err != nil {
			return err
		}
		r.cites, r.recordDigest = cites, recordDigest
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

func validateAction(v value) ([]citation, string, error) {
	obj, err := requireObject(v, "action")
	if err != nil {
		return nil, "", err
	}
	requester, ok := obj.get("requester")
	if !ok {
		return nil, "", errors.New(`action: missing member "requester"`)
	}
	if _, isNull := requester.(vNull); isNull {
		return nil, "", errors.New("action: requester is null")
	}
	if err := validateIdentity(requester, "action.requester"); err != nil {
		return nil, "", err
	}
	decisionV, ok := obj.get("decision")
	if !ok {
		return nil, "", errors.New(`action: missing member "decision"`)
	}
	decision, err := requireObject(decisionV, "action.decision")
	if err != nil {
		return nil, "", err
	}
	for _, member := range []string{"recordDigest", "packDigest"} {
		if err := requireDigest(decision, member); err != nil {
			return nil, "", fmt.Errorf("action.decision: %w", err)
		}
	}
	recordDigest, _ := memberString(decision, "recordDigest")
	citesV, ok := obj.get("cites")
	if !ok {
		return nil, "", errors.New(`action: missing member "cites"`)
	}
	citesArr, ok := citesV.(vArray)
	if !ok {
		return nil, "", errors.New("action: cites is not an array")
	}
	cites := make([]citation, 0, len(citesArr))
	for _, entry := range citesArr {
		c, err := requireObject(entry, "action.cites[]")
		if err != nil {
			return nil, "", err
		}
		sessionID, err := requireString(c, "sessionId")
		if err != nil {
			return nil, "", fmt.Errorf("action.cites[]: %w", err)
		}
		if err := requireSession(sessionID); err != nil {
			return nil, "", fmt.Errorf("action.cites[]: sessionId is not a flat token")
		}
		indexV, ok := c.get("callIndex")
		if !ok {
			return nil, "", errors.New(`action.cites[]: missing member "callIndex"`)
		}
		index, ok := indexV.(vInt)
		if !ok || index < 0 {
			return nil, "", errors.New("action.cites[]: callIndex is not a non-negative integer")
		}
		signature, err := requireString(c, "signature")
		if err != nil {
			return nil, "", fmt.Errorf("action.cites[]: %w", err)
		}
		if !isSignature3(signature) {
			return nil, "", errors.New("action.cites[]: signature is not 128 lowercase hex characters")
		}
		cites = append(cites, citation{sessionID: sessionID, callIndex: int64(index), signature: signature})
	}
	toolV, ok := obj.get("tool")
	if !ok {
		return nil, "", errors.New(`action: missing member "tool"`)
	}
	tool, err := requireObject(toolV, "action.tool")
	if err != nil {
		return nil, "", err
	}
	for _, member := range []string{"shape", "name"} {
		if _, err := requireString(tool, member); err != nil {
			return nil, "", fmt.Errorf("action.tool: %w", err)
		}
	}
	if err := nullableString(tool, "endpoint", nil); err != nil {
		return nil, "", fmt.Errorf("action.tool: %w", err)
	}
	if err := requireDigest(obj, "request"); err != nil {
		return nil, "", fmt.Errorf("action: %w", err)
	}
	adapter, ok := obj.get("adapter")
	if !ok {
		return nil, "", errors.New(`action: missing member "adapter"`)
	}
	if err := validateAdapter(adapter, "action.adapter"); err != nil {
		return nil, "", err
	}
	if _, err := requireString(obj, "observedAt"); err != nil {
		return nil, "", fmt.Errorf("action: %w", err)
	}
	return cites, recordDigest, nil
}

// decisionCandidates hashes every candidate under dir per SPEC.md §4 step 6 and
// reports whether the directory was present at all. An empty dir means the
// verifier was given none, which is absent. Absent and present-but-unreadable
// are told apart exactly as they are for the registry (§4.1): absent fails
// closed later, unreadable is no verdict here.
func decisionCandidates(dir string) (map[string]bool, bool, error) {
	if dir == "" {
		return nil, false, nil
	}
	if err := registryContainerReachable(dir); err != nil {
		return nil, false, fmt.Errorf("decision-record directory: %w", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if !info.IsDir() {
		return nil, false, fmt.Errorf("decision-record path is not a directory: %s", dir)
	}
	candidates := map[string]bool{}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // never followed, whatever it points at
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		candidates[hex.EncodeToString(sum[:])] = true
		if strings.HasSuffix(d.Name(), ".jsonl") {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSuffix(line, "\r")
				if line == "" {
					continue
				}
				sum := sha256.Sum256([]byte(line))
				candidates[hex.EncodeToString(sum[:])] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return candidates, true, nil
}
