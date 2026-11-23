package main

// The dry-run receipt (SPEC.md §1.2c; ADR-0054 decision 2): the gateway's
// signed word that a write would have passed the write's own ladder, sent
// nowhere. It is a form of its own, under its own prefix, with no
// receiptVersion: every receipt verifier, an already released one
// included, finds it malformed, and nothing cites it. gateway
// verify-dry-run checks it as itself, and reads no store.

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// dryRunContext is the dry-run receipt's signing prefix, which no
	// receipt is signed under.
	dryRunContext = "judgment-pack-gateway/dry-run/1:"
	// dryRunVersion1 is dryRunVersion's one value, inside the signing input.
	dryRunVersion1 = "1"
)

// errDryRunNotAReceipt is why a dry-run receipt met as a receipt is
// malformed (SPEC.md §1.4 order 1).
var errDryRunNotAReceipt = errors.New("a dry-run receipt is not a receipt of a session")

// dryRunMembers are the dry-run receipt's members, true where required.
var dryRunMembers = map[string]bool{
	"dryRunVersion": true, "authority": true, "keyId": true, "servedAt": true, "signature": true,
	"source": true, "action": true, "scope": false, "delegation": false, "alg": false,
}

// dryRunActionMembers are its action's: §1.2a's, with no adapter,
// observedAt or delivery, since no target answered.
var dryRunActionMembers = map[string]bool{
	"requester": true, "decision": true, "cites": true, "tool": true, "request": true,
	"policy": false, "approvals": false,
}

// dryRunReport is what verify-dry-run answers. DryRun is true in every
// report, so none reads as an action's.
type dryRunReport struct {
	OK       bool      `json:"ok"`
	Findings []finding `json:"findings"`
	DryRun   bool      `json:"dryRun"`
}

// verifyDryRun checks one dry-run receipt under the pinned key: malformed
// for a form error, key-mismatch for a keyId or alg that is not the pinned
// key's, signature-mismatch for a signature the key did not make over the
// dry-run prefix.
func verifyDryRun(data []byte, pin heldKey) dryRunReport {
	rep := dryRunReport{OK: true, Findings: []finding{}, DryRun: true}
	if status := dryRunStatus(data, pin); status != "" {
		rep.OK = false
		rep.Findings = append(rep.Findings, finding{"status": status})
	}
	return rep
}

func dryRunStatus(data []byte, pin heldKey) string {
	v, err := parseJSON(data)
	if err != nil {
		return "malformed"
	}
	obj, ok := v.(*vObject)
	if !ok || dryRunForm(obj) != nil {
		return "malformed"
	}
	keyID, _ := memberString(obj, "keyId")
	alg, _ := recordAlg(obj, "alg")
	if subtle.ConstantTimeCompare([]byte(keyID), []byte(pin.keyID())) != 1 || alg != pin.alg {
		return "key-mismatch"
	}
	signature, _ := memberString(obj, "signature")
	sig, err := hex.DecodeString(signature)
	if err != nil || !verifyByAlgorithm(alg, pin, recordSigningInput(dryRunContext, obj), sig) {
		return "signature-mismatch"
	}
	return ""
}

// dryRunForm holds a dry-run receipt to §1.2c's form: exactly its members,
// each of §1.2a's forms.
func dryRunForm(obj *vObject) error {
	if err := exactlyMembers(obj, dryRunMembers, "dry-run receipt"); err != nil {
		return err
	}
	for name := range dryRunMembers {
		if _, present := obj.get(name); !present && dryRunMembers[name] {
			return fmt.Errorf("dry-run receipt: missing member %q", name)
		}
	}
	if version, _ := memberString(obj, "dryRunVersion"); version != dryRunVersion1 {
		return errors.New(`dry-run receipt: dryRunVersion is "1"`)
	}
	for _, name := range []string{"authority", "servedAt"} {
		if _, ok := memberString(obj, name); !ok {
			return fmt.Errorf("dry-run receipt: %s is not a string", name)
		}
	}
	if keyID, ok := memberString(obj, "keyId"); !ok || !isLowerHexOfLen(keyID, 32) {
		return errors.New("dry-run receipt: keyId is not 32 lowercase hexadecimal characters")
	}
	if signature, ok := memberString(obj, "signature"); !ok || !isSignature3(signature) {
		return errors.New("dry-run receipt: signature is not 128 lowercase hexadecimal characters")
	}
	if _, ok := recordAlg(obj, "alg"); !ok {
		return errors.New(`dry-run receipt: alg is not "ES256"`)
	}
	source, _ := memberString(obj, "source")
	if platform, isWrite := strings.CutSuffix(source, "/write"); !isWrite || platform == "" {
		return errors.New("dry-run receipt: source is not <platform>/write")
	}
	if v, present := obj.get("scope"); present {
		if s, ok := stringOf(v); !ok || !isScopeIdentifier(s) {
			return errors.New("dry-run receipt: scope is not a scope identifier: " + scopeForm)
		}
	}
	actionV, _ := obj.get("action")
	action, err := requireObject(actionV, "action")
	if err != nil {
		return err
	}
	if err := exactlyMembers(action, dryRunActionMembers, "dry-run receipt action"); err != nil {
		return err
	}
	if err := validateActionClaims(action, &receipt{obj: obj}); err != nil {
		return err
	}
	// §11.7's form, and the requester its subject: the check a receipt's
	// caller and requester are held to, with the requester standing for the
	// caller a dry-run receipt does not carry.
	if v, present := obj.get("delegation"); present {
		requester, _ := action.get("requester")
		holder := newObject()
		holder.set("caller", requester)
		holder.set("action", action)
		if err := validateDelegationMember(v, holder, "action"); err != nil {
			return err
		}
	}
	return nil
}

// cmdVerifyDryRun is gateway verify-dry-run --public-key <hex>
// [--public-key-alg ES256] <file>: the report on standard output, exit 0
// with any verdict, 2 for a usage error or a file that cannot be read.
func cmdVerifyDryRun(args []string, stdout, stderr io.Writer) int {
	const usage = "usage: gateway verify-dry-run --public-key <key> [--public-key-alg ES256] <file>"
	if len(args) < 3 || args[0] != "--public-key" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	keyText, alg, rest := args[1], algEd25519, args[2:]
	if len(rest) > 0 && rest[0] == "--public-key-alg" {
		if len(rest) < 2 || rest[1] != algES256 {
			fmt.Fprintln(stderr, "gateway verify-dry-run: --public-key-alg is ES256; without it the key is an Ed25519 key's 64 lowercase hexadecimal characters")
			return 2
		}
		alg, rest = algES256, rest[2:]
	}
	if len(rest) != 1 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	key := decodeKeyHex(alg, keyText)
	if key == nil || !keySoundFor(alg, key) {
		fmt.Fprintf(stderr, "gateway verify-dry-run: --public-key is not a %s public key of its form\n", algName(alg))
		return 2
	}
	data, err := os.ReadFile(rest[0])
	if err != nil {
		fmt.Fprintln(stderr, "gateway verify-dry-run: the file cannot be read")
		return 2
	}
	out, err := json.Marshal(verifyDryRun(data, heldKey{alg: alg, key: key}))
	if err != nil {
		fmt.Fprintln(stderr, "gateway verify-dry-run:", err)
		return 2
	}
	fmt.Fprintln(stdout, string(out))
	return 0
}

// dryRunVector is one of corpus/dry-run/*.json: a dry-run receipt's bytes,
// what verify-dry-run answers of them, and asReceipt, the status every
// receipt verifier -- v0.38.0's included -- gives the same bytes held as
// receipts/s1/0.json of a store.
type dryRunVector struct {
	Name         string `json:"name"`
	Note         string `json:"note"`
	PublicKeyAlg string `json:"publicKeyAlg"`
	Receipt      string `json:"receipt"`
	Expected     struct {
		OK       bool                `json:"ok"`
		Findings []map[string]string `json:"findings"`
	} `json:"expected"`
	AsReceipt string `json:"asReceipt"`
}

// runDryRunVectors holds verify-dry-run, and the store verifier's reading
// of the same bytes, to every dry-run vector.
func runDryRunVectors(corpusDir string) ([]string, int, error) {
	paths, err := filepath.Glob(filepath.Join(corpusDir, "dry-run", "*.json"))
	if err != nil {
		return nil, 0, err
	}
	sort.Strings(paths)
	edKeyRaw, err := corpusPublicKey(corpusDir)
	if err != nil {
		return nil, 0, err
	}
	p256Key, err := corpusP256PublicKey(corpusDir)
	if err != nil {
		return nil, 0, err
	}
	var failures []string
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, 0, err
		}
		if err := noMemberTwice(raw); err != nil {
			return nil, 0, fmt.Errorf("%s: %v", path, err)
		}
		var vector dryRunVector
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&vector); err != nil {
			return nil, 0, fmt.Errorf("%s: %v", path, err)
		}
		if vector.Name != strings.TrimSuffix(filepath.Base(path), ".json") || vector.AsReceipt == "" {
			return nil, 0, fmt.Errorf("%s: named %q, or no asReceipt", path, vector.Name)
		}
		pin := edKey(edKeyRaw)
		switch vector.PublicKeyAlg {
		case "":
		case algES256:
			pin = p256Key
		default:
			return nil, 0, fmt.Errorf("%s: publicKeyAlg is ES256 or absent", path)
		}
		rep := verifyDryRun([]byte(vector.Receipt), pin)
		var got, want []string
		for _, f := range rep.Findings {
			got = append(got, fmt.Sprint(f["status"]))
		}
		for _, f := range vector.Expected.Findings {
			want = append(want, f["status"])
		}
		if rep.OK != vector.Expected.OK || strings.Join(got, ",") != strings.Join(want, ",") {
			failures = append(failures, fmt.Sprintf("dry-run %s: expected ok=%v %v, got ok=%v %v", vector.Name, vector.Expected.OK, want, rep.OK, got))
		}
		status, err := dryRunAsReceipt([]byte(vector.Receipt), pin)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %v", path, err)
		}
		if status != vector.AsReceipt {
			failures = append(failures, fmt.Sprintf("dry-run %s: as a receipt, expected %s, got %s", vector.Name, vector.AsReceipt, status))
		}
	}
	return failures, len(paths), nil
}

// dryRunAsReceipt is the status the store verifier gives the bytes held as
// receipts/s1/0.json of a store with an empty registry.
func dryRunAsReceipt(data []byte, pin heldKey) (string, error) {
	root, err := os.MkdirTemp("", "dry-run-as-receipt")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(root)
	store := filepath.Join(root, "store")
	if err := os.MkdirAll(filepath.Join(store, "receipts", "s1"), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(store, "receipts", "s1", "0.json"), data, 0o600); err != nil {
		return "", err
	}
	registry := filepath.Join(root, "registry.jsonl")
	if err := os.WriteFile(registry, nil, 0o600); err != nil {
		return "", err
	}
	rep, err := verifierByPin(false, "")(store, registry, "gateway:corpus", "", "", pin)
	if err != nil {
		return "", err
	}
	for _, f := range rep.Findings {
		if f["sessionId"] == "s1" && (f["file"] == "0.json" || f["callIndex"] != nil) {
			return fmt.Sprint(f["status"]), nil
		}
	}
	return "", errors.New("the store verifier named no status for the receipt")
}
