package main

// Boundary tests for the version 3 verifier, derived from SPEC.md §1.2a and
// §4 step 6 for the branches no corpus vector exercises. The structural
// checks are driven through validateVersion3 on hand-built objects, so no
// signature is needed; the candidate rule is driven through
// decisionCandidates on real directories.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testSig3 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func identity() *vObject {
	o := newObject()
	o.set("issuer", vString("https://login.example.com/"))
	o.set("subject", vString("someone"))
	o.set("tokenDigest", vString(testDigest("token")))
	return o
}

func adapter() *vObject {
	o := newObject()
	o.set("name", vString("adapter"))
	o.set("version", vString("1.0"))
	o.set("digest", vString(testDigest("adapter")))
	return o
}

func acquisition() *vObject {
	a := newObject()
	a.set("adapter", adapter())
	a.set("shape", vString("http"))
	a.set("endpoint", vNull{})
	a.set("statement", vNull{})
	a.set("snapshot", vNull{})
	a.set("peerIdentity", vNull{})
	a.set("schema", vNull{})
	a.set("upstreamToken", vNull{})
	a.set("observedAt", vString("2026-09-12T00:00:00Z"))
	return a
}

func action() *vObject {
	act := newObject()
	act.set("requester", identity())
	dec := newObject()
	dec.set("recordDigest", vString(testDigest("record")))
	dec.set("packDigest", vString(testDigest("pack")))
	act.set("decision", dec)
	cite := newObject()
	cite.set("sessionId", vString("s1"))
	cite.set("callIndex", vInt(0))
	cite.set("signature", vString(testSig3))
	act.set("cites", vArray{cite})
	tool := newObject()
	tool.set("shape", vString("mcp"))
	tool.set("endpoint", vNull{})
	tool.set("name", vString("update"))
	act.set("tool", tool)
	act.set("request", vString(testDigest("request")))
	act.set("adapter", adapter())
	act.set("observedAt", vString("2026-09-12T00:00:02Z"))
	return act
}

// receipt3 builds a structurally complete version 3 receipt object of the
// given kind; mutate takes it apart before validation.
func receipt3(kind string, mutate func(*vObject)) (*vObject, *receipt) {
	obj := newObject()
	obj.set("receiptVersion", vString("3"))
	obj.set("sessionId", vString("s1"))
	obj.set("callIndex", vInt(1))
	obj.set("prevSignature", vString(testSig3))
	obj.set("source", vString("corpus"))
	obj.set("argumentsCommitment", vString(testDigest("args")))
	obj.set("resultDigest", vString(testDigest("result")))
	obj.set("servedAt", vString("2026-09-12T00:00:00Z"))
	obj.set("authority", vString("gateway:test"))
	obj.set("keyId", vString(strings.Repeat("ab", 16)))
	obj.set("kind", vString(kind))
	obj.set("caller", vNull{})
	if kind == "acquisition" {
		obj.set("acquisition", acquisition())
	} else {
		obj.set("action", action())
	}
	obj.set("signature", vString(testSig3))
	if mutate != nil {
		mutate(obj)
	}
	r := &receipt{obj: obj, version: "3", sessionID: "s1", keyID: strings.Repeat("ab", 16), signature: testSig3}
	if s, ok := memberString(obj, "sessionId"); ok {
		r.sessionID = s
	}
	if s, ok := memberString(obj, "keyId"); ok {
		r.keyID = s
	}
	if s, ok := memberString(obj, "signature"); ok {
		r.signature = s
	}
	return obj, r
}

func sub(obj *vObject, name string) *vObject {
	v, _ := obj.get(name)
	return v.(*vObject)
}

func TestVersion3StructuralConstraints(t *testing.T) {
	accepted := []struct {
		name   string
		kind   string
		mutate func(*vObject)
	}{
		{"complete acquisition", "acquisition", nil},
		{"complete action", "action", nil},
		{"caller present", "acquisition", func(o *vObject) { o.set("caller", identity()) }},
		{"pageItems present and well formed", "acquisition", func(o *vObject) {
			sub(o, "acquisition").set("pageItems", vArray{vString(testDigest("a")), vString(testDigest("b"))})
		}},
		{"pageItems empty", "acquisition", func(o *vObject) { sub(o, "acquisition").set("pageItems", vArray{}) }},
		{"tool.endpoint a string", "action", func(o *vObject) { sub(sub(o, "action"), "tool").set("endpoint", vString("https://x/")) }},
		{"cites empty", "action", func(o *vObject) { sub(o, "action").set("cites", vArray{}) }},
		{"an unknown extra member", "acquisition", func(o *vObject) { o.set("vendorNote", vString("kept under the signature")) }},
	}
	for _, tc := range accepted {
		t.Run("accepts "+tc.name, func(t *testing.T) {
			obj, r := receipt3(tc.kind, tc.mutate)
			if err := validateVersion3(obj, r); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
	refused := []struct {
		name   string
		kind   string
		mutate func(*vObject)
	}{
		{"argumentsDigest present", "acquisition", func(o *vObject) { o.set("argumentsDigest", vString("hmac-sha256:00")) }},
		{"sessionId not a token", "acquisition", func(o *vObject) { o.set("sessionId", vString("bad session")) }},
		{"keyId uppercase", "acquisition", func(o *vObject) { o.set("keyId", vString(strings.Repeat("AB", 16))) }},
		{"keyId wrong length", "acquisition", func(o *vObject) { o.set("keyId", vString("abcd")) }},
		{"signature uppercase", "acquisition", func(o *vObject) { o.set("signature", vString(strings.ToUpper(testSig3))) }},
		{"signature short", "acquisition", func(o *vObject) { o.set("signature", vString(testSig3[:126])) }},
		{"argumentsCommitment uppercase", "acquisition", func(o *vObject) { o.set("argumentsCommitment", vString(strings.ToUpper(testDigest("x")))) }},
		{"caller absent", "acquisition", func(o *vObject) { o.names = remove(o.names, "caller"); delete(o.byName, "caller") }},
		{"caller a string", "acquisition", func(o *vObject) { o.set("caller", vString("someone")) }},
		{"kind outside enumeration", "acquisition", func(o *vObject) { o.set("kind", vString("other")) }},
		{"acquisition kind with action object", "acquisition", func(o *vObject) { o.set("action", action()) }},
		{"action kind without action object", "action", func(o *vObject) { o.names = remove(o.names, "action"); delete(o.byName, "action") }},
		{"shape outside enumeration", "acquisition", func(o *vObject) { sub(o, "acquisition").set("shape", vString("ftp")) }},
		{"endpoint a number", "acquisition", func(o *vObject) { sub(o, "acquisition").set("endpoint", vInt(42)) }},
		{"endpoint absent", "acquisition", func(o *vObject) {
			a := sub(o, "acquisition")
			a.names = remove(a.names, "endpoint")
			delete(a.byName, "endpoint")
		}},
		{"schema not a digest", "acquisition", func(o *vObject) { sub(o, "acquisition").set("schema", vString("sha256:short")) }},
		{"pageItems not an array", "acquisition", func(o *vObject) { sub(o, "acquisition").set("pageItems", vString("x")) }},
		{"pageItems element not a digest", "acquisition", func(o *vObject) {
			sub(o, "acquisition").set("pageItems", vArray{vString("sha256:nope")})
		}},
		{"adapter.name null", "acquisition", func(o *vObject) { sub(sub(o, "acquisition"), "adapter").set("name", vNull{}) }},
		{"observedAt a number", "acquisition", func(o *vObject) { sub(o, "acquisition").set("observedAt", vInt(1)) }},
		{"requester null", "action", func(o *vObject) { sub(o, "action").set("requester", vNull{}) }},
		{"cites sessionId not a token", "action", func(o *vObject) {
			sub(o, "action").getArray("cites")[0].(*vObject).set("sessionId", vString("../x"))
		}},
		{"cites callIndex negative", "action", func(o *vObject) {
			sub(o, "action").getArray("cites")[0].(*vObject).set("callIndex", vInt(-1))
		}},
		{"cites signature uppercase", "action", func(o *vObject) {
			sub(o, "action").getArray("cites")[0].(*vObject).set("signature", vString(strings.ToUpper(testSig3)))
		}},
		{"cites not an array", "action", func(o *vObject) { sub(o, "action").set("cites", vString("x")) }},
		{"decision.recordDigest not a digest", "action", func(o *vObject) { sub(sub(o, "action"), "decision").set("recordDigest", vString("x")) }},
		{"tool.endpoint a number", "action", func(o *vObject) { sub(sub(o, "action"), "tool").set("endpoint", vInt(1)) }},
		{"request absent", "action", func(o *vObject) {
			a := sub(o, "action")
			a.names = remove(a.names, "request")
			delete(a.byName, "request")
		}},
	}
	for _, tc := range refused {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			obj, r := receipt3(tc.kind, tc.mutate)
			if err := validateVersion3(obj, r); err == nil {
				t.Fatal("accepted a receipt §1.2a refuses")
			}
		})
	}
}

// sub on an array-valued member needs the raw value.
func (o *vObject) getArray(name string) vArray {
	v, _ := o.get(name)
	return v.(vArray)
}

func remove(names []string, name string) []string {
	out := names[:0]
	for _, n := range names {
		if n != name {
			out = append(out, n)
		}
	}
	return out
}

// An unknown version keeps its common members and is left for order 2.
func TestUnknownVersionIsUnsupportedNotMalformed(t *testing.T) {
	obj, _ := receipt3("acquisition", func(o *vObject) { o.set("receiptVersion", vString("4")) })
	r, err := receiptFrom(obj)
	if err != nil {
		t.Fatalf("an unknown version must decode its common members: %v", err)
	}
	if r.version != "4" {
		t.Fatalf("version %q", r.version)
	}
}

// The citation index reads a cited file's signature as written even when the
// canonical parser refuses the file for an unrelated member.
func TestTopLevelSignatureSurvivesAnOutOfDomainMember(t *testing.T) {
	sig, ok := topLevelSignature([]byte(`{"receiptVersion":"3","extra":1.0,"signature":"` + testSig3 + `"}`))
	if !ok || sig != testSig3 {
		t.Fatalf("got (%q, %v)", sig, ok)
	}
	if _, ok := topLevelSignature([]byte(`{"signature":"a","signature":"b"}`)); ok {
		t.Fatal("two top-level signatures are ambiguous and must not resolve")
	}
	if _, ok := topLevelSignature([]byte(`[1]`)); ok {
		t.Fatal("not an object")
	}
	if _, ok := topLevelSignature([]byte(`{"signature":1}`)); ok {
		t.Fatal("not a string")
	}
	// One complete object and nothing after it.
	for _, text := range []string{
		`{"extra":1.0,"signature":"` + testSig3 + `"} {}`,
		`{"extra":1.0,"signature":"` + testSig3 + `"} trailing`,
		`{"extra":1.0,"signature":"` + testSig3 + `"`,
		`{"extra":1.0,"signature":"` + testSig3 + `"}}`,
	} {
		if _, ok := topLevelSignature([]byte(text)); ok {
			t.Fatalf("resolved a signature from text that is not one complete object: %s", text)
		}
	}
}

func hexOf(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestDecisionCandidatesFollowTheByteRule(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "audit")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	// CRLF lines, an empty line, a double CR, and an unterminated final line.
	content := "{\"a\":1}\r\n\r\n{\"b\":2}\r\r\n{\"c\":3}"
	if err := os.WriteFile(filepath.Join(nested, "evaluations.jsonl"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "whole.json"), []byte(`{"whole":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{
		hexOf([]byte(`{"a":1}`)):        true, // CRLF line, CR stripped
		hexOf([]byte(`{"b":2}` + "\r")): true, // double CR: exactly one stripped
		hexOf([]byte(`{"c":3}`)):        true, // unterminated final line
		hexOf([]byte(content)):          true, // the .jsonl file as a whole
		hexOf([]byte(`{"whole":true}`)): true,
		hexOf([]byte(`{"b":2}`)):        true, // NOT a candidate: the line keeps one CR
		hexOf([]byte("")):               true, // NOT a candidate: empty pieces are skipped
	}
	found, present, err := decisionCandidates(dir, wanted, nil)
	if err != nil || !present {
		t.Fatalf("present=%v err=%v", present, err)
	}
	for _, want := range []string{hexOf([]byte(`{"a":1}`)), hexOf([]byte(`{"b":2}` + "\r")), hexOf([]byte(`{"c":3}`)), hexOf([]byte(content)), hexOf([]byte(`{"whole":true}`))} {
		if !found[want] {
			t.Errorf("candidate missing: %s", want)
		}
	}
	for _, not := range []string{hexOf([]byte(`{"b":2}`)), hexOf([]byte(""))} {
		if found[not] {
			t.Errorf("not a candidate but found: %s", not)
		}
	}
}

func TestDecisionCandidatesDirectoryOutcomes(t *testing.T) {
	if _, present, err := decisionCandidates("", nil, nil); present || err != nil {
		t.Fatalf("no directory given must be absent: present=%v err=%v", present, err)
	}
	if _, present, err := decisionCandidates(filepath.Join(t.TempDir(), "missing"), nil, nil); present || err != nil {
		t.Fatalf("a missing directory must be absent: present=%v err=%v", present, err)
	}
	empty := t.TempDir()
	if found, present, err := decisionCandidates(empty, map[string]bool{"x": true}, nil); !present || err != nil || len(found) != 0 {
		t.Fatalf("an empty directory is present with no candidates: present=%v err=%v found=%v", present, err, found)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := decisionCandidates(file, nil, nil); err == nil {
		t.Fatal("a regular file at the path must be no verdict")
	}
	if _, _, err := decisionCandidates(filepath.Join(file, "records"), nil, nil); err == nil {
		t.Fatal("an obstructing parent component must be no verdict")
	}
	if runtime.GOOS != "windows" {
		dir := t.TempDir()
		target := filepath.Join(t.TempDir(), "target.jsonl")
		if err := os.WriteFile(target, []byte(`{"linked":true}`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "link.jsonl")); err != nil {
			t.Skip("symlinks not available")
		}
		wanted := map[string]bool{hexOf([]byte(`{"linked":true}`)): true}
		found, _, err := decisionCandidates(dir, wanted, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 0 {
			t.Fatal("a symbolic link must not be followed")
		}
		unreadable := filepath.Join(t.TempDir(), "closed")
		if err := os.MkdirAll(unreadable, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(unreadable, 0o755) })
		if os.Geteuid() != 0 {
			if _, _, err := decisionCandidates(unreadable, nil, nil); err == nil {
				t.Fatal("an unreadable directory must be no verdict")
			}
		}
	}
}

// A mixed-version session with a hole in its sequence reports the hole and
// is not walked, so no chain finding follows (SPEC.md §1.4).
func TestMixedVersionsUnderABrokenSequenceReportOnlyTheSequence(t *testing.T) {
	// Built from the mixed-session vector with its head removed: the version
	// 2 receipt at index 1 alone is a sequence hole.
	var vec storeVector
	readJSON(t, corpusPath("v3", "stores", "v3-mixed-session-chain-broken.json"), &vec)
	delete(vec.Files, "receipts/s3/0.json")
	tmp, root, registryPath, _, err := materializeVector(vec)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)
	publicKey := mustHex(t, strings.TrimSpace(readFile(t, corpusPath("TEST-PUBLIC-KEY"))))
	rep, err := verifyWithRegistry(root, registryPath, vec.Authority, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	var statuses []string
	for _, f := range rep.Findings {
		statuses = append(statuses, f["status"].(string))
	}
	joined := strings.Join(statuses, ",")
	if !strings.Contains(joined, "sequence-broken") || strings.Contains(joined, "chain-broken") {
		t.Fatalf("want sequence-broken and no chain finding, got %s", joined)
	}
}

// The decision-record path is judged whether or not any action receipt needs
// it: a regular file at the path is present and unreadable evidence, which
// is no verdict (SPEC.md §4.1), even for an empty store.
func TestUnreadableDecisionRecordPathRefusesEvenWithoutActions(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	if err := os.MkdirAll(filepath.Join(store, "receipts"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	publicKey := mustHex(t, strings.TrimSpace(readFile(t, corpusPath("TEST-PUBLIC-KEY"))))
	if _, err := verifyWithRegistryAndRecords(store, filepath.Join(dir, "registry.jsonl"), "gateway:test", file, publicKey); err == nil {
		t.Fatal("a regular file as the decision-record path must be no verdict, action receipts or not")
	}
	if rep, err := verifyWithRegistryAndRecords(store, filepath.Join(dir, "registry.jsonl"), "gateway:test", filepath.Join(dir, "absent"), publicKey); err != nil || !rep.OK {
		t.Fatalf("an absent directory over an empty store is a clean verdict: %v %v", err, rep)
	}
}

// A candidate is read for its cites member and for nothing else (SPEC.md §4
// step 7): the object as JSON, floats and all, the member by the canonical
// parser, exact names, once.
func TestRecordCitationsReadOneMemberAndNothingElse(t *testing.T) {
	sig := strings.Repeat("ab", 64)
	for name, tc := range map[string]struct {
		data      string
		cited     bool
		malformed bool
		count     int
	}{
		"not JSON":                     {"not a record\n", false, false, 0},
		"an array":                     {"[]", false, false, 0},
		"two texts":                    {`{"cites":[]} {}`, false, false, 0},
		"no cites":                     {`{"recordVersion":"1","inputs":{"facts":{"amount":12.5}}}`, false, false, 0},
		"cites resolved beside floats": {`{"inputs":{"facts":{"amount":12.5}},"cites":[{"sessionId":"s","callIndex":1,"signature":"` + sig + `"}]}`, true, false, 1},
		"cites empty":                  {`{"cites":[]}`, true, false, 0},
		"cites not an array":           {`{"cites":{}}`, true, true, 0},
		"cites twice":                  {`{"cites":[{"sessionId":"s","callIndex":1,"signature":"` + sig + `"}],"cites":[]}`, true, true, 0},
		"a member by another case":     {`{"cites":[{"SessionId":"s","callIndex":1,"signature":"` + sig + `"}]}`, true, true, 0},
		"a member twice in a citation": {`{"cites":[{"sessionId":"s","sessionId":"t","callIndex":1,"signature":"` + sig + `"}]}`, true, true, 0},
		"an index as a float":          {`{"cites":[{"sessionId":"s","callIndex":1.0,"signature":"` + sig + `"}]}`, true, true, 0},
		"an index as a string":         {`{"cites":[{"sessionId":"s","callIndex":"1","signature":"` + sig + `"}]}`, true, true, 0},
		"a signature not 128 hex":      {`{"cites":[{"sessionId":"s","callIndex":1,"signature":"x"}]}`, true, true, 0},
		"a session that is not flat":   {`{"cites":[{"sessionId":"../s","callIndex":1,"signature":"` + sig + `"}]}`, true, true, 0},
	} {
		cites, cited, malformed := recordCitations([]byte(tc.data))
		if cited != tc.cited || malformed != tc.malformed || len(cites) != tc.count {
			t.Errorf("%s: cited=%v malformed=%v cites=%d, want %v %v %d", name, cited, malformed, len(cites), tc.cited, tc.malformed, tc.count)
		}
	}
}
