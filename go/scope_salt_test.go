package main

// A seal of version 3 names its scope over the session's scope salt
// (docs/adr/0042-a-seal-names-its-scope-over-a-salt-the-registry-does-not-hold.md):
// the salt is in every receipt of the session and in no registry line, so a
// reader of the registry alone cannot test a guessed scope identifier against
// a seal, two sessions of one scope are sealed over unrelated digests, and a
// verifier holding the receipts holds the seal to them as before.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scopeSaltsOf are the scopeSalt members of a session's receipt files, by
// file name, "" for one holding none.
func scopeSaltsOf(t *testing.T, storeRoot, session string) map[string]string {
	t.Helper()
	dir := filepath.Join(storeRoot, "receipts", session)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		var r map[string]any
		if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, e.Name()))), &r); err != nil {
			t.Fatal(err)
		}
		salt, _ := r["scopeSalt"].(string)
		out[e.Name()] = salt
	}
	return out
}

// dropMember takes the member name out of o.
func dropMember(o *vObject, name string) {
	o.names = remove(o.names, name)
	delete(o.byName, name)
}

// Two sessions of one scope identifier carry a scope salt each, the same in
// every receipt of a session and another in each session, and their seals
// name the scope by digests that are unrelated: neither is the digest of
// version 2 a reader of the registry computes from a guessed identifier and
// the session's id, and the registry holds neither salt. Both verify.
func TestTwoSessionsOfAScopeAreSealedOverUnrelatedDigests(t *testing.T) {
	service, server, _ := scopedService(t)
	scoped := `"scope":` + jsonText(t, testScope) + `,`
	for _, session := range []string{"s-1", "s-1", "s-2", "s-2"} {
		if code, out := post(t, server, "/acquire", `{"session":"`+session+`","source":"scoped",`+scoped+`"arguments":{"q":"a"}}`); code != http.StatusOK {
			t.Fatalf("%s: %d %v", session, code, out)
		}
	}
	for _, session := range []string{"s-1", "s-2"} {
		if code, out := post(t, server, "/seal", `{"session":"`+session+`"}`); code != http.StatusOK {
			t.Fatalf("seal %s: %d %v", session, code, out)
		}
	}
	salts := map[string]string{}
	for _, session := range []string{"s-1", "s-2"} {
		held := scopeSaltsOf(t, service.storeRoot, session)
		if len(held) != 2 || held["0.json"] != held["1.json"] || !isScopeSalt(held["0.json"]) {
			t.Fatalf("session %s's receipts carry %v", session, held)
		}
		salts[session] = held["0.json"]
	}
	if salts["s-1"] == salts["s-2"] {
		t.Fatal("two sessions carry one scope salt")
	}
	registry := readFile(t, service.regPath)
	walk, err := engineWalk([]byte(registry), service.publicKey)
	if err != nil || len(walk.seals) != 2 {
		t.Fatalf("the registry: %v\n%s", err, registry)
	}
	one, two := walk.seals["s-1"], walk.seals["s-2"]
	if !one.salted || !two.salted || one.scopeDigest == two.scopeDigest {
		t.Fatalf("the seals: %+v %+v", one, two)
	}
	for session, s := range map[string]seal{"s-1": one, "s-2": two} {
		// what a reader of the registry alone can compute, from the session's
		// id and the right guess, is not what the seal names
		if s.scopeDigest == sealScopeDigest(session, testScope) || s.scopeDigest == saltedScopeDigest(session, testScope, "") {
			t.Fatalf("session %s's seal names a digest a guess tests: %s", session, s.scopeDigest)
		}
		if s.scopeDigest != saltedScopeDigest(session, testScope, salts[session]) {
			t.Fatalf("session %s's seal is not over its receipts' salt", session)
		}
		if strings.Contains(registry, salts[session]) {
			t.Fatalf("the registry holds session %s's scope salt", session)
		}
	}
	if rep := scopedVerdict(t, service); !rep.OK || len(statusesOf(rep)) != 0 {
		t.Fatalf("both sealed sessions verify: %v", rep.Findings)
	}
}

// A receipt's scopeSalt is under its signature: changed after signing it is
// a signature mismatch. Signed again in a form not its own -- not 64
// lowercase hexadecimal characters, or with no scope beside it -- the
// receipt is malformed.
func TestAScopeSaltIsSignedAndOfItsForm(t *testing.T) {
	service, server, _ := scopedService(t)
	if code, out := post(t, server, "/acquire", `{"session":"s-1","source":"scoped","scope":`+jsonText(t, testScope)+`,"arguments":{"q":"a"}}`); code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, out)
	}
	path := filepath.Join(service.storeRoot, "receipts", "s-1", "0.json")
	original := readFile(t, path)
	salt := service.sessions["s-1"].scopeSalt
	priv := ed25519.NewKeyFromSeed(testSeed)
	resigned := func(change func(obj *vObject)) string {
		v, err := parseJSON([]byte(original))
		if err != nil {
			t.Fatal(err)
		}
		obj := v.(*vObject)
		change(obj)
		dropMember(obj, "signature")
		obj.set("signature", vString(hex.EncodeToString(ed25519.Sign(priv, signedOver(receiptContext3, obj)))))
		return string(canon(obj))
	}
	for _, tc := range []struct{ name, file, status string }{
		{"the salt changed after signing", strings.Replace(original, salt, strings.Repeat("0", 64), 1), "signature-mismatch"},
		{"the salt in capitals", resigned(func(o *vObject) { o.set("scopeSalt", vString(strings.ToUpper(salt))) }), "malformed"},
		{"the salt a byte short", resigned(func(o *vObject) { o.set("scopeSalt", vString(salt[2:])) }), "malformed"},
		{"the salt with no scope", resigned(func(o *vObject) { dropMember(o, "scope") }), "malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.file == original {
				t.Fatal("the file is unchanged")
			}
			if err := os.WriteFile(path, []byte(tc.file), 0o600); err != nil {
				t.Fatal(err)
			}
			rep := scopedVerdict(t, service)
			if len(rep.Findings) < 1 || rep.Findings[0]["status"] != tc.status {
				t.Fatalf("%v", rep.Findings)
			}
		})
	}
}

// A session of a scope left open is sealed after the interruption over the
// salt its receipts carry, with a seal of version 3 of §3c's kind, which
// names neither the identifier nor the salt, and verifies.
func TestASessionLeftOpenIsSealedOverItsSalt(t *testing.T) {
	service, server, _ := scopedService(t)
	for range 2 {
		if code, out := post(t, server, "/acquire", `{"session":"left-open","source":"scoped","scope":`+jsonText(t, testScope)+`,"arguments":{"q":"a"}}`); code != http.StatusOK {
			t.Fatalf("acquire: %d %v", code, out)
		}
	}
	salt := service.sessions["left-open"].scopeSalt
	seedPath := writeSeedFile(t, t.TempDir(), testSeed)
	var stdout, stderr bytes.Buffer
	if code := cmdSealOpenAt([]string{"--store", service.storeRoot, "--seed", seedPath, "--registry", service.regPath, "--authority", service.authority, "--session", "left-open"},
		&stdout, &stderr, fixedStamp("2026-11-18T00:00:00Z")); code != 0 {
		t.Fatalf("seal-open: %d %s %s", code, stdout.String(), stderr.String())
	}
	var line map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &line); err != nil {
		t.Fatalf("%v: %s", err, stdout.String())
	}
	if len(line) != 10 || line["scopeDigest"] != saltedScopeDigest("left-open", testScope, salt) || line["sealVersion"] != "3" || line["kind"] != sealKindInterruption ||
		strings.Contains(stdout.String(), testScope) || strings.Contains(stdout.String(), salt) {
		t.Fatalf("the seal after an interruption: %s", stdout.String())
	}
	rep := scopedVerdict(t, service)
	if !rep.OK || len(statusesOf(rep)) != 0 || len(rep.Observations) != 1 || rep.Observations[0]["observation"] != "sealed-after-interruption" {
		t.Fatalf("the session sealed: ok %v %v %v", rep.OK, rep.Findings, rep.Observations)
	}
}

// A session of a scope that holds no receipt is sealed in §3's form: no
// receipt carries a salt for a digest to be taken over.
func TestASessionOfAScopeHoldingNoReceiptIsSealedInTheFirstForm(t *testing.T) {
	service, _, _ := scopedService(t)
	service.sessions["empty"] = &sessionState{scope: testScope, created: true}
	record, err := service.sealSession("empty")
	if err != nil {
		t.Fatal(err)
	}
	if len(record) != 5 || record["finalCount"] != float64(0) {
		t.Fatalf("the seal of an empty session: %v", record)
	}
}

// A session-removal record of a session sealed over a salt carries the salt,
// and names the session; signed again over another salt, or with none, it
// names nothing, and the session removed is sealed-session-missing.
func TestASessionRemovalRecordNamesASaltedSealByItsSalt(t *testing.T) {
	g, seedPath := scopeStore(t)
	salt := g.sessions["a1"].scopeSalt
	if code, stdout, stderr := removeScopeOn(t, g, seedPath, "--scope", testScope, "--by", "operator-1"); code != 0 {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	file := readFile(t, filepath.Join(g.storeRoot, removalsFile))
	lines := strings.Split(strings.TrimSuffix(file, "\n"), "\n")
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatal(err)
	}
	if len(record) != 10 || record["scopeSalt"] != salt || record["kind"] != sessionRemovalKind {
		t.Fatalf("the session-removal record: %s", lines[0])
	}
	if ok, findings, observations := scopeVerdict(t, g); !ok || len(findings) != 0 || strings.Join(observations, ",") != "a1 "+observationSessionRemoved {
		t.Fatalf("the verdict: %v %v %v", ok, findings, observations)
	}
	priv := ed25519.NewKeyFromSeed(testSeed)
	for _, tc := range []struct {
		name   string
		change func(obj *vObject)
	}{
		{"another salt", func(o *vObject) { o.set("scopeSalt", vString(strings.Repeat("ab", 32))) }},
		{"no salt", func(o *vObject) { dropMember(o, "scopeSalt") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := parseJSON([]byte(lines[0]))
			if err != nil {
				t.Fatal(err)
			}
			obj := v.(*vObject)
			tc.change(obj)
			dropMember(obj, "signature")
			obj.set("signature", vString(hex.EncodeToString(ed25519.Sign(priv, recordSigningInput(sessionRemovalContext, obj)))))
			if err := os.WriteFile(filepath.Join(g.storeRoot, removalsFile), []byte(string(canon(obj))+"\n"+lines[1]+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if ok, findings, _ := scopeVerdict(t, g); ok || strings.Join(findings, ",") != "a1 sealed-session-missing" {
				t.Fatalf("the verdict: %v %v", ok, findings)
			}
		})
	}
}
