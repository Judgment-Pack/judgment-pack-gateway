package main

// A receipt names the witness its trail is registered with (ADR-0014;
// witness_named.go): the member's form, as the verifier holds a receipt to
// it; the configuration that names a witness for a trail, and its
// refusals; the member on an acquisition whose request names a configured
// trail and on an action whose record is of one, signed with the rest; and
// receipts of trails with no witness named, which are the receipts minted
// before the member existed.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// namedTrail and otherTrail are trails of these tests; witnessKey is a
// witness's key, the base point times 1, which the corpus names too.
const (
	namedTrail = "7a11c0de5eed0f0e7a11c0de5eed0f0e"
	otherTrail = "0f0e5eed7a11c0de0f0e5eed7a11c0de"
	witnessKey = "5866666666666666666666666666666666666666666666666666666666666666"
	// witnessKeyTwo is the base point times 2.
	witnessKeyTwo = "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022"
)

func TestWitnessOriginForm(t *testing.T) {
	for _, origin := range []string{
		"https://witness.example:443",
		"https://w-1.witness.example:8443",
		"https://192.0.2.7:443",
		"https://[2001:db8::7]:443",
		"https://localhost:1",
		"https://a:65535",
		"http://127.0.0.1:8080",
		"http://127.255.0.9:80",
		"http://[::1]:8080",
		"https://" + strings.Repeat("a", 2048-len("https://:443")) + ":443",
	} {
		if !isWitnessOrigin(origin) {
			t.Errorf("refused an origin of its form: %.80s", origin)
		}
	}
	for _, origin := range []string{
		"",
		"https://witness.example",             // no port
		"https://witness.example:",            // an empty port
		"https://witness.example:0443",        // a leading zero
		"https://witness.example:0",           // no port at all
		"https://witness.example:65536",       // past the ports
		"https://witness.example:443/",        // something after the port
		"https://witness.example:443/witness", // a path
		"https://witness.example:443?x=1",     // a query
		"https://Witness.example:443",         // a host not in lowercase
		"https://witness..example:443",        // an empty label
		"https://.witness.example:443",        // an empty label first
		"https://user@witness.example:443",    // a user
		"https://witness_example:443",         // a character no host has
		"https://[2001:DB8::7]:443",           // IPv6 not in lowercase
		"https://[2001:db8::7%25eth0]:443",    // a zone
		"https://[::ffff:1.2.3.4]:443",        // IPv6 with dots
		"https://[1::2::3]:443",               // no address
		"https://2001:db8::7:443",             // IPv6 out of brackets
		"http://witness.example:80",           // http off loopback
		"http://localhost:8080",               // a name, not a loopback address written as one
		"http://10.0.0.1:8080",                // not loopback
		"http://127.0.0.01:8080",              // a leading zero
		"http://127.0.0.256:8080",             // not an address
		"http://[0:0:0:0:0:0:0:1]:8080",       // loopback, not written as [::1]
		"ftp://witness.example:21",            // another scheme
		"HTTPS://witness.example:443",         // a scheme not in lowercase
		" https://witness.example:443",        // space before
		"https://witness.example:443 ",        // space after
		"https://witness.example:443\n",       // a newline after
		"https://" + strings.Repeat("a", 2049-len("https://:443")) + ":443", // past 2048 characters
	} {
		if isWitnessOrigin(origin) {
			t.Errorf("took an origin out of its form: %.80s", origin)
		}
	}
}

// engineWithWitnessedBy is an engine configuration carrying witnessedBy
// at the version given; nothing in it is resolved by the parse.
func engineWithWitnessedBy(version, witnessedBy string) string {
	return `{"engineVersion":"` + version + `","authority":"gateway:test","seed":"/srv/engine/gateway.seed","store":"/srv/engine/store",` +
		`"registry":"/srv/engine/registry.jsonl","decisionRecords":"/srv/engine/decisions","listen":"127.0.0.1:8787","catalog":"/srv/engine/catalog",` +
		`"witnessedBy":` + witnessedBy + `,"platforms":{}}`
}

// The configuration that names a witness for a trail: at version 7, an
// object keyed by trail identity, each {origin, publicKey}, held to its
// form, its key to the key rule; a trail given twice is a name given twice.
func TestWitnessedByConfiguration(t *testing.T) {
	entry := func(origin, key string) string {
		return `{"` + namedTrail + `":{"origin":"` + origin + `","publicKey":"` + key + `"}}`
	}
	good := entry("https://witness.example:443", witnessKey)
	cfg, err := parseEngineConfig([]byte(engineWithWitnessedBy("7", good)))
	if err != nil {
		t.Fatal(err)
	}
	w := cfg.witnessedBy[namedTrail]
	if len(cfg.witnessedBy) != 1 || w.origin != "https://witness.example:443" || hex.EncodeToString(w.publicKey) != witnessKey || w.keyID != keyIDFor(mustHex(t, witnessKey)) {
		t.Fatalf("witnessedBy read as %+v", cfg.witnessedBy)
	}
	smallOrder := "0100000000000000000000000000000000000000000000000000000000000000"
	for _, tc := range []struct{ name, text, want string }{
		{"version 6", engineWithWitnessedBy("6", good), "witnessedBy is a version-7 member; engineVersion 6 has no witnessedBy"},
		{"not an object", engineWithWitnessedBy("7", `[]`), "witnessedBy must be an object keyed by trail identity"},
		{"a trail out of form", engineWithWitnessedBy("7", `{"`+strings.ToUpper(namedTrail)+`":{"origin":"https://witness.example:443","publicKey":"`+witnessKey+`"}}`), "names a trail that is not 32 lowercase hexadecimal characters"},
		{"an entry not an object", engineWithWitnessedBy("7", `{"`+namedTrail+`":"https://witness.example:443"}`), "must be an object of origin and publicKey"},
		{"a member missing", engineWithWitnessedBy("7", `{"`+namedTrail+`":{"origin":"https://witness.example:443"}}`), "publicKey"},
		{"a member unknown", engineWithWitnessedBy("7", `{"`+namedTrail+`":{"origin":"https://witness.example:443","publicKey":"`+witnessKey+`","token":"x"}}`), "token"},
		{"an origin with a path", engineWithWitnessedBy("7", entry("https://witness.example:443/w", witnessKey)), "origin is not https://<host>:<port>"},
		{"http off loopback", engineWithWitnessedBy("7", entry("http://witness.example:80", witnessKey)), "origin is not https://<host>:<port>"},
		{"a key in upper case", engineWithWitnessedBy("7", entry("https://witness.example:443", strings.ToUpper(witnessKeyTwo))), "publicKey is not a key of 64 lowercase hexadecimal characters"},
		{"a key of small order", engineWithWitnessedBy("7", entry("https://witness.example:443", smallOrder)), "publicKey names a key that is of small order"},
		{"a trail given twice", engineWithWitnessedBy("7", `{"`+namedTrail+`":{"origin":"https://a.example:443","publicKey":"`+witnessKey+`"},"`+namedTrail+`":{"origin":"https://b.example:443","publicKey":"`+witnessKey+`"}}`), "duplicate"},
	} {
		if _, err := parseEngineConfig([]byte(tc.text)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

// --witnessed-by, for gateway serve without a configuration: repeatable, a
// trail once, held to the same form, and only for version 3 receipts.
func TestWitnessedByFlag(t *testing.T) {
	base := []string{"store", "seed", "gateway:test", "registry.jsonl"}
	flag := func(args ...string) (serveOptions, string, bool) {
		return parseServeOptions(append(append([]string(nil), base...), args...))
	}
	opts, msg, ok := flag("--witnessed-by", namedTrail+"=https://witness.example:443,"+witnessKey, "--witnessed-by", otherTrail+"=http://127.0.0.1:8443,"+witnessKey)
	if !ok || len(opts.witnessedBy) != 2 || opts.witnessedBy[otherTrail].origin != "http://127.0.0.1:8443" {
		t.Fatalf("two trails: %v %s", opts.witnessedBy, msg)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--witnessed-by"}, "requires a following TRAIL=ORIGIN,PUBLICKEY value"},
		{[]string{"--witnessed-by", namedTrail + "=https://witness.example:443"}, "expects TRAIL=ORIGIN,PUBLICKEY"},
		{[]string{"--witnessed-by", "https://witness.example:443," + witnessKey}, "expects TRAIL=ORIGIN,PUBLICKEY"},
		{[]string{"--witnessed-by", "abc=https://witness.example:443," + witnessKey}, "names a trail that is not 32 lowercase hexadecimal characters"},
		{[]string{"--witnessed-by", namedTrail + "=https://witness.example," + witnessKey}, "origin is not"},
		{[]string{"--witnessed-by", namedTrail + "=https://witness.example:443,abc"}, "publicKey is not a key"},
		{[]string{"--witnessed-by", namedTrail + "=https://a.example:443," + witnessKey, "--witnessed-by", namedTrail + "=https://b.example:443," + witnessKey}, "names trail " + namedTrail + " twice"},
		{[]string{"--receipt-version", "2", "--witnessed-by", namedTrail + "=https://witness.example:443," + witnessKey}, "needs --receipt-version 3"},
	} {
		if _, msg, ok := flag(tc.args...); ok || !strings.Contains(msg, tc.want) {
			t.Errorf("%v: %v %q, want %q", tc.args, ok, msg, tc.want)
		}
	}
}

// A gateway refuses to name its own key as a trail's witness, by the key's
// bytes -- whatever path or spelling gave it -- before anything is made: a
// gateway whose key the operator can use is no witness against the
// operator.
func TestWitnessedByRefusesTheGatewaysOwnKey(t *testing.T) {
	own := ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)
	root := t.TempDir()
	opts := serveOptions{sources: map[string]sourceSpec{}, maxSourceOutput: defaultMaxSourceOutput, receiptVersion: receiptVersion3}
	// spelled as the configuration spells it, then read
	_, named, err := parseWitnessedByFlag(otherTrail + "=https://witness.example:443," + hex.EncodeToString(own))
	if err != nil {
		t.Fatal(err)
	}
	other, _ := namedWitnessOf(namedTrail, "https://witness.example:443", witnessKey, "test")
	opts.witnessedBy = map[string]namedWitness{namedTrail: other, otherTrail: named}
	_, err = buildService(filepath.Join(root, "store"), testSeed, "gateway:test", filepath.Join(root, "registry.jsonl"), opts)
	if err == nil || !strings.Contains(err.Error(), "the witness named for trail "+otherTrail+" has this gateway's own key") {
		t.Fatalf("its own key named: %v", err)
	}
	for _, made := range []string{"store", "registry.jsonl"} {
		if _, err := os.Stat(filepath.Join(root, made)); err == nil {
			t.Fatalf("the %s was made before the refusal", made)
		}
	}
	delete(opts.witnessedBy, otherTrail)
	if _, err := buildService(filepath.Join(root, "store"), testSeed, "gateway:test", filepath.Join(root, "registry.jsonl"), opts); err != nil {
		t.Fatalf("another key: %v", err)
	}
	opts.receiptVersion = receiptVersion
	if _, err := buildService(filepath.Join(root, "store2"), testSeed, "gateway:test", filepath.Join(root, "registry2.jsonl"), opts); err == nil || !strings.Contains(err.Error(), "needs receipt version 3") {
		t.Fatalf("version 2 receipts: %v", err)
	}
}

// namingService is a test service that names witnessKey's witness for
// namedTrail.
func namingService(t *testing.T) (*gatewayService, *httptest.Server) {
	t.Helper()
	service, server := testService(t)
	named, err := namedWitnessOf(namedTrail, "https://witness.example:443", witnessKey, "test")
	if err != nil {
		t.Fatal(err)
	}
	service.witnessedBy = map[string]namedWitness{namedTrail: named}
	return service, server
}

// receiptMembers are a receipt's member names, sorted.
func receiptMembers(receipt map[string]any) []string {
	var names []string
	for name := range receipt {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// An acquisition whose request names a trail the configuration names a
// witness for carries the witness, signed with the rest; a request naming
// a trail with no witness configured, or a trail out of form, is refused
// before the source runs; one naming none carries none.
func TestAcquisitionNamesTheWitnessOfTheTrailItNames(t *testing.T) {
	service, server := namingService(t)
	code, out := post(t, server, "/acquire", `{"session":"w-1","source":"screening","arguments":{"q":"acme"},"trail":"`+namedTrail+`"}`)
	if code != http.StatusOK {
		t.Fatalf("acquire naming a trail: %d %v", code, out)
	}
	receipt := out["receipt"].(map[string]any)
	member, _ := receipt["witness"].(map[string]any)
	if member == nil || member["origin"] != "https://witness.example:443" || member["keyId"] != keyIDFor(mustHex(t, witnessKey)) || member["trail"] != namedTrail || len(member) != 3 {
		t.Fatalf("the receipt's witness: %v", receipt["witness"])
	}
	// nothing else of the witness, or of the request, is recorded
	text, _ := json.Marshal(receipt)
	if strings.Contains(string(text), witnessKey) {
		t.Fatal("the receipt carries the witness's key, where it names it by keyId")
	}
	started := service.started.Load()
	for _, tc := range []struct{ name, trail, want string }{
		{"a trail no witness is named for", `"` + otherTrail + `"`, "names no witness for the trail"},
		{"a trail in upper case", `"` + strings.ToUpper(namedTrail) + `"`, "trail must be a trail identity"},
		{"a trail of another length", `"` + namedTrail[:31] + `"`, "trail must be a trail identity"},
		{"null", `null`, "trail must be a trail identity"},
		{"a number", `7`, "trail must be a trail identity"},
		{"an object naming a witness", `{"origin":"https://evil.example:443","keyId":"` + strings.Repeat("a", 32) + `"}`, "trail must be a trail identity"},
	} {
		code, out := post(t, server, "/acquire", `{"session":"w-1","source":"screening","arguments":{"q":"acme"},"trail":`+tc.trail+`}`)
		if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(out["error"]), tc.want) {
			t.Errorf("%s: %d %v", tc.name, code, out)
		}
	}
	if code, out := post(t, server, "/acquire", `{"session":"w-1","source":"screening","arguments":{"q":"acme"},"witness":{"origin":"https://evil.example:443"}}`); code != http.StatusBadRequest {
		t.Errorf("a request naming a witness: %d %v", code, out)
	}
	if service.started.Load() != started {
		t.Fatal("a source ran for a refused trail")
	}
	code, plain := post(t, server, "/acquire", `{"session":"w-1","source":"screening","arguments":{"q":"acme"}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire naming no trail: %d %v", code, plain)
	}
	if _, named := plain["receipt"].(map[string]any)["witness"]; named {
		t.Fatal("a receipt whose request named no trail names a witness")
	}
	// The store verifies, and its report names the one witness, for the
	// trail, once: when it was named is the receipt's servedAt.
	if code, sealed := post(t, server, "/seal", `{"session":"w-1"}`); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, sealed)
	}
	rep, err := verifyWithRegistry(service.storeRoot, service.regPath, service.authority, service.publicKey)
	if err != nil || !rep.OK {
		t.Fatalf("verify: %v %+v", err, rep)
	}
	want := witnessTriple{Trail: namedTrail, Origin: "https://witness.example:443", KeyID: keyIDFor(mustHex(t, witnessKey))}
	if len(rep.Witnesses) != 1 || rep.Witnesses[0] != want || len(rep.namedAt[want]) != 1 || rep.namedAt[want][0] != receipt["servedAt"] {
		t.Fatalf("the report's witnesses: %+v, named at %v", rep.Witnesses, rep.namedAt)
	}
}

// The member is inside the signed bytes: a receipt minted with it verifies,
// and the same receipt with the member changed or taken out is
// signature-mismatch, naming nothing.
func TestTheWitnessMemberIsSigned(t *testing.T) {
	service, server := namingService(t)
	if code, out := post(t, server, "/acquire", `{"session":"w-2","source":"screening","arguments":{},"trail":"`+namedTrail+`"}`); code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, out)
	}
	if code, out := post(t, server, "/seal", `{"session":"w-2"}`); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, out)
	}
	path := filepath.Join(service.storeRoot, "receipts", "w-2", "0.json")
	minted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	verdict := func() (bool, string, int) {
		rep, err := verifyWithRegistry(service.storeRoot, service.regPath, service.authority, service.publicKey)
		if err != nil {
			t.Fatal(err)
		}
		return rep.OK, fmt.Sprint(rep.Findings[0]["status"]), len(rep.Witnesses)
	}
	if ok, status, named := verdict(); !ok || status != "ok" || named != 1 {
		t.Fatalf("the receipt as minted: ok %v, %s, %d witnesses", ok, status, named)
	}
	for _, tc := range []struct{ name, from, to string }{
		{"another origin", `"origin":"https://witness.example:443"`, `"origin":"https://elsewhere.example:443"`},
		{"another trail", `"trail":"` + namedTrail + `"`, `"trail":"` + otherTrail + `"`},
		{"the member taken out", `,"witness":{"keyId":"` + keyIDFor(mustHex(t, witnessKey)) + `","origin":"https://witness.example:443","trail":"` + namedTrail + `"}`, ``},
	} {
		if !strings.Contains(string(minted), tc.from) {
			t.Fatalf("%s: the receipt holds no %s", tc.name, tc.from)
		}
		if err := os.WriteFile(path, []byte(strings.Replace(string(minted), tc.from, tc.to, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		if ok, status, named := verdict(); ok || status != "signature-mismatch" || named != 0 {
			t.Errorf("%s: ok %v, %s, %d witnesses", tc.name, ok, status, named)
		}
	}
}

// An action carries the witness named for the trail of the record it was
// found on, read from the record's bytes, whatever its tool's policy: a
// record of a trail with no witness named, a record with no trail, and a
// record that is no runtime evaluation record give none.
func TestActionNamesTheWitnessOfItsRecordsTrail(t *testing.T) {
	service, server := namingService(t)
	service.sources["tickets/write"] = sourceSpec{argv: []string{os.Args[0], "--tools=update_ticket"}, env: helperEnv, shape: "mcp", tools: []string{"update_ticket"}, endpoint: "https://mcp.example/"}
	records := filepath.Join(t.TempDir(), "decisions")
	if err := os.MkdirAll(records, 0o700); err != nil {
		t.Fatal(err)
	}
	service.decisionRecords = records
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	env, _ := goodEnvelope()
	t.Setenv(envSourceEnvelope, envelopeText(t, env))
	code, first := authed(t, server, "/acquire", `{"session":"act-p","source":"screening","arguments":{"q":"acme"},"trail":"`+namedTrail+`"}`, token)
	if code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, first)
	}
	signature := first["receipt"].(map[string]any)["signature"].(string)
	var lines []string
	place := func(record string) string {
		lines = append(lines, record)
		if err := os.WriteFile(filepath.Join(records, "evaluations.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return "sha256:" + hexOf([]byte(record))
	}
	act := func(record string) map[string]any {
		t.Helper()
		body := `{"session":"act-p","platform":"tickets","tool":"update_ticket","arguments":{"id":"Q-7"},` +
			`"decision":{"recordDigest":"` + place(record) + `","packDigest":"` + packA + `"},` +
			`"cites":[{"sessionId":"act-p","callIndex":0,"signature":"` + signature + `"}]}`
		code, acted := authed(t, server, "/act", body, token)
		if code != http.StatusOK {
			t.Fatalf("act: %d %v", code, acted)
		}
		return acted["receipt"].(map[string]any)
	}
	chained := func(trail string) string {
		return runtimeLine(t, signature, `{"recordVersion":"1",`, `{"recordVersion":"1","trail":"`+trail+`","sequence":2,"previous":"sha256:`+strings.Repeat("0", 64)+`",`)
	}
	named := act(chained(namedTrail))
	member, _ := named["witness"].(map[string]any)
	if member == nil || member["trail"] != namedTrail || member["origin"] != "https://witness.example:443" {
		t.Fatalf("an action on a record of the trail: %v", named["witness"])
	}
	for name, record := range map[string]string{
		"a record of a trail with no witness named":     chained(otherTrail),
		"a record with no trail":                        runtimeLine(t, signature),
		"a record whose trail is not of its form":       chained(strings.ToUpper(namedTrail)),
		"a record that is no runtime evaluation record": runtimeLine(t, signature, `"kind":"evaluation"`, `"kind":"graph-composite"`, `{"recordVersion":"1",`, `{"recordVersion":"1","trail":"`+namedTrail+`",`),
	} {
		if receipt := act(record); receipt["witness"] != nil {
			t.Errorf("%s: the action names %v", name, receipt["witness"])
		}
	}
	// The store and the records verify: the witness named on the action is
	// the record's trail's, and the report names it once, both receipts
	// naming the same.
	if code, out := authed(t, server, "/seal", `{"session":"act-p"}`, token); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, out)
	}
	rep, err := verifyWithRegistryAndRecords(service.storeRoot, service.regPath, service.authority, records, service.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if f["status"] != "ok" {
			t.Fatalf("a finding: %v", f)
		}
	}
	if len(rep.Witnesses) != 1 || rep.Witnesses[0].Trail != namedTrail {
		t.Fatalf("the report's witnesses: %+v", rep.Witnesses)
	}
}

// The verifier holds an action's witness to its record's trail: a record of
// another trail, or of none, is decision-trail-mismatch beside the
// receipt's ok; a record that is not compared is not held to it.
func TestVerifyHoldsAnActionsWitnessToItsRecordsTrail(t *testing.T) {
	for _, name := range []string{"v3-witness-named", "v3-witness-decision-trail-mismatch"} {
		vector := readStoreVector(t, name)
		root, storeRoot, registryPath, records, err := materializeVector(vector)
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(root)
		rep, err := verifyWithRegistryAndRecords(storeRoot, registryPath, vector.Authority, records, mustHex(t, strings.TrimSpace(readFile(t, corpusPath("TEST-PUBLIC-KEY")))))
		if err != nil {
			t.Fatal(err)
		}
		mismatched := 0
		for _, f := range rep.Findings {
			if f["status"] == "decision-trail-mismatch" {
				mismatched++
			}
		}
		if want := map[string]int{"v3-witness-named": 0, "v3-witness-decision-trail-mismatch": 1}[name]; mismatched != want || len(rep.Witnesses) != 1 {
			t.Errorf("%s: %d decision-trail-mismatch, %d witnesses", name, mismatched, len(rep.Witnesses))
		}
	}
}

func readStoreVector(t *testing.T, name string) storeVector {
	t.Helper()
	var vector storeVector
	if err := decodeVectorFile([]byte(readFile(t, corpusPath("v3", "stores", name+".json"))), &vector, false); err != nil {
		t.Fatal(err)
	}
	return vector
}

// Receipts of trails with no witness named are the receipts minted before
// the member existed, byte for byte: every version 3 receipt of the corpus
// that names no witness, minted again by this gateway's stamp under the
// test seed through a gateway that names a witness for another trail, with
// no trail and with a trail it names none for, is the file the corpus
// holds.
func TestReceiptsOfTrailsWithNoWitnessAreTodays(t *testing.T) {
	seed := mustHex(t, strings.TrimSpace(readFile(t, corpusPath("TEST-SEED"))))
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	named, _ := namedWitnessOf(namedTrail, "https://witness.example:443", witnessKey, "test")
	g := &gatewayService{witnessedBy: map[string]namedWitness{namedTrail: named}}
	paths, err := filepath.Glob(corpusPath("v3", "stores", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	compared := 0
	for _, path := range paths {
		var vector storeVector
		if err := decodeVectorFile([]byte(readFile(t, path)), &vector, false); err != nil {
			t.Fatal(err)
		}
		for file, text := range vector.Files {
			if !strings.HasPrefix(file, "receipts/") {
				continue
			}
			v, err := parseJSON([]byte(text))
			obj, isObject := v.(*vObject)
			if err != nil || !isObject {
				continue
			}
			r, err := receiptFrom(obj)
			if err != nil || r.version != receiptVersion3 || r.witness != nil || r.keyID != keyIDFor(public) {
				continue
			}
			sig, _ := hex.DecodeString(r.signature)
			if !ed25519.Verify(public, r.signingInput(), sig) {
				continue
			}
			for _, trail := range []string{"", otherTrail} {
				core := newObject()
				for _, name := range obj.names {
					if name != "signature" && name != "keyId" {
						member, _ := obj.get(name)
						core.set(name, member)
					}
				}
				if member := g.witnessMember(trail); member != nil {
					core.set("witness", member)
				}
				st, err := newStore(t.TempDir(), seed, vector.Authority)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := st.stamp(core); err != nil {
					t.Fatal(err)
				}
				written, err := os.ReadFile(filepath.Join(st.root, "receipts", r.sessionID, fmt.Sprintf("%d.json", r.callIndex)))
				if err != nil {
					t.Fatal(err)
				}
				if string(written) != text {
					t.Fatalf("%s %s, trail %q: minted again, it is not the receipt it was:\n%s\n%s", filepath.Base(path), file, trail, written, text)
				}
				compared++
			}
		}
	}
	if compared < 20 {
		t.Fatalf("only %d receipts compared", compared)
	}
}

// connect keeps the member, its values unchanged: the rewrite of a
// platform's entry renders the file again, and the witness named for a
// trail is in it as it was, still the configuration's.
func TestConnectKeepsWitnessedBy(t *testing.T) {
	text := engineWithWitnessedBy("7", `{"`+namedTrail+`":{"origin":"https://witness.example:443","publicKey":"`+witnessKey+`"}}`)
	out, err := renderPlatformEntry([]byte(text), connectRequest{platform: "warehouse", credentials: map[string]string{"live": "/run/secrets/warehouse"}, user: "engine-warehouse"}, "postgres@sha256:"+strings.Repeat("a", 64), "")
	if err != nil {
		t.Fatal(err)
	}
	before, err := parseEngineConfig([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	after, err := parseEngineConfig(out)
	if err != nil {
		t.Fatalf("the rewritten file: %v\n%s", err, out)
	}
	if len(after.witnessedBy) != 1 || after.witnessedBy[namedTrail].origin != before.witnessedBy[namedTrail].origin || after.version != "7" ||
		hex.EncodeToString(after.witnessedBy[namedTrail].publicKey) != witnessKey {
		t.Fatalf("witnessedBy after connect: %+v, version %s", after.witnessedBy, after.version)
	}
}
