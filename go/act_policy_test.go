package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A write held to its decision (ADR-0011, docs/design/executor.md steps 8 to
// 10): for a tool the operator holds to a decision policy, the executor reads
// the record the request names, holds the request's claims to it and holds
// it to the policy, and refuses at the first that fails, with nothing run.

var (
	packA = "sha256:" + strings.Repeat("a1", 32)
	packB = "sha256:" + strings.Repeat("b2", 32)
)

// policyText is the policy these tests hold update_ticket to.
var policyText = `{"outcomes":["approve"],"packs":["` + packA + `"],"reviewed":true,"bind":[` +
	`{"argument":"/id","fact":"/quote/id"},{"argument":"/revision","fact":"/quote/revision"},{"argument":"/customer","fact":"/quote/customer"}]}`

// policyCanonical is the same policy in its canonical form, written by hand:
// members by code point, no whitespace.
var policyCanonical = `{"bind":[{"argument":"/id","fact":"/quote/id"},{"argument":"/revision","fact":"/quote/revision"},{"argument":"/customer","fact":"/quote/customer"}],` +
	`"outcomes":["approve"],"packs":["` + packA + `"],"reviewed":true}`

func mustPolicy(t *testing.T, text string) *decisionPolicy {
	t.Helper()
	v, err := parseJSON([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := parseDecisionPolicy(v, "test")
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

// runtimeLine is a record as the runtime's audit trail writes one line of
// it (runtime internal/audit, ADR-0018), citing one receipt; edits are
// pairs of text to find in it and text to put in its place, each of which
// must be there.
func runtimeLine(t *testing.T, signature string, edits ...string) string {
	t.Helper()
	line := `{"recordVersion":"1","run":"4f1c2b3a5d6e7f80","at":"2026-09-30T10:00:00.123456789Z","kind":"evaluation","surface":"evaluate",` +
		`"tool":{"name":"jpack","version":"0.23.1"},"evaluatorSpecVersion":"1.0",` +
		`"pack":{"id":"refunds","version":"1.2.0","specVersion":"1.0","digest":"` + packA + `"},` +
		`"inputs":{"facts":{"quote":{"id":"Q-7","revision":4,"amount":12.5,"customer":{"name":"Acme","tier":2}}},"evidence":null,"evidenceSupplied":false},` +
		`"reviewed":true,"reviewedSet":{"lockDigest":"sha256:` + strings.Repeat("c3", 32) + `","lockVersion":"1","configDigest":"sha256:` + strings.Repeat("d4", 32) + `"},` +
		`"cites":[{"sessionId":"act-p","callIndex":0,"signature":"` + signature + `"}],` +
		`"disposition":{"handoff":{"state":"none"},"kind":"outcome","outcomeId":"approve","reasons":[]}}`
	for i := 0; i+1 < len(edits); i += 2 {
		if !strings.Contains(line, edits[i]) {
			t.Fatalf("the record holds no %q to replace", edits[i])
		}
		line = strings.Replace(line, edits[i], edits[i+1], 1)
	}
	return line
}

func TestActHoldsAWriteToItsDecisionPolicy(t *testing.T) {
	service, server := testService(t)
	policy := mustPolicy(t, policyText)
	service.sources["tickets/write"] = sourceSpec{argv: []string{os.Args[0], "--tools=update_ticket,delete_ticket"}, env: helperEnv, shape: "mcp",
		tools: []string{"update_ticket", "delete_ticket"}, endpoint: "https://mcp.example/", policies: map[string]*decisionPolicy{"update_ticket": policy}}
	records := filepath.Join(t.TempDir(), "decisions")
	if err := os.MkdirAll(records, 0o700); err != nil {
		t.Fatal(err)
	}
	service.decisionRecords = records
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	code, first := authed(t, server, "/acquire", `{"session":"act-p","source":"screening","arguments":{"q":"acme"}}`, token)
	if code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, first)
	}
	signature := first["receipt"].(map[string]any)["signature"].(string)

	// Every record is a candidate under the directory: each a line of one
	// .jsonl file, or a file of its own for bytes that are no line.
	var lines []string
	place := func(t *testing.T, record string) string {
		t.Helper()
		lines = append(lines, record)
		if err := os.WriteFile(filepath.Join(records, "evaluations.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return "sha256:" + hexOf([]byte(record))
	}
	arguments := `{"id":"Q-7","revision":4,"status":"approved","customer":{"tier":2,"name":"Acme"}}`
	request := func(tool, recordDigest, packDigest, arguments string) string {
		return `{"session":"act-p","platform":"tickets","tool":"` + tool + `","arguments":` + arguments + `,` +
			`"decision":{"recordDigest":"` + recordDigest + `","packDigest":"` + packDigest + `"},` +
			`"cites":[{"sessionId":"act-p","callIndex":0,"signature":"` + signature + `"}]}`
	}
	started := service.started.Load()

	for _, tc := range []struct {
		name      string
		record    string // the record's text; "" is the runtime's line unchanged
		pack      string // the request's decision.packDigest; "" is packA
		arguments string // "" is the arguments above
		step      string
		want      string
	}{
		// step 8: a runtime evaluation record, or nothing is held to it
		{"a record that is not a JSON object", `[1,2]`, "", "", "record", "not a JSON object"},
		{"a record with a member twice", runtimeLine(t, signature, `"amount":12.5`, `"amount":12.5,"amount":13`), "", "", "record", "not one JSON object this engine can read"},
		{"a record of another version", runtimeLine(t, signature, `"recordVersion":"1"`, `"recordVersion":"2"`), "", "", "record", `recordVersion is not "1"`},
		{"a graph composite", runtimeLine(t, signature, `"kind":"evaluation"`, `"kind":"graph-composite"`), "", "", "record", "graph composite"},
		{"a record of another kind", runtimeLine(t, signature, `"kind":"evaluation"`, `"kind":"other"`), "", "", "record", `kind is not "evaluation"`},
		{"a record with no pack digest", runtimeLine(t, signature, `"digest":"`+packA+`"`, `"id2":"`+packA+`"`), "", "", "record", "no pack digest"},
		// step 9: the request's claims are the record's
		{"a pack digest the record was not decided under", "", packB, "", "consistency", "decision.packDigest"},
		{"a record citing another receipt", runtimeLine(t, signature, signature, strings.Repeat("e", 128)), "", "", "consistency", "as a set"},
		{"a record citing nothing", runtimeLine(t, signature, `"cites":[{"sessionId":"act-p","callIndex":0,"signature":"`+signature+`"}],`, ``), "", "", "consistency", "cites none"},
		{"a record whose cites is not of the shape", runtimeLine(t, signature, `"callIndex":0`, `"callIndex":"0"`), "", "", "consistency", "not of the shape"},
		{"a record whose citation carries a fraction beside its three members", runtimeLine(t, signature, `"callIndex":0,`, `"callIndex":0,"extra":{"fraction":0.5},`), "", "", "consistency", "not of the shape"},
		// step 10: the policy, in its order
		{"a handoff requested on an unresolved record", runtimeLine(t, signature, `{"handoff":{"state":"none"},"kind":"outcome","outcomeId":"approve","reasons":[]}`, `{"handoff":{"state":"requested","triggeredBy":["unknown"]},"kind":"unresolved","reasons":["unknown"]}`), "", "", "policy-outcome", "not an outcome the tool's decision policy allows"},
		{"an outcome the policy does not allow", runtimeLine(t, signature, `"outcomeId":"approve"`, `"outcomeId":"deny"`), "", "", "policy-outcome", "not an outcome"},
		{"an allowed outcome id on a disposition of another kind", runtimeLine(t, signature, `"kind":"outcome"`, `"kind":"unresolved"`), "", "", "policy-outcome", "not an outcome"},
		{"no disposition", runtimeLine(t, signature, `,"disposition":{"handoff":{"state":"none"},"kind":"outcome","outcomeId":"approve","reasons":[]}`, ``), "", "", "policy-outcome", "not an outcome"},
		{"an allowed outcome with a handoff requested", runtimeLine(t, signature, `"handoff":{"state":"none"}`, `"handoff":{"state":"requested","triggeredBy":["exception-escalation"]}`), "", "", "policy-handoff", "requested handoff"},
		{"a pack the policy does not name", runtimeLine(t, signature, `"digest":"`+packA+`"`, `"digest":"`+packB+`"`), packB, "", "policy-packs", "does not name"},
		{"a record judged under draft law", runtimeLine(t, signature, `"reviewed":true`, `"reviewed":false`), "", "", "policy-reviewed", `"reviewed": true`},
		{"a record of a project with no lock", runtimeLine(t, signature, `"reviewed":true,`, ``), "", "", "policy-reviewed", `"reviewed": true`},
		{"a record whose reviewed is not a boolean", runtimeLine(t, signature, `"reviewed":true`, `"reviewed":"true"`), "", "", "policy-reviewed", `"reviewed": true`},
		{"revision 3 decided, revision 4 written", runtimeLine(t, signature, `"revision":4`, `"revision":3`), "", "", "policy-bind", `the argument at "/revision" does not equal the fact at "/quote/revision"`},
		{"the string 4 for the number 4", runtimeLine(t, signature, `"revision":4`, `"revision":"4"`), "", "", "policy-bind", `"/revision"`},
		{"a fact outside the canonical domain", runtimeLine(t, signature, `"revision":4`, `"revision":4.0`), "", "", "policy-bind", `"/revision"`},
		{"an approval for another order", runtimeLine(t, signature, `"id":"Q-7"`, `"id":"Q-8"`), "", "", "policy-bind", `the argument at "/id"`},
		{"another customer", runtimeLine(t, signature, `"tier":2`, `"tier":3`), "", "", "policy-bind", `"/customer"`},
		{"an argument the policy binds, absent", "", "", `{"id":"Q-7","status":"approved","customer":{"tier":2,"name":"Acme"}}`, "policy-bind", `arguments hold nothing at "/revision"`},
		{"a fact the policy binds, absent", runtimeLine(t, signature, `"revision":4,`, ``), "", "", "policy-bind", `facts hold nothing at "/quote/revision"`},
		{"a record with no inputs", runtimeLine(t, signature, `"inputs":{"facts":{"quote":{"id":"Q-7","revision":4,"amount":12.5,"customer":{"name":"Acme","tier":2}}},"evidence":null,"evidenceSupplied":false},`, ``), "", "", "policy-bind", `facts hold nothing at "/quote/id"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := tc.record
			if record == "" {
				record = runtimeLine(t, signature)
			}
			pack, args := tc.pack, tc.arguments
			if pack == "" {
				pack = packA
			}
			if args == "" {
				args = arguments
			}
			code, answer := authed(t, server, "/act", request("update_ticket", place(t, record), pack, args), token)
			if code != http.StatusBadRequest || answer["refusedAt"] != tc.step || !strings.Contains(fmt.Sprint(answer["error"]), tc.want) {
				t.Fatalf("want a refusal at %q saying %q, got %d %v", tc.step, tc.want, code, answer)
			}
			// A refusal names the check, never a value of the record's.
			if strings.Contains(fmt.Sprint(answer["error"]), "deny") || strings.Contains(fmt.Sprint(answer["error"]), "Q-8") {
				t.Fatalf("the refusal quotes the record: %v", answer)
			}
			if service.started.Load() != started {
				t.Fatal("an executor ran for a write its decision does not hold")
			}
		})
	}
	// Bytes that are no JSON at all, a file of their own.
	opaque := []byte("an opaque record\n")
	if err := os.WriteFile(filepath.Join(records, "opaque.bin"), opaque, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, answer := authed(t, server, "/act", request("update_ticket", "sha256:"+hexOf(opaque), packA, arguments), token); code != http.StatusBadRequest || answer["refusedAt"] != "record" {
		t.Fatalf("an opaque record under a policy: %d %v", code, answer)
	}
	if service.started.Load() != started {
		t.Fatal("an executor ran on an opaque record under a policy")
	}
	// A .jsonl file whole is a candidate and no record: its lines are the
	// records, and one named by the file's digest is not read as one.
	whole := []byte(runtimeLine(t, signature) + "\n")
	if err := os.WriteFile(filepath.Join(records, "single.jsonl"), whole, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, answer := authed(t, server, "/act", request("update_ticket", "sha256:"+hexOf(whole), packA, arguments), token); code != http.StatusBadRequest || answer["refusedAt"] != "record" {
		t.Fatalf("a .jsonl file whole under a policy: %d %v", code, answer)
	}
	if service.started.Load() != started {
		t.Fatal("an executor ran on a .jsonl file whole under a policy")
	}

	// Every check met: the executor runs, and the receipt names the policy
	// the write was held to. The bound object is equal as a value, whatever
	// the order its members were written in.
	env, _ := goodEnvelope()
	t.Setenv(envSourceEnvelope, envelopeText(t, env))
	held := place(t, runtimeLine(t, signature))
	code, acted := authed(t, server, "/act", request("update_ticket", held, packA, arguments), token)
	if code != http.StatusOK {
		t.Fatalf("a write its decision holds: %d %v", code, acted)
	}
	inner := acted["receipt"].(map[string]any)["action"].(map[string]any)
	sum := sha256.Sum256([]byte(policyCanonical))
	if inner["policy"] != "sha256:"+hex.EncodeToString(sum[:]) || inner["policy"] != policy.digest {
		t.Fatalf("the receipt names the policy by the digest of its canonical form: %v, want sha256 of %s", inner["policy"], policyCanonical)
	}
	if service.started.Load() != started+1 {
		t.Fatal("the executor runs once for the write its decision holds")
	}

	// A tool the operator holds to no policy is what it was: its record is
	// not read -- bytes that are no JSON, a record whose claims and outcome
	// the policy above would refuse -- and its receipt carries no policy.
	for _, recordDigest := range []string{
		"sha256:" + hexOf(opaque),
		place(t, runtimeLine(t, signature, `"outcomeId":"approve"`, `"outcomeId":"deny"`, `"handoff":{"state":"none"}`, `"handoff":{"state":"requested","triggeredBy":["exception-escalation"]}`)),
	} {
		code, acted := authed(t, server, "/act", request("delete_ticket", recordDigest, packB, `{"id":"Q-9"}`), token)
		if code != http.StatusOK {
			t.Fatalf("a tool with no policy: %d %v", code, acted)
		}
		inner := acted["receipt"].(map[string]any)["action"].(map[string]any)
		var names []string
		for name := range inner {
			names = append(names, name)
		}
		if _, carried := inner["policy"]; carried || len(names) != 7 {
			t.Fatalf("a receipt for a tool with no policy has the members it always had: %v", names)
		}
	}
	if service.started.Load() != started+3 {
		t.Fatal("the executor runs for each write of a tool with no policy")
	}
}

// The digest names the policy as configured, by its canonical form: the
// same policy spelled another way -- other member order, whitespace, an
// escape -- is the same digest; a different policy is another.
func TestDecisionPolicyDigestIsOfItsCanonicalForm(t *testing.T) {
	sum := sha256.Sum256([]byte(policyCanonical))
	want := "sha256:" + hex.EncodeToString(sum[:])
	respelled := "{ \"reviewed\" : true,\n \"packs\": [\"" + packA + "\"],\n \"outcomes\": [\"appro\\u0076e\"],\n \"bind\": [" +
		`{"fact":"/quote/id","argument":"/id"},{"fact":"/quote/revision","argument":"/revision"},{"fact":"/quote/customer","argument":"/customer"}]}`
	for _, text := range []string{policyText, respelled} {
		if got := mustPolicy(t, text).digest; got != want {
			t.Fatalf("%s: digest %s, want %s", text, got, want)
		}
	}
	for _, other := range []string{
		strings.Replace(policyText, `"reviewed":true`, `"reviewed":false`, 1),
		strings.Replace(policyText, `"reviewed":true,`, ``, 1),
		strings.Replace(policyText, `{"argument":"/id","fact":"/quote/id"},`, ``, 1),
	} {
		if mustPolicy(t, other).digest == want {
			t.Fatalf("a different policy has the same digest: %s", other)
		}
	}
}

// The configuration member (docs/design/engine-config.md): a version-4
// member of a platform that sets write: true, each policy a closed object,
// each tool one the platform's write binding names.
func TestDecisionPolicyConfiguration(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding, "history-only": historyOnlyBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	config := func(version, platformExtra string) string {
		text := engineJSON(t, catalog, ``, platformJSONFor(t, "warehouse", ref, "engine-warehouse", platformExtra, "history", "live", "write"))
		return strings.Replace(text, `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
	}
	good := `,"write":true,"decisionPolicy":{"execute":` + strings.Replace(policyText, `"reviewed":true,`, ``, 1) + `}`
	cfg, sources, err := load(t, config("4", good))
	if err != nil {
		t.Fatal(err)
	}
	write := sources["warehouse/write"]
	if cfg.version != "4" || write.policies["execute"] == nil || write.policies["drop"] != nil || len(write.policies["execute"].bind) != 3 || write.policies["execute"].reviewed {
		t.Fatalf("the write source carries the policy for its tool, and none for the other: %+v", write.policies)
	}
	if write.policies["execute"].digest != mustPolicy(t, strings.Replace(policyText, `"reviewed":true,`, ``, 1)).digest {
		t.Fatal("the configured policy's digest is its canonical form's")
	}
	// A configuration without the member is unchanged at every version.
	if _, sources, err := load(t, config("4", `,"write":true`)); err != nil || sources["warehouse/write"].policies != nil {
		t.Fatalf("no policy: %v %+v", err, sources["warehouse/write"].policies)
	}
	with := func(policy string) string {
		return config("4", `,"write":true,"decisionPolicy":{"execute":`+policy+`}`)
	}
	for _, tc := range []struct{ name, text, want string }{
		{"version 3", config("3", good), "decisionPolicy is a version-4 member"},
		{"version 1", config("1", good), "decisionPolicy is a version-4 member"},
		{"a platform that allows no writes", config("4", strings.Replace(good, `"write":true`, `"write":false`, 1)), "does not set write: true"},
		{"a platform with no write member", config("4", strings.Replace(good, `,"write":true`, ``, 1)), "does not set write: true"},
		{"not an object", config("4", `,"write":true,"decisionPolicy":["execute"]`), "decisionPolicy must be an object"},
		{"a tool by the empty string", config("4", `,"write":true,"decisionPolicy":{"":{"outcomes":["approve"]}}`), "empty string"},
		{"a policy that is not an object", with(`["approve"]`), "must be an object"},
		{"an unknown member", with(`{"outcomes":["approve"],"handoff":"none"}`), `unknown member "handoff"`},
		{"no outcomes", with(`{"packs":["` + packA + `"]}`), `missing member "outcomes"`},
		{"outcomes empty", with(`{"outcomes":[]}`), "outcomes must be a non-empty array"},
		{"outcomes not an array", with(`{"outcomes":"approve"}`), "outcomes must be a non-empty array"},
		{"an outcome that is not a string", with(`{"outcomes":[1]}`), "an outcome id"},
		{"an outcome that is empty", with(`{"outcomes":[""]}`), "an outcome id"},
		{"an outcome twice", with(`{"outcomes":["approve","approve"]}`), "names one entry twice"},
		{"packs empty", with(`{"outcomes":["approve"],"packs":[]}`), "packs must be a non-empty array"},
		{"a pack that is not a digest", with(`{"outcomes":["approve"],"packs":["sha256:ABC"]}`), "a digest"},
		{"reviewed not a boolean", with(`{"outcomes":["approve"],"reviewed":"yes"}`), "reviewed, when present, is a boolean"},
		{"bind not an array", with(`{"outcomes":["approve"],"bind":{"argument":"/a","fact":"/a"}}`), "bind, when present, is an array"},
		{"a binding that is not an object", with(`{"outcomes":["approve"],"bind":["/a"]}`), "bind[0] must be an object"},
		{"a binding without its fact", with(`{"outcomes":["approve"],"bind":[{"argument":"/a"}]}`), `missing member "fact"`},
		{"a binding with a member beyond its two", with(`{"outcomes":["approve"],"bind":[{"argument":"/a","fact":"/a","type":"string"}]}`), `unknown member "type"`},
		{"a pointer without its slash", with(`{"outcomes":["approve"],"bind":[{"argument":"revision","fact":"/revision"}]}`), "JSON pointer"},
		{"a pointer with a bad escape", with(`{"outcomes":["approve"],"bind":[{"argument":"/a","fact":"/a~2b"}]}`), "JSON pointer"},
		{"a pointer ending in a tilde", with(`{"outcomes":["approve"],"bind":[{"argument":"/a~","fact":"/a"}]}`), "JSON pointer"},
		{"a pointer that is not a string", with(`{"outcomes":["approve"],"bind":[{"argument":1,"fact":"/a"}]}`), "JSON pointer"},
		{"a binding twice", with(`{"outcomes":["approve"],"bind":[{"argument":"/id","fact":"/id"},{"fact":"/id","argument":"/id"}]}`), "bind names one pair twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseEngineConfig([]byte(tc.text)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a refusal saying %q, got %v", tc.want, err)
			}
		})
	}
	// Judged against the binding: a tool its write operation does not
	// name, or a binding that states no write operation.
	if _, _, err := load(t, config("4", `,"write":true,"decisionPolicy":{"update_ticket":{"outcomes":["approve"]}}`)); err == nil || !strings.Contains(err.Error(), `decisionPolicy names tool "update_ticket", which the binding's write operation does not name`) {
		t.Fatalf("a policy for a tool the binding does not name: %v", err)
	}
	historyOnly := engineJSON(t, catalog, ``, platformJSONFor(t, "warehouse", "history-only@"+digestOf(historyOnlyBinding), "engine-warehouse", `,"write":true,"decisionPolicy":{"execute":{"outcomes":["approve"]}}`, "history"))
	if _, _, err := load(t, strings.Replace(historyOnly, `"engineVersion":"1"`, `"engineVersion":"4"`, 1)); err == nil || !strings.Contains(err.Error(), "states no write operation") {
		t.Fatalf("a policy on a binding with no write operation: %v", err)
	}
}

// historyOnlyBinding is a catalog entry that states no write operation.
const historyOnlyBinding = `{
  "bindingVersion": "1",
  "platform": "history-only",
  "operations": {
    "history": {"shape": "airbyte", "image": "airbyte/source-postgres:3.6.1@` + testImageDigest + `", "licence": "ELv2"}
  }
}`

// JSON pointers resolve as RFC 6901 §4 says, and name nothing where it says
// they name nothing.
func TestJSONPointersResolveAsRFC6901Says(t *testing.T) {
	doc, err := parseJSON([]byte(`{"foo":["bar","baz"],"":0,"a/b":1,"m~n":8,"k\"l":6," ":7,"n":{"0":"zero"}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		pointer string
		want    string // canonical form; "" names nothing
	}{
		{"", `{"":0," ":7,"a/b":1,"foo":["bar","baz"],"k\"l":6,"m~n":8,"n":{"0":"zero"}}`},
		{"/foo", `["bar","baz"]`},
		{"/foo/0", `"bar"`},
		{"/foo/1", `"baz"`},
		{"/", `0`},
		{"/a~1b", `1`},
		{"/m~0n", `8`},
		{`/k"l`, `6`},
		{"/ ", `7`},
		{"/n/0", `"zero"`},
		{"/foo/2", ""},
		{"/foo/-", ""},
		{"/foo/01", ""},
		{"/foo/+1", ""},
		{"/foo/", ""},
		{"/bar", ""},
		{"/foo/0/x", ""},
		{"/a~01b", ""},
	} {
		got, ok := resolvePointer(doc, tc.pointer)
		if (tc.want == "") != !ok || (ok && string(canon(got)) != tc.want) {
			t.Fatalf("%q: got %v (%v), want %q", tc.pointer, got, ok, tc.want)
		}
	}
}

// A record is read as the runtime wrote it: a number of any form is
// admitted, and kept outside the canonical domain where it lies outside it;
// what the canonical parser refuses otherwise is refused here too.
func TestARecordIsReadWithNumbersOfAnyForm(t *testing.T) {
	v, err := parseRecordJSON([]byte(`{"a":12.5,"b":1e2,"c":-0,"d":9007199254740993,"e":4,"f":[0.0,-1E-3]}`))
	if err != nil {
		t.Fatal(err)
	}
	obj := v.(*vObject)
	for name, want := range map[string]value{"a": vNumber("12.5"), "b": vNumber("1e2"), "c": vInt(0), "d": vNumber("9007199254740993"), "e": vInt(4)} {
		if got, _ := obj.get(name); got != want {
			t.Fatalf("%s: %#v, want %#v", name, got, want)
		}
	}
	if canonicalValue(v) {
		t.Fatal("a record holding a fraction is outside the canonical domain")
	}
	if e, _ := obj.get("e"); !canonicalValue(e) {
		t.Fatal("an integer inside the range is inside the domain")
	}
	f, _ := obj.get("f")
	if canonicalValue(f) {
		t.Fatal("an array holding a fraction is outside the domain")
	}
	for _, refused := range []string{`{"a":1,"a":2}`, `{"a":01}`, `{"a":1.}`, `{"a":.5}`, `{"a":1e}`, `{"a":"\ud800"}`, "{\"a\":\"\xff\"}", `{"a":NaN}`, `{"a":+1}`} {
		if _, err := parseRecordJSON([]byte(refused)); err == nil {
			t.Fatalf("%s: read as a record", refused)
		}
	}
	// The canonical parser is unchanged by it.
	if _, err := parseJSON([]byte(`{"a":12.5}`)); err == nil {
		t.Fatal("the canonical parser admits a fraction")
	}
}

// connect has no flag for a decision policy: the entry replaced keeps the
// one it carries, a replacement it would no longer fit is refused before
// anything is asked, and a file at version 4 is never written back as 3.
func TestConnectKeepsADecisionPolicyAndTheVersion(t *testing.T) {
	policy := `{"execute":{"outcomes":["approve"],"reviewed":true}}`
	f := newConnectFixture(t, postgresBinding, ``)
	entry := `"warehouse":{"binding":"postgres@` + digestOf(postgresBinding) + `","credentials":{"history":{"file":"` + escapePath(f.credentials) + `"},"live":{"file":"` + escapePath(f.credentials) + `"},"write":{"file":"` + escapePath(f.credentials) + `"}},"user":"engine-warehouse","write":true,"decisionPolicy":` + policy + `}`
	text := strings.Replace(strings.Replace(f.fileText(t), `"engineVersion":"1"`, `"engineVersion":"4"`, 1), `"platforms":{}`, `"platforms":{`+entry+`}`, 1)
	if err := os.WriteFile(f.config, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	before, _, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	digest := before.platforms[0].policies["execute"].digest
	req := f.request()
	req.replace = true
	// A replacement that allows no writes would leave a policy on nothing.
	req.write = false
	req.credentials = map[string]string{"history": f.credentials, "live": f.credentials}
	if _, err := connect(context.Background(), req, f.host, f.check); err == nil || !strings.Contains(err.Error(), "carries a decisionPolicy, which --replace keeps") {
		t.Fatalf("a replacement without --write: %v", err)
	}
	if len(f.asked) != 0 || f.fileText(t) != text {
		t.Fatal("nothing is asked and nothing is written for a replacement the policy would not fit")
	}
	// A replacement that fits keeps it, and a pin captured beside it leaves
	// the version at 4.
	req.write = true
	req.credentials["write"] = f.credentials
	f.captured = `{"query":{"description":"Run a query","inputSchemaText":"{\"type\":\"object\"}"}}`
	if _, err := connect(context.Background(), req, f.host, f.check); err != nil {
		t.Fatal(err)
	}
	after, _, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	if after.version != "4" || after.platforms[0].descriptors == "" || after.platforms[0].policies["execute"] == nil || after.platforms[0].policies["execute"].digest != digest {
		t.Fatalf("version %s, pin %q, policies %+v: the policy kept as written, the version not lowered", after.version, after.platforms[0].descriptors, after.platforms[0].policies)
	}
	// A binding whose write operation does not name the policy's tool is
	// refused before anything is asked.
	renamed := strings.Replace(postgresBinding, `"tools": ["execute", "drop"]`, `"tools": ["run"]`, 1)
	if err := os.WriteFile(filepath.Join(f.catalog, "postgres.json"), []byte(renamed), 0o600); err != nil {
		t.Fatal(err)
	}
	f.asked = nil
	written := f.fileText(t)
	if _, err := connect(context.Background(), req, f.host, f.check); err == nil || !strings.Contains(err.Error(), `decisionPolicy names tool "execute", which the binding's write operation does not name`) {
		t.Fatalf("a binding that no longer names the policy's tool: %v", err)
	}
	if len(f.asked) != 0 || f.fileText(t) != written {
		t.Fatal("nothing is asked and nothing is written for a binding the policy does not fit")
	}
}
