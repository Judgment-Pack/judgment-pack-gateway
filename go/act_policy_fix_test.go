package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A decision policy that fixes a value and closes the argument set
// (docs/adr/0016-a-policy-fixes-a-value-and-closes-the-argument-set.md):
// fix holds an argument to a value the policy states, closed refuses an
// argument that no pointer of bind or fix reaches, both at policy-bind,
// before anything is sent, both version-9 members of the engine's
// configuration, both in the policy's digest.

// The configuration members: each accepted, and refused case by case.
func TestFixAndClosedConfiguration(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	config := func(version, policy string) string {
		extra := `,"write":true`
		if policy != "" {
			extra += `,"decisionPolicy":{"execute":` + policy + `}`
		}
		text := engineJSON(t, catalog, ``, platformJSONFor(t, "warehouse", ref, "engine-warehouse", extra, "history", "live", "write"))
		return strings.Replace(text, `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
	}
	good := `{"outcomes":["approve"],"bind":[{"argument":"/id","fact":"/ticket/id"}],` +
		`"fix":[{"argument":"/action","value":"update"},{"argument":"/updates/0/op","value":"test"},{"argument":"/meta","value":{"n":2,"tags":["a",null,true]}}],"closed":true}`
	cfg, sources, err := load(t, config("9", good))
	if err != nil {
		t.Fatal(err)
	}
	policy := sources["warehouse/write"].policies["execute"]
	if cfg.version != "9" || policy == nil || !policy.closed || len(policy.fix) != 3 || len(policy.bind) != 1 ||
		policy.fix[0].argument != "/action" || string(policy.fix[0].canonical) != `"update"` ||
		policy.fix[2].argument != "/meta" || string(policy.fix[2].canonical) != `{"n":2,"tags":["a",null,true]}` {
		t.Fatalf("version %s, policy %+v", cfg.version, policy)
	}
	// Each member alone, and closed false, which is the default spelled out.
	for _, alone := range []string{
		`{"outcomes":["approve"],"fix":[{"argument":"","value":{}}]}`,
		`{"outcomes":["approve"],"fix":[{"argument":"/n","value":null}]}`,
		`{"outcomes":["approve"],"fix":[]}`,
		`{"outcomes":["approve"],"closed":true}`,
		`{"outcomes":["approve"],"closed":false}`,
	} {
		if _, _, err := load(t, config("9", alone)); err != nil {
			t.Fatalf("%s: %v", alone, err)
		}
	}
	if _, sources, err := load(t, config("9", `{"outcomes":["approve"],"closed":false}`)); err != nil || sources["warehouse/write"].policies["execute"].closed {
		t.Fatalf("closed false: %v", err)
	}
	// A version-9 file without the members loads, with a policy and without.
	for _, policy := range []string{``, `{"outcomes":["approve"],"bind":[{"argument":"/id","fact":"/id"}]}`} {
		cfg, sources, err := load(t, config("9", policy))
		if err != nil || cfg.version != "9" {
			t.Fatalf("a version-9 file without fix or closed: %v", err)
		}
		if p := sources["warehouse/write"].policies["execute"]; p != nil && (p.closed || p.fix != nil) {
			t.Fatalf("a policy without the members fixes nothing and is open: %+v", p)
		}
	}
	with := func(policy string) string { return config("9", policy) }
	for _, tc := range []struct{ name, text, want string }{
		{"fix in a version-8 file", config("8", `{"outcomes":["approve"],"fix":[{"argument":"/action","value":"update"}]}`), "fix is a version-9 member; engineVersion 8 has no fix"},
		{"closed in a version-8 file", config("8", `{"outcomes":["approve"],"closed":true}`), "closed is a version-9 member; engineVersion 8 has no closed"},
		{"closed false in a version-8 file", config("8", `{"outcomes":["approve"],"closed":false}`), "closed is a version-9 member; engineVersion 8 has no closed"},
		{"an empty fix in a version-5 file", config("5", `{"outcomes":["approve"],"fix":[]}`), "fix is a version-9 member; engineVersion 5 has no fix"},
		{"fix not an array", with(`{"outcomes":["approve"],"fix":{"argument":"/action","value":"update"}}`), "fix, when present, is an array of {argument, value}"},
		{"a fixed value that is not an object", with(`{"outcomes":["approve"],"fix":["/action"]}`), "fix[0] must be an object of argument and value"},
		{"a fixed value without its value", with(`{"outcomes":["approve"],"fix":[{"argument":"/action"}]}`), `fix[0]: missing member "value"`},
		{"a fixed value without its argument", with(`{"outcomes":["approve"],"fix":[{"value":"update"}]}`), `fix[0]: missing member "argument"`},
		{"a fixed value with a member beyond its two", with(`{"outcomes":["approve"],"fix":[{"argument":"/action","value":"update","type":"string"}]}`), `unknown member "type"`},
		{"a pointer without its slash", with(`{"outcomes":["approve"],"fix":[{"argument":"action","value":"update"}]}`), "fix[0]: argument must be a JSON pointer"},
		{"a pointer with a bad escape", with(`{"outcomes":["approve"],"fix":[{"argument":"/a~2b","value":1}]}`), "fix[0]: argument must be a JSON pointer"},
		{"a pointer ending in a tilde", with(`{"outcomes":["approve"],"fix":[{"argument":"/a~","value":1}]}`), "fix[0]: argument must be a JSON pointer"},
		{"a pointer that is not a string", with(`{"outcomes":["approve"],"fix":[{"argument":1,"value":1}]}`), "fix[0]: argument must be a JSON pointer"},
		{"a pointer fixed twice to one value", with(`{"outcomes":["approve"],"fix":[{"argument":"/action","value":"update"},{"value":"update","argument":"/action"}]}`), `fix names the argument "/action" twice`},
		{"a pointer fixed twice to two values", with(`{"outcomes":["approve"],"fix":[{"argument":"/action","value":"update"},{"argument":"/action","value":"create"}]}`), `fix names the argument "/action" twice`},
		{"a pointer both fixed and bound", with(`{"outcomes":["approve"],"bind":[{"argument":"/id","fact":"/ticket/id"}],"fix":[{"argument":"/id","value":42}]}`), `fix[0]: the argument "/id" is both fixed and bound`},
		{"the whole arguments both fixed and bound", with(`{"outcomes":["approve"],"bind":[{"argument":"","fact":"/write"}],"fix":[{"argument":"","value":{}}]}`), `the argument "" is both fixed and bound`},
		{"a fixed value outside the canonical domain", with(`{"outcomes":["approve"],"fix":[{"argument":"/amount","value":12.5}]}`), "engine configuration"},
		{"closed not a boolean", with(`{"outcomes":["approve"],"closed":"true"}`), "closed, when present, is a boolean"},
		{"closed a number", with(`{"outcomes":["approve"],"closed":1}`), "closed, when present, is a boolean"},
		{"closed null", with(`{"outcomes":["approve"],"closed":null}`), "closed, when present, is a boolean"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseEngineConfig([]byte(tc.text)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a refusal saying %q, got %v", tc.want, err)
			}
		})
	}
}

// connect keeps a version-9 policy as written, and the version: a pin
// captured beside it raises nothing and lowers nothing.
func TestConnectKeepsAFixedAndClosedPolicyAndTheVersion(t *testing.T) {
	policy := `{"execute":{"outcomes":["approve"],"bind":[{"argument":"/id","fact":"/id"}],"fix":[{"argument":"/action","value":"update"}],"closed":true}}`
	f := newConnectFixture(t, currentPolicyBinding, ``)
	entry := `"warehouse":{"binding":"postgres@` + digestOf(currentPolicyBinding) + `","credentials":{"history":{"file":"` + escapePath(f.credentials) + `"},"live":{"file":"` + escapePath(f.credentials) + `"},"write":{"file":"` + escapePath(f.credentials) + `"}},"user":"engine-warehouse","write":true,"operationDescriptors":{"live":"sha256:0000000000000000000000000000000000000000000000000000000000000000","write":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},"decisionPolicy":` + policy + `}`
	text := strings.Replace(strings.Replace(f.fileText(t), `"engineVersion":"1"`, `"engineVersion":"11"`, 1), `"platforms":{}`, `"platforms":{`+entry+`}`, 1)
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
	req.write = true
	req.credentials = map[string]string{"history": f.credentials, "live": f.credentials, "write": f.credentials}
	f.captured = `{"query":{"description":"Run a query","inputSchemaText":"{\"type\":\"object\"}"}}`
	if _, err := connect(context.Background(), req, f.host, f.check); err != nil {
		t.Fatal(err)
	}
	after, _, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	kept := after.platforms[0].policies["execute"]
	if after.version != "11" || after.platforms[0].operationDescriptors["live"] == "" || kept == nil || kept.digest != digest || !kept.closed || len(kept.fix) != 1 {
		t.Fatalf("version %s, pin %q, policy %+v: the policy kept as written, the version neither raised nor lowered", after.version, after.platforms[0].operationDescriptors["live"], kept)
	}
}

// The digest names the policy as configured, the new members with the
// rest: a policy that differs from another only in fix or in closed has
// another digest, and the same policy spelled in another order has the same.
func TestFixAndClosedAreInThePolicysDigest(t *testing.T) {
	base := `{"outcomes":["approve"],"bind":[{"argument":"/id","fact":"/ticket/id"}],` +
		`"fix":[{"argument":"/status","value":"approved"},{"argument":"/meta","value":{"b":2,"a":[1,"x",null,true]}}],"closed":true}`
	// The canonical form, written by hand: members by code point, at every
	// depth, the fixed value's among them; arrays in their order.
	canonical := `{"bind":[{"argument":"/id","fact":"/ticket/id"}],"closed":true,` +
		`"fix":[{"argument":"/status","value":"approved"},{"argument":"/meta","value":{"a":[1,"x",null,true],"b":2}}],"outcomes":["approve"]}`
	sum := sha256.Sum256([]byte(canonical))
	want := "sha256:" + hex.EncodeToString(sum[:])
	respelled := "{ \"closed\": true,\n \"fix\": [ {\"value\": \"appro\\u0076ed\", \"argument\": \"/status\"},\n" +
		` {"value": {"a": [1, "x", null, true], "b": 2}, "argument": "/meta"} ],` +
		` "outcomes": ["approve"], "bind": [{"fact": "/ticket/id", "argument": "/id"}] }`
	for _, text := range []string{base, respelled} {
		if got := mustPolicy(t, text).digest; got != want {
			t.Fatalf("%s: digest %s, want %s", text, got, want)
		}
	}
	seen := map[string]string{want: base}
	for _, other := range []string{
		// fix alone differs
		strings.Replace(base, `"value":"approved"`, `"value":"rejected"`, 1),
		strings.Replace(base, `"value":"approved"`, `"value":["approved"]`, 1),
		strings.Replace(base, `"b":2`, `"b":"2"`, 1),
		strings.Replace(base, `{"argument":"/status","value":"approved"},`, ``, 1),
		strings.Replace(base, `"fix":[{"argument":"/status","value":"approved"},{"argument":"/meta","value":{"b":2,"a":[1,"x",null,true]}}],`, `"fix":[],`, 1),
		strings.Replace(base, `"fix":[{"argument":"/status","value":"approved"},{"argument":"/meta","value":{"b":2,"a":[1,"x",null,true]}}],`, ``, 1),
		// the same entries in another order: the same checks, another digest
		strings.Replace(base, `{"argument":"/status","value":"approved"},{"argument":"/meta","value":{"b":2,"a":[1,"x",null,true]}}`, `{"argument":"/meta","value":{"b":2,"a":[1,"x",null,true]}},{"argument":"/status","value":"approved"}`, 1),
		// closed alone differs
		strings.Replace(base, `"closed":true`, `"closed":false`, 1),
		strings.Replace(base, `,"closed":true`, ``, 1),
	} {
		d := mustPolicy(t, other).digest
		if prior, ok := seen[d]; ok {
			t.Fatalf("two policies, one digest:\n%s\n%s", prior, other)
		}
		seen[d] = other
	}
}

// What a closed policy reaches, rule by rule (ADR-0016): a pointer covers
// what it names and everything under it; a container on the way to a named
// pointer has each member or element held in turn; anything else is
// refused, by its pointer.
func TestAClosedPolicyReachesArgumentsByTheirPointers(t *testing.T) {
	for _, tc := range []struct {
		named     []string
		arguments string
		want      string // the first pointer refused; "" when every one is reached
	}{
		{nil, `{}`, ""},
		{nil, `{"x":1}`, "/x"},
		{nil, `{"x":{}}`, "/x"},
		{[]string{""}, `{"x":[{"y":1}],"z":null}`, ""},
		{[]string{"/a"}, `{"a":{"anything":[1,{"b":2}]}}`, ""},
		{[]string{"/a/b"}, `{"a":{"b":1}}`, ""},
		{[]string{"/a/b"}, `{"a":{"b":1,"c":2}}`, "/a/c"},
		{[]string{"/a/b"}, `{"a":5}`, "/a"},
		{[]string{"/a/b"}, `{"a":"b"}`, "/a"},
		{[]string{"/a/b"}, `{"a":{}}`, ""},
		{[]string{"/ab"}, `{"a":{"b":1}}`, "/a"},
		{[]string{"/a/b", "/c"}, `{"c":[1],"a":{"b":{"deep":true}}}`, ""},
		// an array: each element by its index pointer, or the whole array
		{[]string{"/l/0"}, `{"l":[1]}`, ""},
		{[]string{"/l/0"}, `{"l":[1,2]}`, "/l/1"},
		{[]string{"/l/0"}, `{"l":[]}`, ""},
		{[]string{"/l"}, `{"l":[1,2,3]}`, ""},
		{[]string{"/l/0/op", "/l/1"}, `{"l":[{"op":"test"},{"op":"replace","value":1}]}`, ""},
		{[]string{"/l/0/op", "/l/1"}, `{"l":[{"op":"test","from":"/x"},{"op":"replace"}]}`, "/l/0/from"},
		{[]string{"/l/0/op", "/l/1"}, `{"l":[{"op":"test"},{"op":"replace"},{"op":"add"}]}`, "/l/2"},
		{[]string{"/l/01"}, `{"l":[1]}`, "/l/0"},
		{[]string{"/l/-"}, `{"l":[1]}`, "/l/0"},
		// an object's member named like an index is a member
		{[]string{"/o/01", "/o/-"}, `{"o":{"01":1,"-":2}}`, ""},
		// a member's token is its one RFC 6901 spelling
		{[]string{"/a~1b"}, `{"a/b":1}`, ""},
		{[]string{"/a~1b"}, `{"a~1b":1}`, "/a~01b"},
		{[]string{"/a~0b"}, `{"a~b":1}`, ""},
		{[]string{"/"}, `{"":1}`, ""},
		{[]string{"/"}, `{"":1,"x":2}`, "/x"},
	} {
		v, err := parseJSON([]byte(tc.arguments))
		if err != nil {
			t.Fatal(err)
		}
		got, found := unreachedArgument(v, tc.named, nil)
		if found != (tc.want != "") || got != tc.want {
			t.Fatalf("%q over %s: got %q (%v), want %q", tc.named, tc.arguments, got, found, tc.want)
		}
	}
}

// heldTicket is a write tool, update_ticket, of a remote binding at the
// in-process stand-in, held by an engine configuration to the policy given;
// a judgment cited, its record under the decision-record directory with the
// facts below; and a token to act with.
type heldTicket struct {
	server    *httptest.Server
	stand     *writeStandIn
	token     string
	recordRef string
	policy    string
}

const heldTicketFacts = `{"ticket":{"id":"T-7","revision":4,"sku":"S-1"},` +
	`"write":{"id":"T-7","lines":[{"sku":"S-1","qty":1}],"meta":{"source":"desk","tags":["refund",2,null]}}}`

func newHeldTicket(t *testing.T, bin, policy string) *heldTicket {
	t.Helper()
	return newHeldTicketAt(t, bin, "9", policy)
}

// newHeldTicketAt is newHeldTicket in a configuration of the engineVersion
// given.
func newHeldTicketAt(t *testing.T, bin, version, policy string) *heldTicket {
	t.Helper()
	stand := newWriteStandIn(t, `[{"name":"update_ticket","description":"Update a ticket.","inputSchema":{"type":"object"}}]`)
	binding := `{"bindingVersion":"1","platform":"tickets","operations":{"write":{"shape":"mcp","server":{"url":"` + stand.URL + `/mcp","bearer":"token"},"tools":["update_ticket"],"licence":"MIT"}}}`
	config := writeConfigAt(t, version, t.TempDir(), bin, "tickets", binding, "tickets", "", `{"update_ticket":`+policy+`}`)
	cfg, bindings, err := loadEngineConfig(config, stubAccounts(map[string]int{"engine-tickets": 1001}))
	if err != nil {
		t.Fatal(err)
	}
	spec := deriveSources(cfg, bindings)["tickets/write"]
	spec.user = ""
	service, server := testService(t)
	service.sources["tickets/write"] = spec
	service.decisionRecords = t.TempDir()
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	code, first := authed(t, server, "/acquire", `{"session":"held","source":"screening","arguments":{"q":"T-7"}}`, token)
	if code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, first)
	}
	signature := first["receipt"].(map[string]any)["signature"].(string)
	record := `{"recordVersion":"1","run":"4f1c2b3a5d6e7f80","at":"2026-10-14T10:00:00Z","kind":"evaluation","surface":"evaluate",` +
		`"tool":{"name":"jpack","version":"0.32.0"},"evaluatorSpecVersion":"1.0",` +
		`"pack":{"id":"tickets","version":"1.0.0","specVersion":"1.0","digest":"` + packA + `"},` +
		`"inputs":{"facts":` + heldTicketFacts + `,"evidence":null,"evidenceSupplied":false},"reviewed":true,` +
		`"cites":[{"sessionId":"held","callIndex":0,"signature":"` + signature + `"}],` +
		`"disposition":{"handoff":{"state":"none"},"kind":"outcome","outcomeId":"approve","reasons":[]}}`
	if err := os.WriteFile(filepath.Join(service.decisionRecords, "evaluations.jsonl"), []byte(record+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &heldTicket{server: server, stand: stand, token: token, policy: policy,
		recordRef: `"decision":{"recordDigest":"sha256:` + hexOf([]byte(record)) + `","packDigest":"` + packA + `"},` +
			`"cites":[{"sessionId":"held","callIndex":0,"signature":"` + signature + `"}]`}
}

// refused holds a request to a refusal at policy-bind saying want, with
// nothing at all sent to the server.
func (h *heldTicket) refused(t *testing.T, arguments, want string) {
	t.Helper()
	h.stand.forget()
	code, body := authed(t, h.server, "/act", `{"session":"held","platform":"tickets","tool":"update_ticket","arguments":`+arguments+`,`+h.recordRef+`}`, h.token)
	if code != http.StatusBadRequest || body["refusedAt"] != "policy-bind" || !strings.Contains(fmt.Sprint(body["error"]), want) {
		t.Fatalf("%s: want a refusal at policy-bind saying %q, got %d %v", arguments, want, code, body)
	}
	if seen := h.stand.requests(); len(seen) != 0 {
		t.Fatalf("%s: a write the policy refused reached the server: %+v", arguments, seen)
	}
}

// sent holds a request to one call at the server, of the arguments sent,
// and an action receipt naming the policy by its digest. arguments ""
// sends a request with no arguments member.
func (h *heldTicket) sent(t *testing.T, arguments string) {
	t.Helper()
	h.stand.forget()
	member := `"arguments":` + arguments + `,`
	if arguments == "" {
		member, arguments = ``, `{}`
	}
	code, body := authed(t, h.server, "/act", `{"session":"held","platform":"tickets","tool":"update_ticket",`+member+h.recordRef+`}`, h.token)
	if code != http.StatusOK {
		t.Fatalf("%s: act: %d %v", arguments, code, body)
	}
	if inner := body["receipt"].(map[string]any)["action"].(map[string]any); inner["policy"] != mustPolicy(t, h.policy).digest {
		t.Fatalf("%s: the receipt names the policy by its digest: %v", arguments, inner["policy"])
	}
	calls := 0
	for _, r := range h.stand.requests() {
		if r.method != "tools/call" {
			continue
		}
		calls++
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(r.params, &params); err != nil || params.Name != "update_ticket" || canonOf(t, string(params.Arguments)) != canonOf(t, arguments) {
			t.Fatalf("%s: the server got the write as asked, nothing filled in: %s", arguments, r.params)
		}
	}
	if calls != 1 {
		t.Fatalf("%s: the write was sent %d times", arguments, calls)
	}
}

// The check, through /act at policy-bind, over the in-process stand-in that
// counts every request: a refused write sends nothing at all, an admitted
// one is one call of exactly the arguments asked.
func TestActHoldsArgumentsToFixedValuesAndAClosedSet(t *testing.T) {
	bin, _ := buildMCPStandIns(t, t.TempDir())

	t.Run("fix", func(t *testing.T) {
		h := newHeldTicket(t, bin, `{"outcomes":["approve"],"bind":[{"argument":"/id","fact":"/ticket/id"}],`+
			`"fix":[{"argument":"/status","value":"approved"},{"argument":"/priority","value":2},{"argument":"/labels","value":{"team":"billing","tags":["refund"]}}]}`)
		labels := `"labels":{"team":"billing","tags":["refund"]}`
		h.refused(t, `{"id":"T-7","priority":2,`+labels+`}`, `argument "/status" is not the fixed value`)
		h.refused(t, `{"id":"T-7","status":null,"priority":2,`+labels+`}`, `argument "/status" is not the fixed value`)
		h.refused(t, `{"id":"T-7","status":"rejected","priority":2,`+labels+`}`, `argument "/status" is not the fixed value`)
		h.refused(t, `{"id":"T-7","status":"approved","priority":"2",`+labels+`}`, `argument "/priority" is not the fixed value`)
		h.refused(t, `{"id":"T-7","status":"approved","priority":2,"labels":{"team":"billing","tags":["refund"],"extra":true}}`, `argument "/labels" is not the fixed value`)
		h.refused(t, `{"id":"T-7","status":"approved","priority":2,"labels":{"team":"billing","tags":"refund"}}`, `argument "/labels" is not the fixed value`)
		// bind still holds first, and its sentence is its own
		h.refused(t, `{"id":"T-8","status":"approved","priority":2,`+labels+`}`, `the argument at "/id" does not equal the fact at "/ticket/id"`)
		// every fixed value there and equal, an object's members in another
		// order; a policy that is not closed admits a member it does not name
		h.sent(t, `{"note":"by hand","labels":{"tags":["refund"],"team":"billing"},"priority":2,"status":"approved","id":"T-7"}`)
	})

	t.Run("closed", func(t *testing.T) {
		h := newHeldTicket(t, bin, `{"outcomes":["approve"],"bind":[{"argument":"/id","fact":"/ticket/id"},{"argument":"/lines/0/sku","fact":"/ticket/sku"}],`+
			`"fix":[{"argument":"/status","value":"approved"},{"argument":"/lines/0/qty","value":1},{"argument":"/meta","value":{"source":"desk"}}],"closed":true}`)
		h.refused(t, `{"id":"T-7","status":"approved","lines":[{"sku":"S-1","qty":1}],"meta":{"source":"desk"},"note":"x"}`, `argument "/note" is reached by no binding`)
		h.refused(t, `{"id":"T-7","status":"approved","lines":[{"sku":"S-1","qty":1,"discount":5}],"meta":{"source":"desk"}}`, `argument "/lines/0/discount" is reached by no binding`)
		h.refused(t, `{"id":"T-7","status":"approved","lines":[{"sku":"S-1","qty":1},{"sku":"S-2","qty":1}],"meta":{"source":"desk"}}`, `argument "/lines/1" is reached by no binding`)
		h.refused(t, `{"id":"T-7","status":"approved","lines":[{"sku":"S-1","qty":1}],"meta":{"source":"desk"},"a/b~c":{}}`, `argument "/a~1b~0c" is reached by no binding`)
		// a fixed object is held whole by fix, not reached member by member
		h.refused(t, `{"id":"T-7","status":"approved","lines":[{"sku":"S-1","qty":1}],"meta":{"source":"desk","by":"x"}}`, `argument "/meta" is not the fixed value`)
		// every member reached, in another order than the policy's
		h.sent(t, `{"meta":{"source":"desk"},"lines":[{"qty":1,"sku":"S-1"}],"status":"approved","id":"T-7"}`)
	})

	t.Run("the root binding covers everything", func(t *testing.T) {
		h := newHeldTicket(t, bin, `{"outcomes":["approve"],"bind":[{"argument":"","fact":"/write"}],"closed":true}`)
		h.sent(t, `{"id":"T-7","lines":[{"sku":"S-1","qty":1}],"meta":{"tags":["refund",2,null],"source":"desk"}}`)
		h.refused(t, `{"id":"T-7","lines":[{"sku":"S-1","qty":1}],"meta":{"tags":["refund",2,null],"source":"desk"},"more":1}`, `the argument at "" does not equal the fact at "/write"`)
	})

	t.Run("closed with neither bind nor fix", func(t *testing.T) {
		h := newHeldTicket(t, bin, `{"outcomes":["approve"],"closed":true}`)
		h.sent(t, `{}`)
		h.sent(t, ``)
		h.refused(t, `{"id":"T-7"}`, `argument "/id" is reached by no binding`)
		h.refused(t, `{"x":{}}`, `argument "/x" is reached by no binding`)
		h.refused(t, `{"x":[]}`, `argument "/x" is reached by no binding`)
	})
}
