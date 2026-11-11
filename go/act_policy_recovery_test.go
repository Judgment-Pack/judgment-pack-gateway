package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A closed decision policy on a tool whose recovery names an idempotency
// argument (#380): the gateway sets that argument to the action key before
// the policy is checked (SPEC.md §1.2b), so the closed check reaches it as
// the gateway's -- exactly that member, holding exactly the key -- and
// nothing else it did not reach before. A policy that binds, fixes or shapes
// the argument is refused when the configuration is read.

// TestClosedRecoveryTarget is the write and read-back target of the tests
// below, a child of the test binary: in write mode it appends the request it
// was sent, its exact bytes on one line, to the file named, and answers; in
// drop mode it appends and exits without answering, as a write whose answer
// is lost; in read mode it appends the request to the file's .read sibling
// and answers the key it was asked for when a request it holds carried that
// key as its requestId.
func TestClosedRecoveryTarget(t *testing.T) {
	mode := os.Getenv("CLOSED_RECOVERY_MODE")
	if mode == "" {
		return
	}
	sent := os.Getenv("CLOSED_RECOVERY_SENT")
	request, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(3)
	}
	record := func(path string) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			os.Exit(4)
		}
		if _, err := f.Write(append(request, '\n')); err != nil {
			os.Exit(5)
		}
		if err := f.Sync(); err != nil {
			os.Exit(6)
		}
		f.Close()
	}
	found := ""
	switch mode {
	case "write", "drop":
		record(sent)
		if mode == "drop" {
			os.Exit(2)
		}
	case "read":
		record(sent + ".read")
		var asked struct {
			Arguments struct {
				Key string `json:"key"`
			} `json:"arguments"`
		}
		data, _ := os.ReadFile(sent)
		if json.Unmarshal(request, &asked) == nil && asked.Arguments.Key != "" {
			for _, line := range strings.Split(string(data), "\n") {
				var written struct {
					Arguments map[string]any `json:"arguments"`
				}
				if json.Unmarshal([]byte(line), &written) == nil && written.Arguments["requestId"] == asked.Arguments.Key {
					found = asked.Arguments.Key
				}
			}
		}
	default:
		os.Exit(7)
	}
	fmt.Printf(`{"result":{"key":%q,"state":"done"},"acquisition":{"adapter":{"name":"fixture","version":"1","digest":"sha256:%s"},"endpoint":null,"statement":null,"snapshot":null,"peerIdentity":null,"schema":null,"upstreamToken":null,"observedAt":"2026-11-10T00:00:00Z"}}`, found, strings.Repeat("a", 64))
	os.Exit(0)
}

// closedRecoveryDeclaration is the binding's recovery contract: update_ticket
// takes the key as its requestId and is read back by that argument;
// close_ticket declares no recovery.
const closedRecoveryDeclaration = `{"update_ticket":{"idempotencyArgument":"requestId","readBack":{"tool":"find_ticket","arguments":{"key":{"argument":"/requestId"}},"keyPointer":"/key","outcomePointer":"/state","committedValue":"done"}},"close_ticket":null}`

// The closed policies the two tools are held to: every other policy member
// alongside closed, so each is seen to behave as before.
const (
	closedUpdatePolicy = `{"outcomes":["approve"],"bind":[{"argument":"/id","fact":"/ticket/id"}],"fix":[{"argument":"/status","value":"approved"}],` +
		`"shape":[{"pointer":"/lines","type":"array","maxLength":1}],"closed":true}`
	closedClosePolicy = `{"outcomes":["approve"],"bind":[{"argument":"/id","fact":"/ticket/id"}],"closed":true}`
)

// closedRecovery is a gateway serving /act for the two tools, each held to
// its closed policy, over a target that records every request that reaches
// it; a judgment cited, and its record under the decision-record directory.
type closedRecovery struct {
	service  *gatewayService
	server   *httptest.Server
	token    string
	claims   string // the request's decision and cites members
	sentFile string // the file the write target appends each request to
}

func newClosedRecovery(t *testing.T, writeMode string) *closedRecovery {
	t.Helper()
	if !actionJournalSupported {
		t.Skip("keyed dispatch fails closed on this host")
	}
	service, server := testService(t)
	sent := filepath.Join(t.TempDir(), "sent")
	declaration, err := parseJSON([]byte(closedRecoveryDeclaration))
	if err != nil {
		t.Fatal(err)
	}
	b := binding{write: &operation{tools: []string{"update_ticket", "close_ticket"}},
		live: &operation{tools: []string{"find_ticket"}, taxonomies: map[string]ToolTaxonomy{"find_ticket": {Operation: "read", Effect: "read-external"}}}}
	recovery, err := parseActionRecovery(declaration, b)
	if err != nil {
		t.Fatal(err)
	}
	target := func(mode string, tools ...string) sourceSpec {
		return sourceSpec{argv: []string{os.Args[0], "-test.run=^TestClosedRecoveryTarget$"}, env: []string{"CLOSED_RECOVERY_MODE=" + mode, "CLOSED_RECOVERY_SENT=" + sent},
			shape: "mcp", tools: tools, binding: "tickets@sha256:" + strings.Repeat("b", 64), actionRecovery: recovery}
	}
	write := target(writeMode, "update_ticket", "close_ticket")
	write.policies = map[string]*decisionPolicy{"update_ticket": mustPolicy(t, closedUpdatePolicy), "close_ticket": mustPolicy(t, closedClosePolicy)}
	service.sources["tickets/write"] = write
	service.sources["tickets/live"] = target("read", "find_ticket")
	service.requireActionKey = true
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
	record := `{"recordVersion":"1","run":"4f1c2b3a5d6e7f80","at":"2026-11-10T10:00:00Z","kind":"evaluation","surface":"evaluate",` +
		`"tool":{"name":"jpack","version":"0.32.0"},"evaluatorSpecVersion":"1.0",` +
		`"pack":{"id":"tickets","version":"1.0.0","specVersion":"1.0","digest":"` + packA + `"},` +
		`"inputs":{"facts":{"ticket":{"id":"T-7"}},"evidence":null,"evidenceSupplied":false},"reviewed":true,` +
		`"cites":[{"sessionId":"held","callIndex":0,"signature":"` + signature + `"}],` +
		`"disposition":{"handoff":{"state":"none"},"kind":"outcome","outcomeId":"approve","reasons":[]}}`
	if err := os.WriteFile(filepath.Join(service.decisionRecords, "evaluations.jsonl"), []byte(record+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &closedRecovery{service: service, server: server, token: token, sentFile: sent,
		claims: `"decision":{"recordDigest":"sha256:` + hexOf([]byte(record)) + `","packDigest":"` + packA + `"},` +
			`"cites":[{"sessionId":"held","callIndex":0,"signature":"` + signature + `"}]`}
}

// act posts one action, keyed when key is not empty, and answers the status
// and the body's exact bytes.
func (c *closedRecovery) act(t *testing.T, tool, key, arguments string) (int, string) {
	t.Helper()
	member := ""
	if key != "" {
		member = `"actionKey":"` + key + `",`
	}
	body := `{"session":"held","platform":"tickets","tool":"` + tool + `",` + member + `"arguments":` + arguments + `,` + c.claims + `}`
	req, err := http.NewRequest(http.MethodPost, c.server.URL+"/act", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(data)
}

// received is every request the write target has been sent, each its exact
// bytes.
func (c *closedRecovery) received(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(c.sentFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

// refused holds an action to a 400 whose body is exactly want, with nothing
// sent to the target and no source started.
func (c *closedRecovery) refused(t *testing.T, tool, key, arguments, want string) {
	t.Helper()
	before, started := c.received(t), c.service.started.Load()
	code, body := c.act(t, tool, key, arguments)
	if code != http.StatusBadRequest || body != want {
		t.Fatalf("%s %s: want 400 %s, got %d %s", tool, arguments, want, code, body)
	}
	if after := c.received(t); len(after) != len(before) || c.service.started.Load() != started {
		t.Fatalf("%s %s: a refused write reached the target: %q", tool, arguments, after[len(before):])
	}
}

// sent holds an action to one request at the target of exactly the bytes
// want: the arguments asked, the idempotency argument holding the key, and
// nothing else.
func (c *closedRecovery) sent(t *testing.T, tool, key, arguments, want string) {
	t.Helper()
	before := c.received(t)
	code, body := c.act(t, tool, key, arguments)
	if code != http.StatusOK {
		t.Fatalf("%s %s: act: %d %s", tool, arguments, code, body)
	}
	after := c.received(t)
	if len(after) != len(before)+1 || after[len(before)] != want {
		t.Fatalf("%s %s: the target received %q, want exactly %s", tool, arguments, after[len(before):], want)
	}
}

func closedRecoveryKey(c byte) string { return strings.Repeat(string(c), 64) }

func TestAClosedPolicyReachesTheIdempotencyArgumentTheGatewaySets(t *testing.T) {
	c := newClosedRecovery(t, "write")
	unreached := func(pointer string) string {
		return `{"error":"argument \"` + pointer + `\" is reached by no binding","refusedAt":"policy-bind"}`
	}
	k := closedRecoveryKey
	// held is what the policy reaches of update_ticket's arguments: the bound
	// id, the fixed status and the shaped, empty lines.
	held := `"id":"T-7","status":"approved","lines":[]`
	written := func(key string) string {
		return `{"arguments":{"id":"T-7","lines":[],"requestId":"` + key + `","status":"approved"},"tool":"update_ticket"}`
	}

	// The argument omitted, or given equal to the key: the gateway's, reached.
	c.sent(t, "update_ticket", k('1'), `{`+held+`}`, written(k('1')))
	c.sent(t, "update_ticket", k('2'), `{"requestId":"`+k('2')+`",`+held+`}`, written(k('2')))
	// Given with another value: refused as before, at action-key, before the
	// policy is read.
	conflict := `{"error":"action-key-conflict: idempotency argument differs from actionKey","refusedAt":"action-key"}`
	c.refused(t, "update_ticket", k('3'), `{`+held+`,"requestId":"`+k('4')+`"}`, conflict)
	c.refused(t, "update_ticket", k('3'), `{`+held+`,"requestId":7}`, conflict)
	c.refused(t, "update_ticket", k('3'), `{`+held+`,"requestId":""}`, conflict)
	// Only that member: another argument no binding reaches is refused, one
	// holding the key's value among them, and so is the same name below the
	// top level.
	c.refused(t, "update_ticket", k('5'), `{`+held+`,"note":"x"}`, unreached("/note"))
	c.refused(t, "update_ticket", k('5'), `{`+held+`,"note":"`+k('5')+`"}`, unreached("/note"))
	c.refused(t, "update_ticket", k('5'), `{`+held+`,"meta":{"requestId":"`+k('5')+`"}}`, unreached("/meta"))
	c.refused(t, "update_ticket", k('5'), `{"id":"T-7","status":"approved","lines":["`+k('5')+`"]}`, unreached("/lines/0"))
	// bind, fix and shape, as before, each in its order.
	c.refused(t, "update_ticket", k('6'), `{"id":"T-8","status":"approved","lines":[]}`,
		`{"error":"the argument at \"/id\" does not equal the fact at \"/ticket/id\"","refusedAt":"policy-bind"}`)
	c.refused(t, "update_ticket", k('6'), `{"id":"T-7","status":"rejected","lines":[]}`,
		`{"error":"argument \"/status\" is not the fixed value","refusedAt":"policy-bind"}`)
	c.refused(t, "update_ticket", k('6'), `{"id":"T-7","status":"approved"}`,
		`{"error":"argument \"/lines\" is not of the shape the policy holds it to","refusedAt":"policy-bind"}`)
	c.refused(t, "update_ticket", k('6'), `{"id":"T-7","status":"approved","lines":[[],[]]}`,
		`{"error":"argument \"/lines\" holds more elements than the policy's shape allows","refusedAt":"policy-bind"}`)
	// A tool with no recovery: nothing is the gateway's, and a member of that
	// name holding the key is the caller's, refused as before.
	c.refused(t, "close_ticket", k('7'), `{"id":"T-7","requestId":"`+k('7')+`"}`, unreached("/requestId"))
	c.sent(t, "close_ticket", k('7'), `{"id":"T-7"}`, `{"arguments":{"id":"T-7"},"tool":"close_ticket"}`)

	// A request with no key, where none is required: the gateway sets
	// nothing, and the member is the caller's, refused whatever it holds.
	c.service.requireActionKey = false
	c.refused(t, "update_ticket", "", `{`+held+`,"requestId":"`+k('8')+`"}`, unreached("/requestId"))
	c.refused(t, "update_ticket", "", `{`+held+`,"requestId":""}`, unreached("/requestId"))
	c.sent(t, "update_ticket", "", `{`+held+`}`, `{"arguments":{"id":"T-7","lines":[],"status":"approved"},"tool":"update_ticket"}`)
}

// The read-back re-reads by the idempotency argument as before: a write whose
// answer is lost under a closed policy is read back by the requestId the
// gateway set, and reported committed.
func TestAClosedPolicysWriteIsReadBackByTheIdempotencyArgument(t *testing.T) {
	c := newClosedRecovery(t, "drop")
	key := closedRecoveryKey('9')
	code, body := c.act(t, "update_ticket", key, `{"id":"T-7","status":"approved","lines":[]}`)
	if code != http.StatusOK {
		t.Fatalf("act: %d %s", code, body)
	}
	var out struct {
		Reconciliation struct {
			Receipt struct {
				Acquisition struct {
					Reconciliation struct {
						Key, Outcome string
					} `json:"reconciliation"`
				} `json:"acquisition"`
			} `json:"receipt"`
		} `json:"reconciliation"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if got := out.Reconciliation.Receipt.Acquisition.Reconciliation; got.Key != key || got.Outcome != "committed" {
		t.Fatalf("read back %+v: %s", got, body)
	}
	if got := c.received(t); len(got) != 1 || got[0] != `{"arguments":{"id":"T-7","lines":[],"requestId":"`+key+`","status":"approved"},"tool":"update_ticket"}` {
		t.Fatalf("the write: %q", got)
	}
	read, err := os.ReadFile(c.sentFile + ".read")
	if err != nil || string(read) != `{"arguments":{"key":"`+key+`"},"tool":"find_ticket"}`+"\n" {
		t.Fatalf("the read-back: %q %v", read, err)
	}
}

// What the closed walk reaches of the gateway's argument (unreachedArgument):
// the one top-level member its pointer names, spelled as RFC 6901 spells it,
// and only while it holds the key. The step that sets it runs first, so on
// /act the value always is the key; the walk holds it to the key all the
// same, so that the rule does not rest on the order of the steps.
func TestTheClosedWalkReachesTheGatewaysArgumentByNameAndValue(t *testing.T) {
	key := closedRecoveryKey('c')
	for _, tc := range []struct {
		name      string // the idempotency argument; "" for a request the gateway supplies nothing to
		arguments string
		want      string // the first pointer refused; "" when every one is reached
	}{
		{"requestId", `{"requestId":"` + key + `"}`, ""},
		{"requestId", `{"requestId":"` + closedRecoveryKey('d') + `"}`, "/requestId"},
		{"requestId", `{"requestId":7}`, "/requestId"},
		{"requestId", `{"requestId":["` + key + `"]}`, "/requestId"},
		{"requestId", `{"requestId":"` + key + `","other":"` + key + `"}`, "/other"},
		{"requestId", `{"nested":{"requestId":"` + key + `"}}`, "/nested"},
		{"", `{"requestId":"` + key + `"}`, "/requestId"},
		// the name's one pointer spelling: "/" as "~1", "~" as "~0"
		{"a/b~c", `{"a/b~c":"` + key + `"}`, ""},
		{"a/b~c", `{"a":{"b~c":"` + key + `"}}`, "/a"},
		{"a~1b", `{"a/b":"` + key + `"}`, "/a~1b"},
		{"a~1b", `{"a~1b":"` + key + `"}`, ""},
	} {
		v, err := parseJSON([]byte(tc.arguments))
		if err != nil {
			t.Fatal(err)
		}
		var supplied *gatewayArgument
		if tc.name != "" {
			supplied = (&actionRecovery{idempotencyArgument: tc.name}).supplied(key)
		}
		got, found := unreachedArgument(v, nil, nil, supplied)
		if found != (tc.want != "") || got != tc.want {
			t.Fatalf("%q over %s: got %q (%v), want %q", tc.name, tc.arguments, got, found, tc.want)
		}
	}
	// The gateway supplies nothing for a tool with no recovery, one whose
	// recovery names no argument, or a request with no key.
	for name, supplied := range map[string]*gatewayArgument{
		"no recovery":         (*actionRecovery)(nil).supplied(key),
		"no argument":         (&actionRecovery{readBack: &actionReadBack{}}).supplied(key),
		"no key":              (&actionRecovery{idempotencyArgument: "requestId"}).supplied(""),
		"no recovery, no key": (*actionRecovery)(nil).supplied(""),
	} {
		if supplied != nil {
			t.Errorf("%s: the gateway supplies %+v", name, supplied)
		}
	}
}

// recoveryPolicyBinding is the policy fixture's binding at version 3, its
// execute tool taking the key as its requestId and drop declaring no
// recovery.
func recoveryPolicyBinding(argument string) string {
	b := strings.Replace(currentPolicyBinding, `"bindingVersion":"2"`, `"bindingVersion":"3"`, 1)
	return strings.TrimSuffix(b, "}") + `,"actionRecovery":{"execute":{"idempotencyArgument":` + argument + `},"drop":null}}`
}

// recoveryPolicyConfig is an engine configuration of one platform on that
// binding, its write tools held to the policies given.
func recoveryPolicyConfig(t *testing.T, bindingText, policies string) string {
	t.Helper()
	catalog := catalogWith(t, map[string]string{"postgres": bindingText})
	pins := `"operationDescriptors":{"live":"sha256:` + strings.Repeat("0", 64) + `","write":"sha256:` + strings.Repeat("1", 64) + `"}`
	text := engineJSON(t, catalog, ``, platformJSONFor(t, "warehouse", "postgres@"+digestOf(bindingText), "engine-warehouse",
		`,"write":true,`+pins+`,"decisionPolicy":`+policies, "history", "live", "write"))
	return strings.Replace(text, `"engineVersion":"1"`, `"engineVersion":"11"`, 1)
}

// The argument is the gateway's: a policy of the tool whose recovery names it
// neither binds, fixes nor shapes it, or a value under it, and a
// configuration that does is refused when it is read, saying so. A closed
// policy and the recovery together load, as does a policy naming the
// argument on a tool with no recovery, or a pointer that only begins with
// its name.
func TestAPolicyDoesNotHoldTheIdempotencyArgument(t *testing.T) {
	binding := recoveryPolicyBinding(`"requestId"`)
	held := func(entry string) string {
		return `platform warehouse: decisionPolicy.execute: ` + entry +
			`, which the gateway sets to the action key (actionRecovery); a policy neither binds, fixes nor shapes it, nor a value under it`
	}
	for _, tc := range []struct{ name, policies, want string }{
		{"bound", `{"execute":{"outcomes":["approve"],"bind":[{"argument":"/id","fact":"/id"},{"argument":"/requestId","fact":"/key"}],"closed":true}}`,
			held(`bind[1] names "/requestId", the tool's idempotency argument "requestId"`)},
		{"fixed", `{"execute":{"outcomes":["approve"],"fix":[{"argument":"/requestId","value":"k"}]}}`,
			held(`fix[0] names "/requestId", the tool's idempotency argument "requestId"`)},
		{"shaped", `{"execute":{"outcomes":["approve"],"shape":[{"pointer":"/requestId","type":"object"}],"closed":true}}`,
			held(`shape[0] names "/requestId", the tool's idempotency argument "requestId"`)},
		{"a value under it bound", `{"execute":{"outcomes":["approve"],"bind":[{"argument":"/requestId/0","fact":"/key"}]}}`,
			held(`bind[0] names "/requestId/0", under the tool's idempotency argument "requestId"`)},
		{"a value under it fixed, beside a policy for drop", `{"drop":{"outcomes":["approve"]},"execute":{"outcomes":["approve"],"fix":[{"argument":"/id","value":1},{"argument":"/requestId/a","value":1}]}}`,
			held(`fix[1] names "/requestId/a", under the tool's idempotency argument "requestId"`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := load(t, recoveryPolicyConfig(t, binding, tc.policies))
			if err == nil || err.Error() != tc.want {
				t.Fatalf("want %s\ngot  %v", tc.want, err)
			}
		})
	}
	// posture reads the configuration as serve does, and says the same.
	path := filepath.Join(t.TempDir(), "engine.json")
	if err := os.WriteFile(path, []byte(recoveryPolicyConfig(t, binding, `{"execute":{"outcomes":["approve"],"fix":[{"argument":"/requestId","value":"k"}]}}`)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := postureOfConfig(path, stubAccounts(stubUsers)); err == nil || err.Error() != held(`fix[0] names "/requestId", the tool's idempotency argument "requestId"`) {
		t.Fatalf("posture: %v", err)
	}
	// The name's one pointer spelling.
	escaped := recoveryPolicyBinding(`"a/b~c"`)
	if _, _, err := load(t, recoveryPolicyConfig(t, escaped, `{"execute":{"outcomes":["approve"],"bind":[{"argument":"/a~1b~0c","fact":"/key"}]}}`)); err == nil ||
		err.Error() != held(`bind[0] names "/a~1b~0c", the tool's idempotency argument "a/b~c"`) {
		t.Fatalf("an escaped name: %v", err)
	}
	for name, tc := range map[string]struct{ binding, policies string }{
		"closed with recovery, the observed configuration": {binding, `{"execute":{"outcomes":["approve"],"bind":[{"argument":"/id","fact":"/id"}],"closed":true}}`},
		"the name on the tool with no recovery":            {binding, `{"drop":{"outcomes":["approve"],"bind":[{"argument":"/requestId","fact":"/key"}],"closed":true}}`},
		"a pointer that only begins with the name":         {binding, `{"execute":{"outcomes":["approve"],"bind":[{"argument":"/requestIdentity","fact":"/key"},{"argument":"/requestI","fact":"/key"}]}}`},
		"the whole arguments":                              {binding, `{"execute":{"outcomes":["approve"],"bind":[{"argument":"","fact":"/write"}],"closed":true}}`},
		"the unescaped spelling of an escaped name":        {escaped, `{"execute":{"outcomes":["approve"],"bind":[{"argument":"/a/b~0c","fact":"/key"}]}}`},
		"a binding of version 2, with no recovery":         {currentPolicyBinding, `{"execute":{"outcomes":["approve"],"bind":[{"argument":"/requestId","fact":"/key"}],"closed":true}}`},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := load(t, recoveryPolicyConfig(t, tc.binding, tc.policies)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// connect --replace keeps a decision policy, and holds it to the binding it
// now pins as a load does: a kept policy that binds the argument the binding
// makes the gateway's is refused, saying why, and the file is left as it was.
func TestConnectRefusesAKeptPolicyHoldingTheIdempotencyArgument(t *testing.T) {
	binding := recoveryPolicyBinding(`"requestId"`)
	f := newConnectFixture(t, binding, ``)
	policy := `{"execute":{"outcomes":["approve"],"bind":[{"argument":"/requestId","fact":"/key"}],"closed":true}}`
	entry := `"warehouse":{"binding":"postgres@` + digestOf(binding) + `","credentials":{"history":{"file":"` + escapePath(f.credentials) + `"},"live":{"file":"` + escapePath(f.credentials) + `"},"write":{"file":"` + escapePath(f.credentials) + `"}},"user":"engine-warehouse","write":true,"operationDescriptors":{"live":"sha256:0000000000000000000000000000000000000000000000000000000000000000","write":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},"decisionPolicy":` + policy + `}`
	text := strings.Replace(strings.Replace(f.fileText(t), `"engineVersion":"1"`, `"engineVersion":"11"`, 1), `"platforms":{}`, `"platforms":{`+entry+`}`, 1)
	if err := os.WriteFile(f.config, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	req := f.request()
	req.replace = true
	req.write = true
	req.credentials = map[string]string{"history": f.credentials, "live": f.credentials, "write": f.credentials}
	_, err := connect(context.Background(), req, f.host, f.check)
	want := `platform warehouse carries a decisionPolicy, which --replace keeps: decisionPolicy.execute: bind[0] names "/requestId", the tool's idempotency argument "requestId", which the gateway sets to the action key (actionRecovery); a policy neither binds, fixes nor shapes it, nor a value under it`
	if err == nil || err.Error() != want {
		t.Fatalf("want %s\ngot  %v", want, err)
	}
	if f.fileText(t) != text {
		t.Fatal("a refused connect changed the file")
	}
}
