package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// writeRequestersAnswer is the whole body of a write-requesters refusal,
// byte for byte: one fixed sentence, naming no requester and no list.
const writeRequestersAnswer = `{"error":"the requester is not one the configuration's writeRequesters names for this tool","refusedAt":"write-requesters"}`

// requesterEntry is one {issuer, subject} as a configuration writes it.
func requesterEntry(issuer, subject string) string {
	return `{"issuer":"` + issuer + `","subject":"` + subject + `"}`
}

// requestersFrom parses a writeRequesters member as the configuration's
// parser does, for a platform named tickets.
func requestersFrom(t *testing.T, text, issuer string, delegation bool) *writeRequesters {
	t.Helper()
	v, err := parseJSON([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	w, err := parseWriteRequesters(v, "tickets", issuer, delegation)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// rawPost posts body to url with the headers given, and returns the status,
// the response's headers and its bytes as sent.
func rawPost(t *testing.T, url, body string, headers map[string]string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, raw
}

// requestersFixture is a gateway with an identity, a write platform of two
// tools whose target is this test binary, and a receipt and a decision
// record an action may cite.
type requestersFixture struct {
	service           *gatewayService
	server            *httptest.Server
	issuer            *testIssuer
	stdin             string
	signature, record string
}

func newRequestersFixture(t *testing.T) *requestersFixture {
	t.Helper()
	service, server := testService(t)
	env, _ := goodEnvelope()
	t.Setenv(envSourceEnvelope, envelopeText(t, env))
	service.sources["tickets/write"] = sourceSpec{argv: []string{os.Args[0], "--tools=update_ticket,delete_ticket"}, env: helperEnv, shape: "mcp", tools: []string{"update_ticket", "delete_ticket"}, endpoint: "https://mcp.example/"}
	service.decisionRecords = t.TempDir()
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	f := &requestersFixture{service: service, server: server, issuer: issuer}
	code, first := authed(t, server, "/acquire", `{"session":"wr-1","source":"screening","arguments":{"q":"example"}}`, f.token(t, "user-7"))
	if code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, first)
	}
	f.signature = first["receipt"].(map[string]any)["signature"].(string)
	line := `{"kind":"evaluation","cites":[{"sessionId":"wr-1","callIndex":0,"signature":"` + f.signature + `"}]}`
	if err := os.WriteFile(filepath.Join(service.decisionRecords, "evaluations.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.record = "sha256:" + hexOf([]byte(line))
	// Set after the acquisition, so the file holds only what a write's
	// target was sent.
	f.stdin = filepath.Join(t.TempDir(), "stdin")
	t.Setenv(envSourceStdinFile, f.stdin)
	return f
}

// token is a token of the configured issuer for subject.
func (f *requestersFixture) token(t *testing.T, subject string) string {
	t.Helper()
	now := time.Now()
	return f.issuer.mint(t, "ec-1", nil, map[string]any{"iss": "https://login.example", "sub": subject, "aud": "gateway:acme", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix()})
}

func (f *requestersFixture) hold(w *writeRequesters) {
	spec := f.service.sources["tickets/write"]
	spec.requesters = w
	f.service.sources["tickets/write"] = spec
}

func (f *requestersFixture) body(tool, arguments, extra string) string {
	return `{"session":"wr-1","platform":"tickets","tool":"` + tool + `","arguments":` + arguments + `,` +
		`"decision":{"recordDigest":"` + f.record + `","packDigest":"sha256:` + strings.Repeat("b", 64) + `"},` +
		`"cites":[{"sessionId":"wr-1","callIndex":0,"signature":"` + f.signature + `"}]` + extra + `}`
}

// act asks for a write through tool as subject, with body, and answers the
// status, the bytes answered, the bytes the target read (nil when no target
// ran) and whether the answer challenged for a bearer token.
func (f *requestersFixture) act(t *testing.T, subject, body string) (int, []byte, []byte, bool) {
	t.Helper()
	if err := os.Remove(f.stdin); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	started := f.service.started.Load()
	code, header, raw := rawPost(t, f.server.URL+"/act", body, map[string]string{"Authorization": "Bearer " + f.token(t, subject)})
	sent, err := os.ReadFile(f.stdin)
	switch {
	case errors.Is(err, os.ErrNotExist):
		sent = nil
	case err != nil:
		t.Fatal(err)
	}
	if ran := f.service.started.Load() != started; ran != (sent != nil) {
		t.Fatalf("a target started: %v, and recorded what it read: %v", ran, sent != nil)
	}
	return code, raw, sent, header.Get("WWW-Authenticate") != ""
}

// sentFor is what the target of a write through tool reads for arguments
// {"id":"T-1"}: the canonical request, the tool and the arguments.
func sentFor(tool string) string {
	return `{"arguments":{"id":"T-1"},"tool":"` + tool + `"}`
}

// wantAdmitted asks as subject through tool and wants the write sent, the
// target given exactly the request, and the receipt naming subject.
func (f *requestersFixture) wantAdmitted(t *testing.T, subject, tool string) {
	t.Helper()
	code, raw, sent, _ := f.act(t, subject, f.body(tool, `{"id":"T-1"}`, ""))
	if code != http.StatusOK || string(sent) != sentFor(tool) {
		t.Fatalf("%s through %s: %d %s, the target read %q", subject, tool, code, raw, sent)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	requester := out["receipt"].(map[string]any)["action"].(map[string]any)["requester"].(map[string]any)
	if requester["issuer"] != "https://login.example" || requester["subject"] != subject {
		t.Fatalf("the receipt names %v", requester)
	}
}

// wantRefused asks as subject through tool with body and wants the fixed
// refusal, nothing run and nothing minted.
func (f *requestersFixture) wantRefused(t *testing.T, subject, body string) {
	t.Helper()
	before := f.receipts(t)
	code, raw, sent, challenged := f.act(t, subject, body)
	if code != http.StatusForbidden || string(raw) != writeRequestersAnswer || sent != nil || challenged {
		t.Fatalf("%q: %d %s, the target read %q, challenged %v", subject, code, raw, sent, challenged)
	}
	if after := f.receipts(t); after != before {
		t.Fatalf("a refusal wrote to the store:\n%s\nthen\n%s", before, after)
	}
}

// receipts is every file the store holds, with its size: a refusal
// mints no receipt and records nothing else.
func (f *requestersFixture) receipts(t *testing.T) string {
	t.Helper()
	var files []string
	err := filepath.Walk(f.service.storeRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, fmt.Sprintf("%s:%d", path, info.Size()))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(files, "\n")
}

// An absent member changes nothing: every requester the identity
// authenticates asks for a write through every tool, and the target reads
// exactly the request.
func TestWriteRequestersAbsentChangesNothing(t *testing.T) {
	f := newRequestersFixture(t)
	for _, subject := range []string{"user-7", "user-8", "User-7"} {
		for _, tool := range []string{"update_ticket", "delete_ticket"} {
			f.wantAdmitted(t, subject, tool)
		}
	}
	// The request the target reads, written out by hand.
	_, _, sent, _ := f.act(t, "user-9", f.body("update_ticket", `{"id":"T-1"}`, ""))
	if string(sent) != `{"arguments":{"id":"T-1"},"tool":"update_ticket"}` {
		t.Fatalf("the target read %q", sent)
	}
}

// Each list admits exactly the requesters it names: the platform's for a
// tool with none of its own, the tool's own in place of the platform's, and
// nobody for a list that is present and empty.
func TestWriteRequestersAdmitOnlyTheRequestersNamed(t *testing.T) {
	f := newRequestersFixture(t)
	const iss = "https://login.example"
	u7, u8 := requesterEntry(iss, "user-7"), requesterEntry(iss, "user-8")
	type asks map[string][]string // by tool, the subjects asking
	for _, c := range []struct {
		name, member      string
		admitted, refused asks
	}{
		{"a platform list", `{"platform":[` + u7 + `]}`,
			asks{"update_ticket": {"user-7"}, "delete_ticket": {"user-7"}},
			asks{"update_ticket": {"user-8"}, "delete_ticket": {"user-8"}}},
		{"two requesters", `{"platform":[` + u7 + `,` + u8 + `]}`,
			asks{"update_ticket": {"user-7", "user-8"}, "delete_ticket": {"user-7", "user-8"}},
			asks{"update_ticket": {"user-9"}}},
		{"a tool's own list in place of the platform's", `{"platform":[` + u7 + `],"tools":{"delete_ticket":[` + u8 + `]}}`,
			asks{"update_ticket": {"user-7"}, "delete_ticket": {"user-8"}},
			asks{"update_ticket": {"user-8"}, "delete_ticket": {"user-7"}}},
		{"a tool's list and no platform list", `{"tools":{"delete_ticket":[` + u8 + `]}}`,
			asks{"update_ticket": {"user-7", "user-9"}, "delete_ticket": {"user-8"}},
			asks{"delete_ticket": {"user-7"}}},
		{"an empty platform list", `{"platform":[]}`,
			asks{},
			asks{"update_ticket": {"user-7", "user-8"}, "delete_ticket": {"user-7", "user-8"}}},
		{"an empty tool list", `{"platform":[` + u7 + `],"tools":{"delete_ticket":[]}}`,
			asks{"update_ticket": {"user-7"}},
			asks{"update_ticket": {"user-8"}, "delete_ticket": {"user-7", "user-8"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f.hold(requestersFrom(t, c.member, iss, false))
			for tool, subjects := range c.admitted {
				for _, subject := range subjects {
					f.wantAdmitted(t, subject, tool)
				}
			}
			for tool, subjects := range c.refused {
				for _, subject := range subjects {
					f.wantRefused(t, subject, f.body(tool, `{"id":"T-1"}`, ""))
				}
			}
		})
	}
}

// A requester is compared byte for byte, issuer and subject: no case
// folding, no trimming, no Unicode normalization, no look-alike, and no
// subject of one issuer is another issuer's.
func TestWriteRequestersCompareExactly(t *testing.T) {
	f := newRequestersFixture(t)
	const iss = "https://login.example"
	f.hold(requestersFrom(t, `{"platform":[`+requesterEntry(iss, "user-7")+`,`+requesterEntry(iss, "café-7")+`]}`, iss, false))
	f.wantAdmitted(t, "user-7", "update_ticket")
	f.wantAdmitted(t, "café-7", "update_ticket")
	for _, near := range []string{
		"User-7", "USER-7", "user-7 ", " user-7", "user-7\t", "user-07",
		"user‑7",  // a non-breaking hyphen
		"uѕer-7",  // a Cyrillic dze for the s
		"user-7​", // a zero-width space after
		"café-7", // the same text decomposed
		"CAFÉ-7",
	} {
		f.wantRefused(t, near, f.body("update_ticket", `{"id":"T-1"}`, ""))
	}
	// The same subject of another issuer, or of the issuer spelled
	// otherwise, is not the requester: a token of the configured issuer
	// for user-7 is refused by a list naming user-7 of any other.
	for _, other := range []string{"https://other.example", "https://LOGIN.example", "https://login.example/", "https://login.example "} {
		f.hold(requestersFrom(t, `{"platform":[`+requesterEntry(other, "user-7")+`]}`, iss, true))
		f.wantRefused(t, "user-7", f.body("update_ticket", `{"id":"T-1"}`, ""))
	}
}

// The requester is held before anything else of the request is read: a
// requester the list does not name, asking with a bad action key, arguments
// a policy refuses and a decision of no form, is answered the requester's
// refusal, and one it names is answered at each later step in its turn.
func TestWriteRequestersHoldBeforeTheKeyAndThePolicy(t *testing.T) {
	f := newRequestersFixture(t)
	const iss = "https://login.example"
	spec := f.service.sources["tickets/write"]
	spec.policies = map[string]*decisionPolicy{"update_ticket": mustPolicy(t, `{"outcomes":["approve"],"fix":[{"argument":"/action","value":"update"}]}`)}
	f.service.sources["tickets/write"] = spec
	f.hold(requestersFrom(t, `{"platform":[`+requesterEntry(iss, "user-7")+`]}`, iss, false))
	violating := `{"id":"T-1","action":"delete"}`
	badDecision := func(body string) string { return strings.Replace(body, f.record, "sha256:abc", 1) }
	for _, c := range []struct{ name, body, admittedAt string }{
		{"a bad key, a policy's argument and no decision", badDecision(f.body("update_ticket", violating, `,"actionKey":"not-a-key"`)), "action-key"},
		{"arguments that are not an object", f.body("update_ticket", `[1]`, `,"actionKey":"not-a-key"`), "arguments"},
		{"a decision of no form", badDecision(f.body("update_ticket", violating, "")), "decision"},
		{"arguments a policy refuses", f.body("update_ticket", violating, ""), "record"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f.wantRefused(t, "user-8", c.body)
			code, raw, sent, _ := f.act(t, "user-7", c.body)
			out := map[string]any{}
			_ = json.Unmarshal(raw, &out)
			if code != http.StatusBadRequest || out["refusedAt"] != c.admittedAt || sent != nil {
				t.Fatalf("the requester named: %d %s, want a refusal at %s", code, raw, c.admittedAt)
			}
		})
	}
	// The steps before the tool is known answer every requester alike, as
	// they did: the restriction is on a tool's writes, and which tools a
	// platform offers is the binding's, not a requester's.
	code, raw, _, _ := f.act(t, "user-8", f.body("close_ticket", `{"id":"T-1"}`, ""))
	if out := map[string]any{}; code != http.StatusBadRequest || json.Unmarshal(raw, &out) != nil || out["refusedAt"] != "tool" {
		t.Fatalf("a tool the binding does not name: %d %s", code, raw)
	}
	// No token is the ladder's first step, whatever the lists say.
	if status, header, raw := rawPost(t, f.server.URL+"/act", f.body("update_ticket", `{"id":"T-1"}`, ""), nil); status != http.StatusUnauthorized || header.Get("WWW-Authenticate") == "" || strings.Contains(string(raw), "write-requesters") {
		t.Fatalf("no token: %d %s", status, raw)
	}
}

// Every route to a write is held: a keyed first send, a replay of the key,
// its reconciliation and the read-back of an uncertain key, a delegated
// run's actor, and each sender that names a reservation -- each to the
// requester the receipt names, the delegation's subject, never the agent or
// the token that sends the request.
func TestWriteRequestersHoldEveryRouteToAWrite(t *testing.T) {
	h := newDelegationHarness(t, false)
	hold := func(text string) {
		t.Helper()
		spec := h.g.sources["tickets/write"]
		spec.requesters = requestersFrom(t, text, testIssuerURL, true)
		h.g.sources["tickets/write"] = spec
	}
	refused := func(step string, body string, headers map[string]string, key string) {
		t.Helper()
		started, sent := h.g.started.Load(), h.sent(key)
		status, _, raw := rawPost(t, h.server.URL+"/act", body, headers)
		if status != http.StatusForbidden || string(raw) != writeRequestersAnswer {
			t.Fatalf("%s: %d %s", step, status, raw)
		}
		if h.g.started.Load() != started || h.sent(key) != sent {
			t.Fatalf("%s: a source ran for a refused requester", step)
		}
	}
	bearer := func(subject string) map[string]string {
		return map[string]string{"Authorization": "Bearer " + h.token(t, subject)}
	}
	alice := requesterEntry(testIssuerURL, "alice")

	// A keyed first send: refused for bob, nothing journaled; sent for alice.
	hold(`{"platform":[` + alice + `]}`)
	first := delegationKey(1)
	refused("a first send", h.actBody("k1", first, ""), bearer("bob"), first)
	journalAbsent(t, h.g, h.g.actionNamespace(&caller{issuer: testIssuerURL, subject: "bob"}, first))
	if status, out := h.post(t, "/act", h.actBody("k1", first, ""), bearer("alice")); status != http.StatusOK || h.sent(first) != 1 {
		t.Fatalf("alice: %d %v", status, out)
	}
	// A replay and a reconciliation of the key, once alice is no longer
	// named (a configuration restarted with a narrower list): refused, the
	// retained answer withheld, and nothing read back.
	hold(`{"platform":[` + requesterEntry(testIssuerURL, "carol") + `]}`)
	refused("a replay", h.actBody("k2", first, ""), bearer("alice"), first)
	refused("a reconciliation", h.actBody("k3", first, withKeyScope+withReconcile), bearer("alice"), first)
	// The read-back of an uncertain key.
	actionKeysMode(t, h.root, "write", "drop")
	hold(`{"platform":[` + alice + `]}`)
	uncertain := delegationKey(2)
	if status, out := h.post(t, "/act", h.actBody("k4", uncertain, ""), bearer("alice")); status != http.StatusOK || h.sent(uncertain) != 1 {
		t.Fatalf("an uncertain send: %d %v", status, out)
	}
	hold(`{"platform":[]}`)
	refused("the read-back of an uncertain key", h.actBody("k5", uncertain, ""), bearer("alice"), uncertain)
	actionKeysMode(t, h.root, "write", "respond")

	// A delegated run's actor: the requester is the delegation's subject.
	cred := h.credential(t, statement(t, nil))
	presented := func() map[string]string {
		return map[string]string{"Authorization": "DPoP " + cred, "DPoP": h.proof(t, "/act", cred, nil, nil)}
	}
	delegated := delegationKey(3)
	for _, c := range []struct{ name, member string }{
		{"a list naming the agent", `{"platform":[` + requesterEntry("desk", rootAgent) + `]}`},
		{"a list naming the issuing host", `{"platform":[` + requesterEntry(testIssuerURL, hostRequester) + `]}`},
		{"the subject of another issuer", `{"platform":[` + requesterEntry("https://other.example", testSubjectSub) + `]}`},
	} {
		hold(c.member)
		refused("the actor under "+c.name, h.actBody("d1", delegated, ""), presented(), delegated)
	}
	hold(`{"platform":[` + requesterEntry(testIssuerURL, testSubjectSub) + `]}`)
	status, out := h.post(t, "/act", h.actBody("d1", delegated, ""), presented())
	if status != http.StatusOK || h.sent(delegated) != 1 {
		t.Fatalf("the actor of the subject named: %d %v", status, out)
	}
	if requester := out["receipt"].(map[string]any)["action"].(map[string]any)["requester"].(map[string]any); requester["subject"] != testSubjectSub || requester["issuer"] != testIssuerURL {
		t.Fatalf("the receipt names %v", requester)
	}

	// Each sender naming the reservation reaches the key as the subject's
	// request: admitted where the subject is named, refused where only the
	// sender's own token subject is.
	reservation := h.reservationOf(testSub(), rootAgent)
	for i, sender := range []string{testSubjectSub, hostRequester, testOperator} {
		session := fmt.Sprintf("r-%d", i)
		hold(`{"platform":[` + requesterEntry(testIssuerURL, testSubjectSub) + `]}`)
		if status, out := h.post(t, "/act", h.actBody(session, delegated, reservation), bearer(sender)); status != http.StatusOK || h.sent(delegated) != 1 {
			t.Fatalf("%s for the subject named: %d %v", sender, status, out)
		}
		hold(`{"platform":[` + requesterEntry(testIssuerURL, hostRequester) + `,` + requesterEntry(testIssuerURL, testOperator) + `]}`)
		refused(sender+" for a subject not named", h.actBody(session, delegated, reservation), bearer(sender), delegated)
	}
}

// The member as a configuration carries it (engine version 18): read into
// the platform and onto its write source alone, refused at an earlier
// version by name, and held to its shape with a refusal that names the
// entry and never repeats a requester.
func TestWriteRequestersConfiguration(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	const iss = "https://login.example"
	identity := `,"identity":{"issuer":"` + iss + `","audience":"gateway:acme","keys":"` + abs(t, t.TempDir(), "keys.json") + `"}`
	pub := hex.EncodeToString(ed25519.NewKeyFromSeed(delegationHostSeed).Public().(ed25519.PublicKey))
	delegation := `,"delegation":` + delegationConfigText(pub, "https://desk.example/admission", abs(t, t.TempDir(), "desk-token"), "")
	config := func(version, top, platformExtra string) string {
		text := engineJSON(t, catalog, top, platformJSONFor(t, "warehouse", ref, "engine-warehouse", platformExtra, "history", "live", "write"))
		return strings.Replace(text, `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
	}
	u7 := requesterEntry(iss, "user-7")
	member := func(text string) string { return `,"write":true,"writeRequesters":` + text }
	good := member(`{"platform":[` + u7 + `],"tools":{"drop":[]}}`)
	cfg, sources, err := load(t, config("18", identity, good))
	if err != nil {
		t.Fatal(err)
	}
	want := &writeRequesters{platform: map[requesterRef]bool{{iss, "user-7"}: true}, tools: map[string]map[requesterRef]bool{"drop": {}}}
	if !reflect.DeepEqual(cfg.platforms[0].requesters, want) || !reflect.DeepEqual(sources["warehouse/write"].requesters, want) {
		t.Fatalf("the member: %+v, on the write source %+v", cfg.platforms[0].requesters, sources["warehouse/write"].requesters)
	}
	for _, name := range []string{"warehouse/live", "warehouse/history"} {
		if sources[name].requesters != nil {
			t.Fatalf("%s carries the member", name)
		}
	}
	// Without the member, nothing is held at any version, and the sources
	// are the ones an earlier version derives.
	_, at18, err := load(t, config("18", identity, `,"write":true`))
	if err != nil || at18["warehouse/write"].requesters != nil {
		t.Fatalf("no member: %v", err)
	}
	// With a delegation, an entry may name a subject of another issuer,
	// which a delegation's chain may carry.
	if _, sources, err := load(t, config("18", identity+delegation, member(`{"platform":[`+requesterEntry("https://other.example", "user-7")+`]}`))); err != nil || !sources["warehouse/write"].requesters.platform[requesterRef{"https://other.example", "user-7"}] {
		t.Fatalf("another issuer under a delegation: %v", err)
	}
	const at = "engine configuration: platform warehouse: writeRequesters"
	for _, c := range []struct{ name, text, want string }{
		{"a version-17 file", config("17", identity, good), "engine configuration: platform warehouse: writeRequesters is a version-18 member; engineVersion 17 has no writeRequesters"},
		{"a version-1 file", config("1", identity, good), "engine configuration: platform warehouse: writeRequesters is a version-18 member; engineVersion 1 has no writeRequesters"},
		{"a platform that allows no write", config("18", identity, strings.Replace(good, `,"write":true`, ``, 1)), at + " holds write tools to their requesters, and the platform does not set write: true"},
		{"write false", config("18", identity, strings.Replace(good, `"write":true`, `"write":false`, 1)), at + " holds write tools to their requesters, and the platform does not set write: true"},
		{"no identity", config("18", ``, good), at + " needs identity: a requester is who a bearer token or a delegation authenticates, and with no identity nobody is"},
		{"not an object", config("18", identity, member(`[`+u7+`]`)), at + " must be an object of platform, tools or both"},
		{"an empty object", config("18", identity, member(`{}`)), at + " names neither platform nor tools, and restricts nothing"},
		{"an unknown member", config("18", identity, member(`{"platform":[],"subjects":[]}`)), at + `: unknown member "subjects"`},
		{"a claim match", config("18", identity, member(`{"platform":[],"claims":{"groups":"writers"}}`)), at + `: unknown member "claims"`},
		{"a member twice", config("18", identity, member(`{"platform":[],"platform":[]}`)), `engine configuration: duplicate member name "platform"`},
		{"a platform list not an array", config("18", identity, member(`{"platform":`+u7+`}`)), at + ".platform must be an array of requesters, each {issuer, subject}"},
		{"tools not an object", config("18", identity, member(`{"tools":[]}`)), at + ".tools, when present, is an object naming at least one write tool"},
		{"tools naming none", config("18", identity, member(`{"tools":{}}`)), at + ".tools, when present, is an object naming at least one write tool"},
		{"a tool by the empty string", config("18", identity, member(`{"tools":{"":[]}}`)), at + ".tools names a tool by the empty string"},
		{"a tool twice", config("18", identity, member(`{"tools":{"drop":[],"drop":[]}}`)), `engine configuration: duplicate member name "drop"`},
		{"a tool's list not an array", config("18", identity, member(`{"tools":{"drop":"user-7"}}`)), at + ".tools.drop must be an array of requesters, each {issuer, subject}"},
		{"an entry that is a string", config("18", identity, member(`{"platform":["user-7"]}`)), at + ".platform[0] must be an object of issuer and subject"},
		{"an entry without its subject", config("18", identity, member(`{"platform":[{"issuer":"`+iss+`"}]}`)), at + `.platform[0]: missing member "subject"`},
		{"an entry without its issuer", config("18", identity, member(`{"platform":[{"subject":"user-7"}]}`)), at + `.platform[0]: missing member "issuer"`},
		{"an entry with a member beyond its two", config("18", identity, member(`{"platform":[{"issuer":"`+iss+`","subject":"user-7","audience":"gateway:acme"}]}`)), at + `.platform[0]: unknown member "audience"`},
		{"an empty subject", config("18", identity, member(`{"platform":[`+u7+`,`+requesterEntry(iss, "")+`]}`)), at + ".platform[1]: subject must be a non-empty string"},
		{"an empty issuer", config("18", identity, member(`{"tools":{"drop":[`+requesterEntry("", "user-7")+`]}}`)), at + ".tools.drop[0]: issuer must be a non-empty string"},
		{"a subject that is not a string", config("18", identity, member(`{"platform":[{"issuer":"`+iss+`","subject":7}]}`)), at + ".platform[0]: subject must be a non-empty string"},
		{"a requester twice", config("18", identity, member(`{"platform":[`+u7+`,`+requesterEntry(iss, "user-8")+`,`+u7+`]}`)), at + ".platform[2] names a requester an earlier entry of the list names"},
		{"a requester twice in a tool's list", config("18", identity, member(`{"tools":{"execute":[`+u7+`,`+u7+`]}}`)), at + ".tools.execute[1] names a requester an earlier entry of the list names"},
		{"another issuer with no delegation", config("18", identity, member(`{"platform":[`+requesterEntry("https://other.example", "user-7")+`]}`)), at + ".platform[0]: issuer is not identity.issuer, and with no delegation configured every requester is of identity.issuer"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := load(t, c.text)
			if err == nil || err.Error() != c.want {
				t.Fatalf("want %q, got %v", c.want, err)
			}
			if strings.Contains(err.Error(), "user-7") || strings.Contains(err.Error(), "user-8") {
				t.Fatalf("the refusal repeats a requester: %v", err)
			}
			// posture reads the configuration as serve does, and refuses it alike.
			path := filepath.Join(t.TempDir(), "engine.json")
			if err := os.WriteFile(path, []byte(c.text), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := postureOfConfig(path, stubAccounts(stubUsers)); err == nil || err.Error() != c.want {
				t.Fatalf("posture: want %q, got %v", c.want, err)
			}
		})
	}
	// Judged against the binding: a tool its write operation does not name.
	if _, _, err := load(t, config("18", identity, member(`{"tools":{"update_ticket":[`+u7+`]}}`))); err == nil || err.Error() != `platform warehouse: writeRequesters names tool "update_ticket", which the binding's write operation does not name` {
		t.Fatalf("a tool the binding does not name: %v", err)
	}
}

// posture reports that write tools are held to their requesters, by count
// alone, and a configuration that gives no platform the member reports
// what it did.
func TestWriteRequestersPosture(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	const iss = "https://login.example"
	identity := `,"identity":{"issuer":"` + iss + `","audience":"gateway:acme","keys":"` + abs(t, t.TempDir(), "keys.json") + `"}`
	lineOf := func(t *testing.T, platformExtra string) (postureLine, bool) {
		t.Helper()
		text := strings.Replace(engineJSON(t, catalog, identity, platformJSONFor(t, "warehouse", ref, "engine-warehouse", platformExtra, "history", "live", "write")), `"engineVersion":"1"`, `"engineVersion":"18"`, 1)
		path := filepath.Join(t.TempDir(), "engine.json")
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		in, err := postureOfConfig(path, stubAccounts(stubUsers))
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range hostPosture(in).lines {
			if l.name == protectionWriteRequesters {
				return l, true
			}
		}
		return postureLine{}, false
	}
	u7 := requesterEntry(iss, "user-7")
	for _, c := range []struct{ name, member, state, reason string }{
		{"every tool held", `{"platform":[` + u7 + `]}`, postureEnforced,
			"each of the 2 write tools admits a write only from a requester its writeRequesters list names"},
		{"every tool held, one by its own empty list", `{"platform":[` + u7 + `],"tools":{"drop":[]}}`, postureEnforced,
			"each of the 2 write tools admits a write only from a requester its writeRequesters list names"},
		{"one tool held", `{"tools":{"drop":[` + u7 + `]}}`, postureNotEnforced,
			"1 of the 2 write tools admits a write only from a requester a writeRequesters list names; the other 1 admits any requester the identity or a delegation authenticates"},
	} {
		t.Run(c.name, func(t *testing.T) {
			l, reported := lineOf(t, `,"write":true,"writeRequesters":`+c.member)
			if !reported || l.state != c.state || l.reason != c.reason {
				t.Fatalf("%v %+v", reported, l)
			}
		})
	}
	if l, reported := lineOf(t, `,"write":true`); reported {
		t.Fatalf("a configuration without the member reports %+v", l)
	}
	// /posture serves the same line, and names no requester.
	service, server := testService(t)
	service.sources["tickets/write"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv, shape: "mcp", tools: []string{"update_ticket"}, requesters: requestersFrom(t, `{"platform":[`+u7+`]}`, iss, false)}
	resp, err := http.Get(server.URL + "/posture")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if state, reason := postureLineIn(t, body, protectionWriteRequesters); state != postureEnforced || reason != "the 1 write tool admits a write only from a requester its writeRequesters list names" {
		t.Fatalf("/posture: %s %q", state, reason)
	}
	if strings.Contains(string(body), "user-7") || strings.Contains(string(body), iss) {
		t.Fatalf("/posture names a requester: %s", body)
	}
}

// connect --replace keeps the member, which connect has no flag for: an
// entry written without it would admit every requester to the writes it
// restricted. A replacement it would no longer fit -- no --write, or a
// binding whose write operation no longer names a tool it lists -- is
// refused before anything is asked, and the file is left as it was.
func TestConnectReplaceKeepsWriteRequesters(t *testing.T) {
	f := newConnectFixture(t, currentPolicyBinding, ``)
	const iss = "https://login.example"
	requesters := `{"platform":[` + requesterEntry(iss, "user-7") + `],"tools":{"drop":[]}}`
	entry := `"warehouse":{"binding":"postgres@` + digestOf(currentPolicyBinding) + `","credentials":{"history":{"file":"` + escapePath(f.credentials) + `"},"live":{"file":"` + escapePath(f.credentials) + `"},"write":{"file":"` + escapePath(f.credentials) + `"}},"user":"engine-warehouse","write":true,"operationDescriptors":{"live":"sha256:0000000000000000000000000000000000000000000000000000000000000000","write":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},"writeRequesters":` + requesters + `}`
	keys := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(keys, newIssuer(t).keySet(), 0o600); err != nil {
		t.Fatal(err)
	}
	identity := `"identity":{"issuer":"` + iss + `","audience":"gateway:acme","keys":"` + escapePath(keys) + `"},`
	text := strings.Replace(strings.Replace(f.fileText(t), `"engineVersion":"1"`, `"engineVersion":"18"`, 1), `"platforms":{}`, identity+`"platforms":{`+entry+`}`, 1)
	if err := os.WriteFile(f.config, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	before, _, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	req := f.request()
	req.replace = true
	req.write = false
	req.credentials = map[string]string{"history": f.credentials, "live": f.credentials}
	if _, err := connect(context.Background(), req, f.host, f.check); err == nil || err.Error() != "platform warehouse carries writeRequesters, which --replace keeps, and the entry replacing it does not set --write; remove writeRequesters from the file first, or give --write" {
		t.Fatalf("a replacement without --write: %v", err)
	}
	if len(f.asked) != 0 || f.fileText(t) != text {
		t.Fatal("nothing is asked and nothing is written for a replacement the member would not fit")
	}
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
	if after.version != "18" || after.platforms[0].requesters == nil || !reflect.DeepEqual(after.platforms[0].requesters, before.platforms[0].requesters) {
		t.Fatalf("version %s, requesters %+v: the member kept as written", after.version, after.platforms[0].requesters)
	}
	if written := f.fileText(t); !strings.Contains(written, `"writeRequesters": {`) {
		t.Fatalf("the file as written: %s", written)
	}
	// A binding whose write operation no longer names a tool the member
	// lists is refused before anything is asked.
	renamed := strings.Replace(strings.Replace(currentPolicyBinding, `"tools":["execute","drop"]`, `"tools":["execute"]`, 1), `"toolTaxonomies":{"execute":{"operation":"act","effect":"act"},"drop":{"operation":"act","effect":"act"}}`, `"toolTaxonomies":{"execute":{"operation":"act","effect":"act"}}`, 1)
	if renamed == currentPolicyBinding {
		t.Fatal("the binding was not renamed")
	}
	if err := os.WriteFile(filepath.Join(f.catalog, "postgres.json"), []byte(renamed), 0o600); err != nil {
		t.Fatal(err)
	}
	f.asked = nil
	written := f.fileText(t)
	if _, err := connect(context.Background(), req, f.host, f.check); err == nil || err.Error() != `platform warehouse carries writeRequesters, which --replace keeps: writeRequesters names tool "drop", which the binding's write operation does not name` {
		t.Fatalf("a binding that no longer names a listed tool: %v", err)
	}
	if len(f.asked) != 0 || f.fileText(t) != written {
		t.Fatal("nothing is asked and nothing is written for a binding the member does not fit")
	}
}
