package main

// What one scope's caller learns of another scope identifier's state through
// the shared gateway (ADR-0041): each test holds a caller of scope B to the
// same answer whether or not scope A's state exists.

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// rawCall sends one message on a transport session of the front and is the
// answer's body as it came, byte for byte.
func (f *mcpFixture) rawCall(t *testing.T, sid, body string) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.front.URL+mcpEndpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d %s", body, resp.StatusCode, raw)
	}
	return raw
}

// A front fixed to scope B seals B's sessions alone: to a caller whose token
// reaches every scope, its seal of a session of scope A, or of a session of
// none, is the answer for a session the gateway does not hold, byte for
// byte, whether or not that session exists, and nothing is sealed -- the
// signer seals both to the same caller asked directly. B's own session it
// seals. At the signer, a /seal naming a scope is held to it the same way.
func TestAFrontFixedToAScopeSealsThatScopesSessionsAlone(t *testing.T) {
	f := scopedMCPFixture(t, mcpConfig{scope: callerScopeB})
	f.token = tokenFor(t, f.issuer, subjectEvery, nil)
	sid := f.open(t)
	seal := func(session string) []byte {
		t.Helper()
		return f.rawCall(t, sid, toolCall(7, mcpSealTool, `{"session":"`+session+`"}`, ""))
	}
	before := map[string][]byte{"shared-a": seal("shared-a"), "shared-plain": seal("shared-plain")}
	for _, tc := range []struct{ session, source, scope string }{
		{"shared-a", "a/live", callerScopeA},
		{"shared-plain", "plain/live", ""},
	} {
		if code, out := authed(t, f.signer, "/acquire", acquireBodyFor(tc.session, tc.source, tc.scope), f.token); code != http.StatusOK {
			t.Fatalf("an acquisition into %s at the signer: %d %v", tc.session, code, out)
		}
	}
	for session, unknown := range before {
		if !bytes.Contains(unknown, []byte(`no such session: `+session)) {
			t.Fatalf("the seal of a session that does not exist: %s", unknown)
		}
		if got := seal(session); !bytes.Equal(got, unknown) {
			t.Errorf("the front fixed to B seals %s, which exists:\n%s\nnot as when it did not:\n%s", session, got, unknown)
		}
		// the signer, asked naming B, answers as it does for a session it does
		// not hold; asked naming none, it seals the session
		code, raw := postRawWith(t, f.signer, "/seal", `{"session":"`+session+`","scope":"`+callerScopeB+`"}`, f.token)
		_, absent := postRawWith(t, f.signer, "/seal", `{"session":"never-`+session+`","scope":"`+callerScopeB+`"}`, f.token)
		if code != http.StatusBadRequest || string(raw) != strings.Replace(string(absent), "never-"+session, session, 1) {
			t.Errorf("a seal of %s naming B at the signer: %d %s", session, code, raw)
		}
		if code, out := authed(t, f.signer, "/seal", `{"session":"`+session+`"}`, f.token); code != http.StatusOK {
			t.Errorf("%s was not left open: %d %v", session, code, out)
		}
	}
	// B's own session is sealed through the front
	_, _, body := f.call(t, http.MethodPost, sid, toolCall(8, "b.lookup", `{}`, `{"`+mcpSessionMeta+`":"own-b"}`), nil)
	acquired(t, body)
	_, _, body = f.call(t, http.MethodPost, sid, toolCall(9, mcpSealTool, `{"session":"own-b"}`, ""), nil)
	if record := sameBothWays(t, resultOf(t, body)); record["sessionId"] != "own-b" || record["finalCount"] != float64(1) {
		t.Fatalf("B's session through the front fixed to B: %v", record)
	}
	// a scope member that is not a string is refused, naming nothing of it
	if code, raw := postRawWith(t, f.signer, "/seal", `{"session":"own-b","scope":7}`, f.token); code != http.StatusBadRequest || bytes.Contains(raw, []byte("7")) {
		t.Fatalf("a scope that is not a string: %d %s", code, raw)
	}
}

// A gateway that fixes no source to a scope identifier reads /seal's scope as
// any member /seal does not read, and refuses it, as /acquire does.
func TestASealNamingAScopeIsRefusedWhereNoSourceIsScoped(t *testing.T) {
	_, server := testService(t)
	code, raw := postRawWith(t, server, "/seal", `{"session":"s","scope":"`+callerScopeA+`"}`, "")
	if code != http.StatusBadRequest || !bytes.Contains(raw, []byte("does not read: scope")) {
		t.Fatalf("%d %s", code, raw)
	}
}

// /posture served to a caller of scope B is judged over B's sources alone
// (ADR-0041): with scope A's sources -- a platform a delegated call reaches
// that names no grant, a write tool no writeRequesters list holds, a
// read-only source closed on a refusal and serving no IAM_POLICY, a program
// run as the signer's own user -- or without them, every line, every count,
// programs and readOnlySources are the same bytes. The installation's report
// changes with them, so A's sources are ones a line is judged over.
func TestPostureOfOneScopeIsTheSameWhateverAnotherScopeHolds(t *testing.T) {
	closed := newGCPAssetSource(gcpStandInOp, gcpAssetTokenMetadata, false)
	closed.closed = &readOnlyRefusal{reason: refusalCredentialCanWrite, on: "refresh"}
	iamOp := gcpStandInOp
	iamOp.contentTypes = []string{"RESOURCE", "IAM_POLICY"}
	gate := &grantGate{provider: "azure-devops", connection: "boards"}
	ofB := map[string]sourceSpec{
		"b-crm/live":     {shape: "mcp", scope: callerScopeB, tools: []string{"query"}, grant: gate},
		"b-crm/write":    {shape: "mcp", scope: callerScopeB, tools: []string{"update"}, grant: gate, requesters: &writeRequesters{platform: map[requesterRef]bool{}}},
		"b-assets/live":  {shape: "http", scope: callerScopeB, gcpAsset: newGCPAssetSource(iamOp, gcpAssetTokenMetadata, false)},
		"b-program/live": {argv: []string{"/nonexistent/b-program"}, user: "engine-b", scope: callerScopeB},
	}
	withA := map[string]sourceSpec{
		"a-crm/live":     {shape: "mcp", scope: callerScopeA, tools: []string{"query"}},
		"a-crm/write":    {shape: "mcp", scope: callerScopeA, tools: []string{"update", "close"}, requesters: &writeRequesters{}},
		"a-assets/live":  {shape: "http", scope: callerScopeA, gcpAsset: closed},
		"a-program/live": {argv: []string{"/nonexistent/a-program"}, scope: callerScopeA},
	}
	for name, spec := range ofB {
		withA[name] = spec
	}
	report := func(sources map[string]sourceSpec, reach *scopeReach) []byte {
		return hostPosture(postureInput{configured: true, sources: sources, reach: reach,
			delegation: &delegationPosture{}, callerScopes: "checked"}).canonical()
	}
	b := &scopeReach{ids: map[string]bool{callerScopeB: true}}
	got, alone := report(withA, b), report(ofB, b)
	if !bytes.Equal(got, alone) {
		t.Fatalf("B's report changes with A's sources:\n%s\n%s", got, alone)
	}
	for _, name := range []string{"a-crm", "a-assets", "a-program"} {
		if bytes.Contains(got, []byte(name)) {
			t.Errorf("B's report names %s: %s", name, got)
		}
	}
	if bytes.Equal(report(withA, nil), report(ofB, nil)) {
		t.Fatal("the installation's report is the same with and without A's sources, so the test shows nothing")
	}
}
