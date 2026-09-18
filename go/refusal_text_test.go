package main

// What a refusal quotes of the caller's own text is bounded (requestText).
// An answer is JSON, which spells a byte like '<' six times over, so a name
// as long as the request bound allows would otherwise make an answer several
// times the body -- and `--max-request` raises what the body may be.

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// requestText quotes short text as it is, and longer text as its first bytes
// and how long the whole was, cut before a UTF-8 sequence the bound would
// split.
func TestRequestTextQuotesABoundedPrefix(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"nothing", "", ""},
		{"a name as it was sent", "screening", "screening"},
		{"exactly the bound", strings.Repeat("a", maxRequestText), strings.Repeat("a", maxRequestText)},
		{"one byte past the bound", strings.Repeat("a", maxRequestText+1), strings.Repeat("a", maxRequestText) + "…(65 bytes)"},
		{"far past the bound", strings.Repeat("<", 3<<20), strings.Repeat("<", maxRequestText) + "…(3145728 bytes)"},
	} {
		if got := requestText(tc.in); got != tc.want {
			t.Fatalf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	// A rune the bound would split is left out whole, whatever its length,
	// so what is quoted is text and not half a character.
	for _, r := range []rune{'é', '€', '𝄞'} {
		size := utf8.RuneLen(r)
		for straddle := 1; straddle < size; straddle++ {
			kept := maxRequestText - straddle
			in := strings.Repeat("a", kept) + string(r) + strings.Repeat("b", 200)
			want := strings.Repeat("a", kept) + fmt.Sprintf("…(%d bytes)", len(in))
			got := requestText(in)
			if got != want {
				t.Fatalf("%q of %d bytes across the bound: %q, want %q", string(r), size, got, want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("%q of %d bytes across the bound was cut mid-character: %q", string(r), size, got)
			}
		}
	}
}

// postRawWith posts a body and returns the answer's status and its bytes as
// they were written, which is what an answer's size is judged on.
func postRawWith(t *testing.T, server *httptest.Server, path, body, token string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
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
	return resp.StatusCode, raw
}

// maxRefusal is what a refusal of one of these requests is held to: far
// below the megabytes an unbounded quotation of the request's own text
// produced, and far above any of these messages.
const maxRefusal = 1024

// Under a raised `--max-request` a refusal of an /acquire body stays small,
// whatever the body named: the source, a member of the arguments, a number
// in them, or a member of the envelope the source made of them.
func TestAnAcquireRefusalQuotesABoundedPrefixOfTheRequest(t *testing.T) {
	service, server := testService(t)
	service.maxRequest = 8 << 20
	service.maxSourceOutput = 8 << 20
	// An adapter source that writes back what it was given, so the arguments
	// reach the envelope reader as the caller wrote them.
	service.sources["adapter"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv, shape: "http"}
	t.Setenv(envSourceEchoStdin, "1")
	big := strings.Repeat("<", 3<<20)
	digits := strings.Repeat("9", 3<<20)
	marker := fmt.Sprintf("(%d bytes)", len(big))
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	longKid := strings.Repeat("<", 5000)
	for _, tc := range []struct {
		name  string
		body  string
		token string
		code  int
		want  []string
	}{
		{
			name: "an unknown source",
			body: `{"session":"bounded","source":"` + big + `","arguments":{}}`,
			code: http.StatusBadRequest,
			want: []string{"unknown source: ", marker},
		},
		{
			name: "a member of the arguments named twice",
			body: `{"session":"bounded","source":"screening","arguments":{"` + big + `":0,"` + big + `":1}}`,
			code: http.StatusBadRequest,
			want: []string{"duplicate member name", marker},
		},
		{
			name: "a number outside the canonical domain",
			body: `{"session":"bounded","source":"screening","arguments":{"n":` + digits + `}}`,
			code: http.StatusBadRequest,
			want: []string{"is outside the canonical domain", marker},
		},
		{
			name: "an envelope member the adapter may not report",
			body: `{"session":"bounded","source":"adapter","arguments":{"` + big + `":0}}`,
			code: http.StatusBadRequest,
			want: []string{"unknown member", marker},
		},
		{
			name: "an acquisition member the adapter may not report",
			body: `{"session":"bounded","source":"adapter","arguments":{"result":0,"acquisition":{"` + big + `":0}}}`,
			code: http.StatusBadRequest,
			want: []string{"acquisition member", "is not one an adapter reports", marker},
		},
		{
			name: "an adapter member the adapter may not report",
			body: `{"session":"bounded","source":"adapter","arguments":{"result":0,"acquisition":{"adapter":{"name":"a","version":"1","digest":"sha256:` + strings.Repeat("a", 64) + `","` + big + `":0}}}}`,
			code: http.StatusBadRequest,
			want: []string{"adapter member", "is not one an adapter reports", marker},
		},
		{
			// The decoder names no member of its own: a guard on what is
			// quoted before the gateway's own reading begins.
			name: "a body the decoder refuses after a long member name",
			body: `{"` + big + `": x}`,
			code: http.StatusBadRequest,
			want: []string{"invalid character 'x'"},
		},
		{
			name: "a long number where the body takes a string",
			body: `{"session":"bounded","source":` + digits + `}`,
			code: http.StatusBadRequest,
			want: []string{"cannot unmarshal number"},
		},
		{
			name:  "a token signed by a key the key file does not name",
			body:  `{"session":"bounded","source":"screening","arguments":{}}`,
			token: issuer.mintRaw(t, "ec-1", `{"alg":"ES256","kid":"`+longKid+`"}`, `{"iss":"https://login.example","sub":"u","aud":"gateway:acme","exp":`+fmt.Sprint(time.Now().Add(time.Hour).Unix())+`}`),
			code:  http.StatusUnauthorized,
			want:  []string{"which is not in the key file", fmt.Sprintf("(%d bytes)", len(longKid))},
		},
		{
			name:  "a token naming an algorithm of its own",
			body:  `{"session":"bounded","source":"screening","arguments":{}}`,
			token: issuer.mintRaw(t, "ec-1", `{"alg":"`+longKid+`","kid":"ec-1"}`, `{"iss":"https://login.example","sub":"u","aud":"gateway:acme","exp":`+fmt.Sprint(time.Now().Add(time.Hour).Unix())+`}`),
			code:  http.StatusUnauthorized,
			want:  []string{"token says alg", fmt.Sprintf("(%d bytes)", len(longKid))},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.token != "" {
				service.identity = &id
				defer func() { service.identity = nil }()
			}
			code, raw := postRawWith(t, server, "/acquire", tc.body, tc.token)
			if code != tc.code {
				t.Fatalf("%d, want %d: %s", code, tc.code, first(raw, 400))
			}
			if len(raw) > maxRefusal {
				t.Fatalf("the refusal is %d bytes of a %d-byte request; it quotes what the caller sent past the bound: %s",
					len(raw), len(tc.body), first(raw, 400))
			}
			for _, want := range tc.want {
				if !strings.Contains(string(raw), want) {
					t.Fatalf("the refusal does not say %q: %s", want, raw)
				}
			}
		})
	}
}

// The same for /act, at its own one-mebibyte bound: the platform, the tool,
// a member of the decision or of a citation, and a member of the arguments
// named twice.
func TestAnActRefusalQuotesABoundedPrefixOfTheRequest(t *testing.T) {
	service, server := testService(t)
	service.sources["tickets/write"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv, shape: "mcp",
		tools: []string{"update_ticket"}, endpoint: "https://mcp.example/"}
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	big := strings.Repeat("<", (1<<20)-4096)
	half := strings.Repeat("<", (1<<19)-4096)
	digest := `"sha256:` + strings.Repeat("a", 64) + `"`
	decision := `"decision":{"recordDigest":` + digest + `,"packDigest":` + digest + `}`
	cite := `"cites":[{"sessionId":"act-bounded","callIndex":0,"signature":"` + strings.Repeat("a", 128) + `"}]`
	for _, tc := range []struct {
		name, body, step string
		want             []string
	}{
		{
			name: "a platform that allows no writes",
			body: `{"session":"act-bounded","platform":"` + big + `","tool":"update_ticket","arguments":{},` + decision + `,` + cite + `}`,
			step: "platform",
			want: []string{"allows no writes", fmt.Sprintf("(%d bytes)", len(big))},
		},
		{
			name: "a tool the binding does not name",
			body: `{"session":"act-bounded","platform":"tickets","tool":"` + big + `","arguments":{},` + decision + `,` + cite + `}`,
			step: "tool",
			want: []string{"not one the platform's write binding names", fmt.Sprintf("(%d bytes)", len(big))},
		},
		{
			name: "a member of the arguments named twice",
			body: `{"session":"act-bounded","platform":"tickets","tool":"update_ticket","arguments":{"` + half + `":0,"` + half + `":1},` + decision + `,` + cite + `}`,
			step: "arguments",
			want: []string{"duplicate member name", fmt.Sprintf("(%d bytes)", len(half))},
		},
		{
			name: "a member the decision does not have",
			body: `{"session":"act-bounded","platform":"tickets","tool":"update_ticket","arguments":{},"decision":{"` + big + `":0,"recordDigest":` + digest + `,"packDigest":` + digest + `},` + cite + `}`,
			step: "decision",
			want: []string{"decision: unknown member", fmt.Sprintf("(%d bytes)", len(big))},
		},
		{
			name: "a member a citation does not have",
			body: `{"session":"act-bounded","platform":"tickets","tool":"update_ticket","arguments":{},` + decision + `,"cites":[{"` + big + `":0}]}`,
			step: "cites",
			want: []string{"cites[0]: unknown member", fmt.Sprintf("(%d bytes)", len(big))},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.body) > maxRequestBody {
				t.Fatalf("the body is %d bytes, past /act's bound of %d", len(tc.body), maxRequestBody)
			}
			code, raw := postRawWith(t, server, "/act", tc.body, token)
			if code != http.StatusBadRequest {
				t.Fatalf("%d, want %d: %s", code, http.StatusBadRequest, first(raw, 400))
			}
			if len(raw) > maxRefusal {
				t.Fatalf("the refusal is %d bytes of a %d-byte request; it quotes what the caller sent past the bound: %s",
					len(raw), len(tc.body), first(raw, 400))
			}
			if !strings.Contains(string(raw), `"refusedAt":"`+tc.step+`"`) {
				t.Fatalf("the refusal is not at %s: %s", tc.step, raw)
			}
			for _, want := range tc.want {
				if !strings.Contains(string(raw), want) {
					t.Fatalf("the refusal does not say %q: %s", want, raw)
				}
			}
		})
	}
}

// first is the head of an answer, for a failure message that must not itself
// print megabytes.
func first(raw []byte, n int) string {
	if len(raw) <= n {
		return string(raw)
	}
	return string(raw[:n]) + "..."
}

// maxMCPAnswer is what an answer of the MCP front is held to here. It is
// larger than maxRefusal because a tool result carries its object twice --
// as structuredContent, and as a text block, inside which a byte JSON spells
// long is spelled long again -- which is how the largest of these answers
// reaches about 1.1 KiB; it is far below the mebibytes an unbounded
// quotation of a mebibyte message produced.
const maxMCPAnswer = 2048

// postMCP sends one message to the front and returns the status and the
// answer's bytes as they were written, which is what an answer's size is
// judged on.
func postMCP(t *testing.T, f *mcpFixture, session, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.front.URL+mcpEndpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
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
	return resp.StatusCode, raw
}

// The MCP front quotes a caller's text bounded as the signer's refusals do:
// a message may be a mebibyte, and what it names -- a method, a tool, a
// member, a session the signer would refuse -- comes back as a bounded
// quotation of it and how long the whole was.
func TestAnMCPRefusalQuotesABoundedPrefixOfTheMessage(t *testing.T) {
	f := newMCPFixture(t, false)
	session := f.open(t)
	big := strings.Repeat("<", (1<<20)-4096)
	half := strings.Repeat("<", (1<<19)-4096)
	bigMarker := fmt.Sprintf("(%d bytes)", len(big))
	for _, tc := range []struct {
		name string
		body string
		code int
		want []string
	}{
		{
			name: "a method the server does not serve",
			body: `{"jsonrpc":"2.0","id":1,"method":"` + big + `"}`,
			code: http.StatusOK,
			want: []string{"method not supported", bigMarker},
		},
		{
			name: "a tool the table does not name",
			body: toolCall(1, big, `{}`, ""),
			code: http.StatusOK,
			want: []string{"unknown tool", bigMarker},
		},
		{
			name: "a member of the parameters the server does not read",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"screen.lookup","arguments":{},"` + big + `":1}}`,
			code: http.StatusOK,
			want: []string{"does not read", bigMarker},
		},
		{
			// refused before the id is read, so the transport rejects the
			// message rather than answering it
			name: "a member of the message named twice",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"` + half + `":1,"` + half + `":2}}`,
			code: http.StatusBadRequest,
			want: []string{"appears twice", fmt.Sprintf("(%d bytes)", len(half))},
		},
		{
			// the name is sent on as given and the signer refuses the
			// message; what the answer names it is bounded
			name: "a session the signer refuses",
			body: toolCall(1, "screen.lookup", `{}`, `{"`+mcpSessionMeta+`":"`+big+`"}`),
			code: http.StatusOK,
			want: []string{bigMarker},
		},
		{
			name: "a seal of a session the signer refuses",
			body: toolCall(1, mcpSealTool, `{"session":"`+big+`"}`, ""),
			code: http.StatusOK,
			want: []string{bigMarker},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.body) > mcpMaxMessageBytes {
				t.Fatalf("the message is %d bytes, past the front's bound of %d", len(tc.body), mcpMaxMessageBytes)
			}
			code, raw := postMCP(t, f, session, tc.body)
			if code != tc.code {
				t.Fatalf("%d, want %d: %s", code, tc.code, first(raw, 400))
			}
			if len(raw) > maxMCPAnswer {
				t.Fatalf("the answer is %d bytes to a %d-byte message; it quotes what the caller sent past the bound: %s",
					len(raw), len(tc.body), first(raw, 400))
			}
			for _, want := range tc.want {
				if !strings.Contains(string(raw), want) {
					t.Fatalf("the answer does not say %q: %s", want, first(raw, 400))
				}
			}
		})
	}
}

// The bound is for text the signer would refuse: a session name the signer
// admits -- 128 bytes at most (§3a) -- is answered as it was sent, so the
// client can seal it, name it again or verify it.
func TestAnMCPAnswerNamesAnAdmittedSessionWhole(t *testing.T) {
	f := newMCPFixture(t, false)
	sid := f.open(t)
	name := "s-" + strings.Repeat("a", 126)
	if err := requireSession(name); err != nil || len(name) != 128 {
		t.Fatalf("the name the test sends is %d bytes and %v", len(name), err)
	}
	// Read from the answer's own session member, which is what the client
	// seals by: the receipt beside it carries the name the signer stamped.
	code, _, body := f.call(t, http.MethodPost, sid, toolCall(1, "screen.lookup", `{}`, `{"`+mcpSessionMeta+`":"`+name+`"}`), nil)
	if code != http.StatusOK {
		t.Fatalf("a call in a 128-byte session: %d %v", code, body)
	}
	if named := sameBothWays(t, resultOf(t, body))["session"]; named != name {
		t.Fatalf("the answer names the session %q, want %q", named, name)
	}
}

// An overload names the session the call resolved to, and quotes it under
// the same bound -- the window's overload, counted at arrival before the name
// has been anywhere near the signer, and the closed gate's.
func TestAnMCPOverloadQuotesABoundedSession(t *testing.T) {
	f := newMCPFixture(t, false)
	f.server.cfg.mcp.callsPerMinute = 1
	spent := f.open(t)
	// a second transport session, opened while admission is still open, with
	// a window of its own
	closed := f.open(t)
	big := strings.Repeat("<", (1<<20)-4096)
	named := `{"` + mcpSessionMeta + `":"` + big + `"}`
	if code, raw := postMCP(t, f, spent, toolCall(1, "screen.lookup", `{}`, "")); code != http.StatusOK {
		t.Fatalf("the call that spends the window: %d %s", code, first(raw, 400))
	}
	for _, tc := range []struct {
		name    string
		session string
		want    string
	}{
		{"the window spent", spent, "calls in this window already"},
		{"admission closed", closed, "admission is closed for maintenance"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.session == closed {
				f.server.closeAdmission()
			}
			code, raw := postMCP(t, f, tc.session, toolCall(2, "screen.lookup", `{}`, named))
			if code != http.StatusOK {
				t.Fatalf("%d, want 200: %s", code, first(raw, 400))
			}
			if len(raw) > maxMCPAnswer {
				t.Fatalf("the overload is %d bytes to a %d-byte message: %s", len(raw), len(big), first(raw, 400))
			}
			for _, want := range []string{tc.want, fmt.Sprintf("(%d bytes)", len(big))} {
				if !strings.Contains(string(raw), want) {
					t.Fatalf("the overload does not say %q: %s", want, first(raw, 400))
				}
			}
		})
	}
}

// What the front repeats of the signer's own refusal is bounded too, at a
// bound of its own (maxSignerReason): the refusals this gateway writes are
// bounded where they are written and come back whole, so the case this covers
// is a signer that answers with more -- an answer of the front is JSON around
// that reason, and it carries it twice.
func TestAnMCPAnswerBoundsTheSignersReason(t *testing.T) {
	long := strings.Repeat("a", 3<<20)
	marker := fmt.Sprintf("…(%d bytes)", len(long))
	whole := strings.Repeat("b", maxSignerReason)
	for _, tc := range []struct {
		name    string
		status  int
		refusal string
		code    int
		want    string
	}{
		{"a refusal carrying an error member", http.StatusBadRequest, `{"error":"` + long + `"}`, http.StatusOK, marker},
		{"a refusal that is not JSON", http.StatusBadRequest, long, http.StatusOK, marker},
		{"a refusal of the token, which the transport answers itself", http.StatusUnauthorized, `{"error":"` + long + `"}`, http.StatusUnauthorized, marker},
		{"a reason at the bound, answered as it was given", http.StatusBadRequest, `{"error":"` + whole + `"}`, http.StatusOK, whole},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// a signer of this front's own, which answers one refusal
			signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.refusal)
			}))
			defer signer.Close()
			server, err := newMCPServer(mcpTestConfig(t, signer, nil), mcpBindings(), nil, "")
			if err != nil {
				t.Fatal(err)
			}
			f := &mcpFixture{server: server, front: httptest.NewServer(server.httpHandler())}
			defer f.front.Close()
			code, raw := postMCP(t, f, f.open(t), toolCall(1, "screen.lookup", `{}`, ""))
			if code != tc.code {
				t.Fatalf("%d, want %d: %s", code, tc.code, first(raw, 400))
			}
			if len(raw) > maxMCPAnswer {
				t.Fatalf("the answer is %d bytes to a %d-byte refusal; it repeats the signer's reason past the bound: %s",
					len(raw), len(tc.refusal), first(raw, 400))
			}
			if !strings.Contains(string(raw), tc.want) {
				t.Fatalf("the answer does not carry %d bytes of the reason: %s", len(tc.want), first(raw, 400))
			}
		})
	}
}
