package main

// The request envelope is read the way everything else this gateway signs is
// read: by exact member names, each given once, and nothing else admitted.
// encoding/json's struct decoding did neither -- it matched a name without
// regard to case and kept the last of several spellings -- so a body could
// name one session to whoever read it and another to the signer, and a seal
// taken from the second spelling cannot be taken back.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// requestMembers reads one object by its members' exact names and keeps each
// member's bytes as they were sent; everything the body rule said before is
// still said.
func TestRequestMembersReadsOneObjectByExactNames(t *testing.T) {
	allowed := map[string]bool{"session": true, "source": true, "arguments": true}
	for _, tc := range []struct {
		name, body string
		want       map[string]string
		refusal    string
	}{
		{
			name: "the members the endpoint reads, as they were sent",
			body: `{"session":"s","source":"screening","arguments":{ "a" : 1 }}`,
			want: map[string]string{"session": `"s"`, "source": `"screening"`, "arguments": `{ "a" : 1 }`},
		},
		{
			name: "an optional member left out stays left out",
			body: `{"session":"s"}`,
			want: map[string]string{"session": `"s"`},
		},
		{
			name: "a member given as null is present and null",
			body: `{"session":"s","arguments":null}`,
			want: map[string]string{"session": `"s"`, "arguments": "null"},
		},
		{
			name: "whitespace after the object is not content",
			body: "{\"session\":\"s\"} \t\r\n",
			want: map[string]string{"session": `"s"`},
		},
		{
			name:    "a member the endpoint does not read",
			body:    `{"session":"s","sourceX":"x"}`,
			refusal: `does not read: sourceX`,
		},
		{
			name:    "a member spelled in another case is not that member",
			body:    `{"SESSION":"s"}`,
			refusal: `does not read: SESSION`,
		},
		{
			name:    "a member named twice, exactly",
			body:    `{"session":"first","session":"second"}`,
			refusal: `member "session" appears twice`,
		},
		{
			name:    "a member named twice, in two cases",
			body:    `{"session":"first","Session":"second"}`,
			refusal: `does not read: Session`,
		},
		{
			name:    "a body that is not an object",
			body:    `["session","s"]`,
			refusal: "must be a JSON object",
		},
		{
			name:    "a body that is a bare null",
			body:    `null`,
			refusal: "must be a JSON object",
		},
		{
			name:    "a second value after the object",
			body:    `{"session":"s"} {"session":"t"}`,
			refusal: "exactly one JSON value",
		},
		{
			name:    "bytes after the object that are no value",
			body:    `{"session":"s"} @`,
			refusal: "trailing content",
		},
		{
			name:    "nothing at all",
			body:    ``,
			refusal: "EOF",
		},
		{
			// Each member's value is read as a value of its own, so what
			// bounds the nesting inside it is the depth the canon parser
			// takes (maxNesting), not that depth less whatever the envelope
			// around it costs.
			name: "a member nested as deep as the parser descends",
			body: `{"arguments":` + strings.Repeat("[", maxNesting) + strings.Repeat("]", maxNesting) + `}`,
			want: map[string]string{"arguments": strings.Repeat("[", maxNesting) + strings.Repeat("]", maxNesting)},
		},
		{
			name:    "a member nested one level deeper",
			body:    `{"arguments":` + strings.Repeat("[", maxNesting+1) + strings.Repeat("]", maxNesting+1) + `}`,
			refusal: "max depth",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			members, err := requestMembers(strings.NewReader(tc.body), allowed)
			if tc.refusal != "" {
				if err == nil || !strings.Contains(err.Error(), tc.refusal) {
					t.Fatalf("want a refusal saying %q, got %v (%v)", tc.refusal, err, members)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused a body it reads: %v", err)
			}
			if len(members) != len(tc.want) {
				t.Fatalf("read %d member(s), want %d: %v", len(members), len(tc.want), members)
			}
			for name, raw := range tc.want {
				if string(members[name]) != raw {
					t.Fatalf("member %q read as %s, want %s", name, members[name], raw)
				}
			}
		})
	}
}

// /acquire refuses a member it does not read, a member named twice, and a
// spelling of one of its own members in another case -- each before any
// source runs and with nothing minted.
func TestAcquireReadsItsEnvelopeByExactMemberNames(t *testing.T) {
	service, server := testService(t)
	for _, tc := range []struct {
		name, body, refusal string
	}{
		{
			name:    "a member the gateway does not read",
			body:    `{"session":"exact-a","source":"screening","arguments":{},"sourceX":"evil"}`,
			refusal: "does not read: sourceX",
		},
		{
			name:    "the source named twice, exactly",
			body:    `{"session":"exact-b","source":"screening","source":"nosuchsource","arguments":{}}`,
			refusal: `member "source" appears twice`,
		},
		{
			name:    "the source named twice, in two cases",
			body:    `{"session":"exact-c","source":"screening","SOURCE":"nosuchsource","arguments":{}}`,
			refusal: "does not read: SOURCE",
		},
		{
			name:    "the session named twice, in two cases",
			body:    `{"session":"exact-d","SESSION":"elsewhere","source":"screening","arguments":{}}`,
			refusal: "does not read: SESSION",
		},
		{
			name:    "the arguments named twice, in two cases",
			body:    `{"session":"exact-e","source":"screening","arguments":{"who":"first"},"ARGUMENTS":{"who":"second"}}`,
			refusal: "does not read: ARGUMENTS",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := service.started.Load()
			code, answer := post(t, server, "/acquire", tc.body)
			if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(answer["error"]), tc.refusal) {
				t.Fatalf("want a refusal saying %q, got %d %v", tc.refusal, code, answer)
			}
			if service.started.Load() != started {
				t.Fatal("a source ran for a body the gateway refused to read")
			}
			if entries, err := os.ReadDir(filepath.Join(service.storeRoot, "receipts")); err == nil && len(entries) != 0 {
				t.Fatalf("a refused body left receipts behind: %v", entries)
			}
		})
	}
	// The control: the same body without the second spelling is acquired,
	// so what the cases above prove is the refusal and not a fixture that
	// never worked.
	if code, answer := post(t, server, "/acquire", `{"session":"exact-a","source":"screening","arguments":{}}`); code != http.StatusOK {
		t.Fatalf("an envelope of the members it reads: %d %v", code, answer)
	}
}

// A folded spelling is not the member: a body whose only "source" is
// "SOURCE" names no source, and one whose only "session" is "SESSION" names
// no session. Neither is read as the member it resembles, whatever the
// refusal says.
func TestAcquireDoesNotReadAFoldedSpellingAsItsMember(t *testing.T) {
	service, server := testService(t)
	code, answer := post(t, server, "/acquire", `{"session":"folded-source","SOURCE":"screening","arguments":{}}`)
	if code == http.StatusOK {
		t.Fatalf("a body naming SOURCE was acquired as though it named source: %v", answer)
	}
	if _, err := os.Stat(filepath.Join(service.storeRoot, "receipts", "folded-source")); err == nil {
		t.Fatal("a body naming SOURCE minted a receipt")
	}
	if service.started.Load() != 0 {
		t.Fatal("a body naming SOURCE started a source")
	}
}

// /seal is final: the session it seals is the one its own "session" member
// names, and a body that names the member twice -- in any spelling -- seals
// nothing at all.
func TestSealReadsItsSessionMemberExactly(t *testing.T) {
	_, server := testService(t)
	for _, session := range []string{"sealme", "keepme"} {
		if code, answer := post(t, server, "/acquire", `{"session":"`+session+`","source":"screening","arguments":{}}`); code != http.StatusOK {
			t.Fatalf("acquire into %s: %d %v", session, code, answer)
		}
	}
	// A body whose only session-like member is "SESSION" names no session,
	// so nothing is sealed -- what it resembles is not what it is.
	if code, answer := post(t, server, "/seal", `{"SESSION":"keepme"}`); code != http.StatusBadRequest {
		t.Fatalf("a seal whose only session member is SESSION: %d %v", code, answer)
	}
	if code, answer := post(t, server, "/seal", `{"session":"sealme","SESSION":"keepme"}`); code != http.StatusBadRequest {
		t.Fatalf("a seal naming the session twice, in two cases: %d %v", code, answer)
	}
	if code, answer := post(t, server, "/seal", `{"session":"keepme","session":"sealme"}`); code != http.StatusBadRequest {
		t.Fatalf("a seal naming the session twice, exactly: %d %v", code, answer)
	}
	// Neither session was sealed by any of that: both still take a receipt.
	for _, session := range []string{"sealme", "keepme"} {
		if code, answer := post(t, server, "/acquire", `{"session":"`+session+`","source":"screening","arguments":{}}`); code != http.StatusOK {
			t.Fatalf("session %s was sealed by a refused seal: %d %v", session, code, answer)
		}
	}
	// And the seal the body does name still works.
	if code, answer := post(t, server, "/seal", `{"session":"sealme"}`); code != http.StatusOK {
		t.Fatalf("a seal of the session its member names: %d %v", code, answer)
	}
	if code, _ := post(t, server, "/acquire", `{"session":"sealme","source":"screening","arguments":{}}`); code != http.StatusBadRequest {
		t.Fatalf("the sealed session still took a receipt: %d", code)
	}
	if code, answer := post(t, server, "/acquire", `{"session":"keepme","source":"screening","arguments":{}}`); code != http.StatusOK {
		t.Fatalf("the session the seal did not name was sealed: %d %v", code, answer)
	}
}

// An action is a write. A body that names a member this engine does not
// read, or names one twice, is refused before the ladder and therefore
// before any executor runs -- which the control at the end shows is what the
// same fixture otherwise does.
func TestActReadsItsEnvelopeByExactMemberNamesBeforeAnyExecutorRuns(t *testing.T) {
	service, server := testService(t)
	service.sources["tickets/write"] = sourceSpec{argv: []string{os.Args[0], "--tools=update_ticket"}, env: helperEnv,
		shape: "mcp", tools: []string{"update_ticket"}, endpoint: "https://mcp.example/"}
	records := filepath.Join(t.TempDir(), "decisions")
	if err := os.MkdirAll(records, 0o700); err != nil {
		t.Fatal(err)
	}
	service.decisionRecords = records
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))

	// A receipt to cite, and a decision record that cites it.
	code, first := authed(t, server, "/acquire", `{"session":"act-env","source":"screening","arguments":{"q":"acme"}}`, token)
	if code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, first)
	}
	signature := first["receipt"].(map[string]any)["signature"].(string)
	line := `{"kind":"evaluation","cites":[{"sessionId":"act-env","callIndex":0,"signature":"` + signature + `"}]}`
	if err := os.WriteFile(filepath.Join(records, "evaluations.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	good := `{"session":"act-env","platform":"tickets","tool":"update_ticket","arguments":{"id":"T-1"},` +
		`"decision":{"recordDigest":"sha256:` + hexOf([]byte(line)) + `","packDigest":"sha256:` + strings.Repeat("b", 64) + `"},` +
		`"cites":[{"sessionId":"act-env","callIndex":0,"signature":"` + signature + `"}]}`

	for _, tc := range []struct {
		name, body, refusal string
	}{
		{
			name:    "a member the engine does not read",
			body:    strings.Replace(good, `"tool":"update_ticket"`, `"tool":"update_ticket","toolX":"delete_ticket"`, 1),
			refusal: "does not read: toolX",
		},
		{
			name:    "the tool named twice, exactly",
			body:    strings.Replace(good, `"tool":"update_ticket"`, `"tool":"update_ticket","tool":"delete_ticket"`, 1),
			refusal: `member "tool" appears twice`,
		},
		{
			name:    "the tool named twice, in two cases",
			body:    strings.Replace(good, `"tool":"update_ticket"`, `"tool":"update_ticket","TOOL":"delete_ticket"`, 1),
			refusal: "does not read: TOOL",
		},
		{
			name:    "the decision named twice, in two cases",
			body:    strings.Replace(good, `"decision":{`, `"Decision":{"recordDigest":"sha256:`+strings.Repeat("c", 64)+`","packDigest":"sha256:`+strings.Repeat("b", 64)+`"},"decision":{`, 1),
			refusal: "does not read: Decision",
		},
		{
			name:    "the citations named twice, exactly",
			body:    strings.Replace(good, `"cites":[`, `"cites":[],"cites":[`, 1),
			refusal: `member "cites" appears twice`,
		},
		{
			name:    "the arguments named twice, in two cases",
			body:    strings.Replace(good, `"arguments":{"id":"T-1"}`, `"arguments":{"id":"T-1"},"Arguments":{"id":"T-2"}`, 1),
			refusal: "does not read: Arguments",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := service.started.Load()
			code, answer := authed(t, server, "/act", tc.body, token)
			if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(answer["error"]), tc.refusal) {
				t.Fatalf("want a refusal saying %q, got %d %v", tc.refusal, code, answer)
			}
			if answer["refusedAt"] != nil {
				t.Fatalf("an envelope this engine cannot read is refused before the ladder: %v", answer)
			}
			if service.started.Load() != started {
				t.Fatal("an executor ran for a body the engine refused to read")
			}
		})
	}
	// The control: every step of the ladder passes for the same body
	// without a second spelling, and the executor runs. (It is no executor
	// and answers no envelope, so the action itself fails after it ran.)
	started := service.started.Load()
	if code, answer := authed(t, server, "/act", good, token); code == http.StatusOK || answer["refusedAt"] != nil {
		t.Fatalf("the stand-in executor cannot mint an action: %d %v", code, answer)
	}
	if service.started.Load() != started+1 {
		t.Fatalf("the executor did not run for the body the cases above vary: started %d, was %d",
			service.started.Load(), started)
	}
}

// An action's arguments are held to the same value budget a read's are
// (maxArgumentValues), rather than to the arithmetic of the one-mebibyte
// body that happens to make the budget unreachable today.
func TestAnActionsArgumentsAreHeldToTheValueBudget(t *testing.T) {
	service, _ := testService(t)
	service.sources["tickets/write"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv,
		shape: "mcp", tools: []string{"update_ticket"}, endpoint: "https://mcp.example/"}
	who := &caller{issuer: "https://login.example", subject: "u", tokenDigest: strings.Repeat("a", 64)}
	// One array and a number for every unit of the budget: the value past it
	// is refused where it begins.
	arguments := json.RawMessage("[" + strings.Repeat("0,", maxArgumentValues-1) + "0]")
	_, err := service.act(json.RawMessage(`"act-budget"`), json.RawMessage(`"tickets"`), json.RawMessage(`"update_ticket"`),
		arguments, json.RawMessage(`{}`), json.RawMessage(`[]`), who)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("more JSON values than the budget of %d", maxArgumentValues)) {
		t.Fatalf("arguments past the value budget: %v", err)
	}
	if service.started.Load() != 0 {
		t.Fatal("an executor ran for arguments past the budget")
	}
}

// What a refusal repeats of a failed source's stderr is printable ASCII,
// bounded, and the count it gives is of the text quoted.
func TestAFailedSourcesStderrIsPrintableAndBounded(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"a line as it was written", "source refused\n", "source refused"},
		{"an escape sequence", "\x1b]0;title\x07\x1b[31mred", "?]0;title??[31mred"},
		{"a byte that is not UTF-8", "bad \xff\xfe byte", "bad ?? byte"},
		{"a character outside ASCII", "café", "caf??"},
		{"nothing at all", "   \n\t", ""},
		{
			name: "past the bound",
			in:   strings.Repeat("e", maxSourceFailureText+50),
			want: strings.Repeat("e", maxSourceFailureText) + fmt.Sprintf("…(%d bytes)", maxSourceFailureText+50),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sourceFailureText(tc.in); got != tc.want {
				t.Fatalf("%q, want %q", got, tc.want)
			}
		})
	}
}

// The same over the whole path a caller sees: a source that writes an escape
// sequence and a long tail on its stderr and fails.
func TestAFailedSourcesStderrReachesTheCallerPrintable(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh to write a source with")
	}
	service, server := testService(t)
	t.Cleanup(service.cancel)
	script := filepath.Join(t.TempDir(), "noisy.sh")
	body := "#!/bin/sh\nprintf '\\033]0;renamed\\007refused ' >&2\n" +
		"i=0; while [ $i -lt 300 ]; do printf 'T' >&2; i=$((i+1)); done\nexit 1\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	service.sources["noisy"] = sourceSpec{argv: []string{script}}
	code, answer := post(t, server, "/acquire", `{"session":"noisy","source":"noisy","arguments":{}}`)
	message := fmt.Sprint(answer["error"])
	if code != http.StatusBadRequest || !strings.HasPrefix(message, "source failed: ") {
		t.Fatalf("a failed source: %d %v", code, answer)
	}
	for i := 0; i < len(message); i++ {
		if message[i] < 0x20 || message[i] == 0x7f {
			t.Fatalf("the refusal carries the byte %#x at offset %d: %q", message[i], i, message)
		}
	}
	if !strings.Contains(message, "?]0;renamed?refused") {
		t.Fatalf("the refusal does not carry what the source said, made printable: %q", message)
	}
	if !strings.Contains(message, "bytes)") || len(message) > 300 {
		t.Fatalf("the refusal is %d bytes and does not say how long the whole was: %q", len(message), message)
	}
}

// --source-max-output has a ceiling of its own, as --max-request has: a
// source's output is the one parse this gateway makes under no value budget,
// so the bytes are the whole of what bounds it.
func TestSourceMaxOutputHasACeiling(t *testing.T) {
	base := []string{"store", "seed", "authority", "registry", "--source-max-output"}
	at := fmt.Sprint(maxSourceOutputCeiling)
	opts, message, ok := parseServeOptions(append(base, at))
	if !ok || opts.maxSourceOutput != maxSourceOutputCeiling {
		t.Fatalf("a bound of exactly the ceiling: %v %q", opts.maxSourceOutput, message)
	}
	for _, value := range []string{
		fmt.Sprint(maxSourceOutputCeiling + 1),
		"9223372036854775807",
		"99999999999999999999",
	} {
		_, message, ok := parseServeOptions(append(base, value))
		want := fmt.Sprintf("--source-max-output %q is not a number of bytes from 1 to %d", value, maxSourceOutputCeiling)
		if ok || message != want {
			t.Fatalf("a bound of %s: accepted=%v, %q", value, ok, message)
		}
	}
}
