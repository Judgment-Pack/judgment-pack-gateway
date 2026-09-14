package main

import (
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

// authed posts one body with a bearer token and decodes the answer.
func authed(t *testing.T, server *httptest.Server, path, body, token string) (int, map[string]any) {
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
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// The executor's refusal ladder (docs/design/executor.md), each step reached
// on its own and nothing run for any of them: an action is refused before
// any executor starts unless the requester is authenticated, the platform
// allows writes, the tool is the binding's, the decision claim has its
// shape, every citation resolves in this engine's store under its key, and
// the decision record is under the decision-record directory. When every
// step passes, the executor runs.
func TestActRefusesBeforeAnyExecutorRuns(t *testing.T) {
	service, server := testService(t)
	service.sources["tickets/write"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv, shape: "mcp", tools: []string{"update_ticket"}, endpoint: "https://mcp.example/"}
	records := filepath.Join(t.TempDir(), "decisions")
	if err := os.MkdirAll(records, 0o700); err != nil {
		t.Fatal(err)
	}
	service.decisionRecords = records

	good := func(session, callIndex, signature, record string) string {
		return `{"session":"act-1","platform":"tickets","tool":"update_ticket","arguments":{"id":"T-1"},` +
			`"decision":{"recordDigest":"` + record + `","packDigest":"sha256:` + strings.Repeat("b", 64) + `"},` +
			`"cites":[{"sessionId":"` + session + `","callIndex":` + callIndex + `,"signature":"` + signature + `"}]}`
	}
	noRecord := "sha256:" + strings.Repeat("c", 64)

	// No identity configured: nothing is a requester, and the action is
	// refused before its body is read.
	if code, body := post(t, server, "/act", good("act-1", "0", strings.Repeat("a", 128), noRecord)); code != http.StatusUnauthorized || !strings.Contains(fmt.Sprint(body["error"]), "no identity configured") {
		t.Fatalf("no identity: %d %v", code, body)
	}
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	if code, body := post(t, server, "/act", good("act-1", "0", strings.Repeat("a", 128), noRecord)); code != http.StatusUnauthorized || !strings.Contains(fmt.Sprint(body["error"]), "bearer token") {
		t.Fatalf("no token: %d %v", code, body)
	}

	// A receipt to cite, in this engine's own store.
	code, first := authed(t, server, "/acquire", `{"session":"act-1","source":"screening","arguments":{"q":"acme"}}`, token)
	if code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, first)
	}
	receipt := first["receipt"].(map[string]any)
	signature := receipt["signature"].(string)
	// A decision record that cites it, as one line of a .jsonl file, which
	// §4 step 6 reads line by line; and one whole file that does not.
	line := `{"kind":"evaluation","cites":[{"sessionId":"act-1","callIndex":0,"signature":"` + signature + `"}]}`
	if err := os.WriteFile(filepath.Join(records, "evaluations.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(records, "other.json"), []byte(`{"kind":"other"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	record := "sha256:" + hexOf([]byte(line))
	started := service.started.Load()

	for _, tc := range []struct{ name, body, step, want string }{
		{"unknown platform", strings.Replace(good("act-1", "0", signature, record), `"platform":"tickets"`, `"platform":"docs"`, 1), "platform", "allows no writes"},
		{"a tool the binding does not name", strings.Replace(good("act-1", "0", signature, record), `"tool":"update_ticket"`, `"tool":"delete_ticket"`, 1), "tool", "not one the platform's write binding names"},
		{"a decision missing a member", strings.Replace(good("act-1", "0", signature, record), `,"packDigest":"sha256:`+strings.Repeat("b", 64)+`"`, ``, 1), "decision", "decision"},
		{"a decision digest not of its form", strings.Replace(good("act-1", "0", signature, record), record, "sha256:abc", 1), "decision", "64 lowercase hex"},
		{"no citation", strings.Replace(good("act-1", "0", signature, record), `"cites":[{`, `"cites":[],"x":[{`, 1), "cites", ""},
		{"a citation of a session that is not there", good("act-2", "0", signature, record), "cites", "no such session"},
		{"a citation of a receipt that is not there", good("act-1", "7", signature, record), "cites", "no such receipt"},
		{"a citation with another signature", good("act-1", "0", strings.Repeat("a", 128), record), "cites", "not the receipt's"},
		{"a cited receipt that does not verify", "artifact-missing", "cites", "does not verify under this engine's key (artifact-missing)"},
		{"a record that is not under the directory", good("act-1", "0", signature, noRecord), "decision", "no candidate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			if body == "artifact-missing" {
				// The receipt is there by name and its signature is the
				// cited one, but its artifact is gone: the ladder refuses
				// it, and so does the executor, before anything runs.
				digest := strings.TrimPrefix(receipt["resultDigest"].(string), "sha256:")
				artifact := filepath.Join(service.storeRoot, "artifacts", digest)
				if err := os.Rename(artifact, artifact+".aside"); err != nil {
					t.Fatal(err)
				}
				defer os.Rename(artifact+".aside", artifact)
				body = good("act-1", "0", signature, record)
			}
			code, answer := authed(t, server, "/act", body, token)
			if tc.name == "no citation" {
				// An unknown top-level member is a bad request before the ladder.
				if code != http.StatusBadRequest {
					t.Fatalf("%d %v", code, answer)
				}
				return
			}
			if code != http.StatusBadRequest || answer["refusedAt"] != tc.step || !strings.Contains(fmt.Sprint(answer["error"]), tc.want) {
				t.Fatalf("want a refusal at %q saying %q, got %d %v", tc.step, tc.want, code, answer)
			}
		})
	}
	if code, body := authed(t, server, "/act", `{"session":"act-1","platform":"tickets","tool":"update_ticket","arguments":{},"decision":{"recordDigest":"`+record+`","packDigest":"sha256:`+strings.Repeat("b", 64)+`"},"cites":[]}`, token); code != http.StatusBadRequest || body["refusedAt"] != "cites" || !strings.Contains(fmt.Sprint(body["error"]), "at least one receipt") {
		t.Fatalf("an empty citation list: %d %v", code, body)
	}
	if service.started.Load() != started {
		t.Fatal("an executor ran for a refused action")
	}
	// The write source is the executor's alone: /acquire names no such
	// source, whoever asks.
	if code, body := authed(t, server, "/acquire", `{"session":"act-1","source":"tickets/write","arguments":{}}`, token); code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(body["error"]), "unknown source") {
		t.Fatalf("a write source through /acquire: %d %v", code, body)
	}
	// Every step passed: the executor ran. This stand-in is no executor
	// and answers no envelope, so the action fails after it ran -- what is
	// held here is that the ladder ended and nothing before it started one.
	code, body := authed(t, server, "/act", good("act-1", "0", signature, record), token)
	if code == http.StatusOK || body["refusedAt"] != nil {
		t.Fatalf("the stand-in executor cannot mint an action: %d %v", code, body)
	}
	if service.started.Load() != started+1 {
		t.Fatalf("the executor runs once every step has passed: started %d, was %d", service.started.Load(), started)
	}
	// Without a decision-record directory no record can be found, and the
	// ladder says so at the decision step, before any executor runs.
	service.decisionRecords = ""
	if code, body := authed(t, server, "/act", good("act-1", "0", signature, record), token); code != http.StatusBadRequest || body["refusedAt"] != "decision" || !strings.Contains(fmt.Sprint(body["error"]), "without a decision-record directory") {
		t.Fatalf("no decision-record directory: %d %v", code, body)
	}
	if service.started.Load() != started+1 {
		t.Fatal("an executor ran with no decision-record directory")
	}
}
