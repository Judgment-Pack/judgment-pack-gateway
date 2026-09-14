package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
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
	service.sources["tickets/write"] = sourceSpec{argv: []string{os.Args[0], "--tools=update_ticket,delete_ticket"}, env: helperEnv, shape: "mcp", tools: []string{"update_ticket", "delete_ticket"}, endpoint: "https://mcp.example/"}
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
		{"a tool the binding does not name", strings.Replace(good("act-1", "0", signature, record), `"tool":"update_ticket"`, `"tool":"close_ticket"`, 1), "tool", "not one the platform's write binding names"},
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
	// A request missing its decision is refused at the decision step, after
	// the session step: on a session that cannot be entered, it is the
	// session that is named.
	if code, body := authed(t, server, "/act", strings.Replace(good("act-1", "0", signature, record), `"decision":{`, `"decisionX":{`, 1), token); code != http.StatusBadRequest {
		t.Fatalf("an unknown member: %d %v", code, body)
	}
	noDecision := `{"session":"act-1","platform":"tickets","tool":"update_ticket","arguments":{},"cites":[{"sessionId":"act-1","callIndex":0,"signature":"` + signature + `"}]}`
	if code, body := authed(t, server, "/act", noDecision, token); code != http.StatusBadRequest || body["refusedAt"] != "decision" || !strings.Contains(fmt.Sprint(body["error"]), "decision is required") {
		t.Fatalf("no decision: %d %v", code, body)
	}
	if code, body := authed(t, server, "/act", strings.Replace(noDecision, `"session":"act-1"`, `"session":"act-8"`, 1), token); code != http.StatusBadRequest || body["refusedAt"] != "decision" {
		t.Fatalf("no decision on a fresh session reaches the decision step: %d %v", code, body)
	}
	// Started for the one tool requested: the binding's list narrowed to it
	// on the command line the executor actually got.
	if argv := service.startedWith.Load(); argv == nil || !contains(*argv, "--tools=update_ticket") || contains(*argv, "--tools=update_ticket,delete_ticket") {
		t.Fatalf("the executor is started for the requested tool alone: %v", argv)
	}
	// A decision-record directory that cannot be read refuses at the
	// decision step, without saying where it is.
	if runtime.GOOS != "windows" && os.Getuid() != 0 {
		unreadable := filepath.Join(t.TempDir(), "sealed-records")
		if err := os.MkdirAll(unreadable, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(unreadable, "evaluations.jsonl"), []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(unreadable, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(unreadable, 0o700) })
		service.decisionRecords = unreadable
		code, body := authed(t, server, "/act", good("act-1", "0", signature, record), token)
		if code != http.StatusBadRequest || body["refusedAt"] != "decision" || !strings.Contains(fmt.Sprint(body["error"]), "could not be read") || strings.Contains(fmt.Sprint(body["error"]), unreadable) {
			t.Fatalf("an unreadable decision-record directory: %d %v", code, body)
		}
		if service.started.Load() != started+1 {
			t.Fatal("an executor ran with an unreadable decision-record directory")
		}
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
	// The decision-record directory is back for what follows.
	service.decisionRecords = records
	// A session sealed here is refused at the session step, before any
	// evidence is read; so is one sealed in the registry by an earlier
	// process, or one whose receipts on disk this process did not mint.
	if code, body := authed(t, server, "/seal", `{"session":"act-1"}`, token); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, body)
	}
	if code, body := authed(t, server, "/act", good("act-1", "0", signature, record), token); code != http.StatusBadRequest || body["refusedAt"] != "session" || !strings.Contains(fmt.Sprint(body["error"]), "sealed in the registry") {
		t.Fatalf("a sealed session: %d %v", code, body)
	}
	// On a sealed session, a request missing its decision is refused at
	// the session step: the ladder's order is the order of the answer. So
	// is one whose arguments do not parse, and one faulty at every later
	// step at once.
	if code, body := authed(t, server, "/act", noDecision, token); code != http.StatusBadRequest || body["refusedAt"] != "session" {
		t.Fatalf("a sealed session names the session before the missing decision: %d %v", code, body)
	}
	if code, body := authed(t, server, "/act", strings.Replace(good("act-1", "0", signature, record), `"arguments":{"id":"T-1"}`, `"arguments":{"n":1.5}`, 1), token); code != http.StatusBadRequest || body["refusedAt"] != "session" {
		t.Fatalf("a sealed session names the session before unparseable arguments: %d %v", code, body)
	}
	if code, body := authed(t, server, "/act", `{"session":"act-1","platform":"docs","tool":"x","arguments":{"n":1.5},"decision":{},"cites":[]}`, token); code != http.StatusBadRequest || body["refusedAt"] != "session" {
		t.Fatalf("a request faulty at every step is answered by the earliest: %d %v", code, body)
	}
	// A member of the wrong type is a fault at that member's own step, not
	// a decoding error ahead of the ladder: on the sealed session a tool or
	// a platform that is not a string is still answered as the session.
	for _, tc := range []struct{ name, body, step, reason string }{
		{"a tool that is not a string, on a sealed session", `{"session":"act-1","platform":"tickets","tool":7,"arguments":{},"decision":{},"cites":[]}`, "session", "sealed"},
		{"a platform that is not a string, on a sealed session", `{"session":"act-1","platform":7,"tool":"update_ticket","arguments":{},"decision":{},"cites":[]}`, "session", "sealed"},
		{"a session that is not a string", `{"session":7,"platform":"tickets","tool":"update_ticket","arguments":{},"decision":{},"cites":[]}`, "session", "session must be a JSON string"},
		{"a session absent", `{"platform":"tickets","tool":"update_ticket","arguments":{},"decision":{},"cites":[]}`, "session", "session is required"},
		{"a tool that is not a string, on an unknown platform", `{"session":"act-4","platform":"docs","tool":7,"arguments":{},"decision":{},"cites":[]}`, "platform", "allows no writes"},
		{"a platform that is not a string, on an open session", `{"session":"act-4","platform":7,"tool":"update_ticket","arguments":{},"decision":{},"cites":[]}`, "platform", "platform must be a JSON string"},
		{"a tool that is not a string, on a writable platform", `{"session":"act-4","platform":"tickets","tool":7,"arguments":{"n":1.5},"decision":{},"cites":[]}`, "tool", "tool must be a JSON string"},
		{"a tool absent", `{"session":"act-4","platform":"tickets","arguments":{"n":1.5},"decision":{},"cites":[]}`, "tool", "tool is required"},
	} {
		code, body := authed(t, server, "/act", tc.body, token)
		if code != http.StatusBadRequest || body["refusedAt"] != tc.step || !strings.Contains(fmt.Sprint(body["error"]), tc.reason) {
			t.Fatalf("%s: want the %s step (%s), got %d %v", tc.name, tc.step, tc.reason, code, body)
		}
	}
	if service.started.Load() != started+1 {
		t.Fatal("an executor ran for a request refused at the session step")
	}
	restarted, err := newGatewayService(service.storeRoot, testSeed, "gateway:test", service.regPath, service.sources)
	if err != nil {
		t.Fatal(err)
	}
	restarted.identity = &id
	restarted.decisionRecords = records
	restartedServer := httptest.NewServer(restarted.handler())
	defer restartedServer.Close()
	if code, body := authed(t, restartedServer, "/act", good("act-1", "0", signature, record), token); code != http.StatusBadRequest || body["refusedAt"] != "session" || !strings.Contains(fmt.Sprint(body["error"]), "sealed in the registry") {
		t.Fatalf("a session sealed before this start: %d %v", code, body)
	}
	// An unsealed session with receipts on disk, after a restart: the
	// chain cannot be continued from an empty memory, so no action enters
	// it; the cited receipt itself still resolves, since the session it
	// cites is not the one the action would be minted into.
	if code, body := authed(t, server, "/acquire", `{"session":"act-2","source":"screening","arguments":{"q":"acme"}}`, token); code != http.StatusOK {
		t.Fatalf("acquire into a second session: %d %v", code, body)
	}
	predating := strings.Replace(good("act-1", "0", signature, record), `"session":"act-1"`, `"session":"act-2"`, 1)
	if code, body := authed(t, restartedServer, "/act", predating, token); code != http.StatusBadRequest || body["refusedAt"] != "session" || !strings.Contains(fmt.Sprint(body["error"]), "predates this start") {
		t.Fatalf("a session with receipts this engine did not mint: %d %v", code, body)
	}
	// And named as the session before any later fault: the session step
	// judges the store before the decision is read.
	noDecisionInto := func(session string) string {
		return `{"session":"` + session + `","platform":"tickets","tool":"update_ticket","arguments":{},"cites":[{"sessionId":"act-1","callIndex":0,"signature":"` + signature + `"}]}`
	}
	if code, body := authed(t, restartedServer, "/act", noDecisionInto("act-2"), token); code != http.StatusBadRequest || body["refusedAt"] != "session" {
		t.Fatalf("a predating session is named before a missing decision: %d %v", code, body)
	}
	if restarted.started.Load() != 0 {
		t.Fatal("an executor ran after a restart for a session the store already held")
	}
	// A reservation is not a minting: an acquisition admitted into that
	// session after the restart, with nothing minted yet, leaves the
	// session one this process did not mint, and the action is refused at
	// admission as it was at the session step.
	if err := restarted.admit("act-2"); err != nil {
		t.Fatal(err)
	}
	if code, body := authed(t, restartedServer, "/act", predating, token); code != http.StatusBadRequest || body["refusedAt"] != "session" || !strings.Contains(fmt.Sprint(body["error"]), "predates this start") {
		t.Fatalf("a session reserved by an in-flight acquisition: %d %v", code, body)
	}
	if code, body := authed(t, restartedServer, "/act", noDecisionInto("act-2"), token); code != http.StatusBadRequest || body["refusedAt"] != "session" {
		t.Fatalf("a reserved session is named before a missing decision: %d %v", code, body)
	}
	restarted.release("act-2")
	if restarted.started.Load() != 0 {
		t.Fatal("an executor ran into a session an acquisition had only reserved")
	}
	// An old session that lost its first receipt and kept its second: an
	// acquisition into it after a restart recreates the first and counts
	// on from there, and an action into it is still refused, since this
	// process did not find the store empty there when it first admitted --
	// ownership is not a receipt count.
	if code, body := authed(t, server, "/acquire", `{"session":"act-6","source":"screening","arguments":{"q":"a"}}`, token); code != http.StatusOK {
		t.Fatalf("acquire into act-6: %d %v", code, body)
	}
	if code, body := authed(t, server, "/acquire", `{"session":"act-6","source":"screening","arguments":{"q":"b"}}`, token); code != http.StatusOK {
		t.Fatalf("second acquire into act-6: %d %v", code, body)
	}
	if err := os.Remove(filepath.Join(service.storeRoot, "receipts", "act-6", "0.json")); err != nil {
		t.Fatal(err)
	}
	lost, err := newGatewayService(service.storeRoot, testSeed, "gateway:test", service.regPath, service.sources)
	if err != nil {
		t.Fatal(err)
	}
	lost.identity = &id
	lost.decisionRecords = records
	lostServer := httptest.NewServer(lost.handler())
	defer lostServer.Close()
	if code, body := authed(t, lostServer, "/acquire", `{"session":"act-6","source":"screening","arguments":{"q":"c"}}`, token); code != http.StatusOK {
		t.Fatalf("a read into the old session recreates its first receipt: %d %v", code, body)
	}
	lostBefore := lost.started.Load()
	if code, body := authed(t, lostServer, "/act", strings.Replace(good("act-1", "0", signature, record), `"session":"act-1"`, `"session":"act-6"`, 1), token); code != http.StatusBadRequest || body["refusedAt"] != "session" || !strings.Contains(fmt.Sprint(body["error"]), "did not mint") {
		t.Fatalf("an old session with a recreated receipt: %d %v", code, body)
	}
	if lost.started.Load() != lostBefore {
		t.Fatal("an executor ran into an old session whose receipt count a read had raised")
	}
	// A session put on disk between the session step and admission -- an
	// acquisition's stamp landing in the window the evidence checks open --
	// is caught by admission's own recheck under the lock, and nothing runs.
	restarted.beforeAdmit = func() {
		if err := os.MkdirAll(filepath.Join(service.storeRoot, "receipts", "act-7"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(service.storeRoot, "receipts", "act-7", "0.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raced := strings.Replace(good("act-1", "0", signature, record), `"session":"act-1"`, `"session":"act-7"`, 1)
	if code, body := authed(t, restartedServer, "/act", raced, token); code != http.StatusBadRequest || body["refusedAt"] != "session" || !strings.Contains(fmt.Sprint(body["error"]), "did not mint") {
		t.Fatalf("a session that appeared on disk before admission: %d %v", code, body)
	}
	restarted.beforeAdmit = nil
	if restarted.started.Load() != 0 {
		t.Fatal("an executor ran into a session that appeared on disk before admission")
	}
	// A fresh session an action opens: admission makes its directory, the
	// executor runs (and, being the stand-in, fails), the directory stays
	// this process's own, so a second action into it passes the session
	// step and runs the executor again -- and the store still verifies with
	// the empty session there.
	opened := strings.Replace(good("act-1", "0", signature, record), `"session":"act-1"`, `"session":"act-5"`, 1)
	for attempt := 1; attempt <= 2; attempt++ {
		if code, body := authed(t, restartedServer, "/act", opened, token); code == http.StatusOK || body["refusedAt"] != nil {
			t.Fatalf("attempt %d into the session the action opened runs the executor: %d %v", attempt, code, body)
		}
		if restarted.started.Load() != int64(attempt) {
			t.Fatalf("attempt %d: the executor ran %d times", attempt, restarted.started.Load())
		}
	}
	// The empty directory is a session with no receipts: unsealed, as every
	// open session is, and nothing else -- no malformed, misfiled or count
	// finding of its own.
	report, err := verifyWithRegistry(service.storeRoot, service.regPath, "gateway:test", service.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	var about []finding
	for _, f := range report.Findings {
		if f["sessionId"] == "act-5" {
			about = append(about, f)
		}
	}
	if len(about) != 1 || about[0]["status"] != "unregistered-session" {
		t.Fatalf("a session directory an action opened and did not fill is only an unsealed session: %v", about)
	}
	// Each later step, reached by satisfying the ones before it and faulting
	// every one after: the earliest fault names the step, and nothing runs.
	for _, tc := range []struct{ name, body, step string }{
		{"tool, with arguments, decision and cites faulty", `{"session":"act-8","platform":"tickets","tool":"close_ticket","arguments":{"n":1.5},"decision":{"x":1},"cites":[]}`, "tool"},
		{"arguments, with decision and cites faulty", `{"session":"act-8","platform":"tickets","tool":"update_ticket","arguments":{"n":1.5},"decision":{"x":1},"cites":[]}`, "arguments"},
		{"decision, with cites faulty", `{"session":"act-8","platform":"tickets","tool":"update_ticket","arguments":{},"decision":{"x":1},"cites":[]}`, "decision"},
		{"cites, with the record absent", `{"session":"act-8","platform":"tickets","tool":"update_ticket","arguments":{},"decision":{"recordDigest":"` + noRecord + `","packDigest":"sha256:` + strings.Repeat("b", 64) + `"},"cites":[{"sessionId":"act-1","callIndex":0,"signature":"` + signature + `","note":1}]}`, "cites"},
	} {
		code, body := authed(t, restartedServer, "/act", tc.body, token)
		if code != http.StatusBadRequest || body["refusedAt"] != tc.step {
			t.Fatalf("%s: want the %s step, got %d %v", tc.name, tc.step, code, body)
		}
	}
	if restarted.started.Load() != 2 {
		t.Fatal("an executor ran for a request refused at a later step")
	}
	// An entry in the store that is not a directory -- a dangling link --
	// is a session this engine did not mint too; a stat that followed the
	// link would have called it absent.
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(service.storeRoot, "nowhere"), filepath.Join(service.storeRoot, "receipts", "act-9")); err != nil {
			t.Fatal(err)
		}
		if code, body := authed(t, restartedServer, "/act", strings.Replace(good("act-1", "0", signature, record), `"session":"act-1"`, `"session":"act-9"`, 1), token); code != http.StatusBadRequest || body["refusedAt"] != "session" || !strings.Contains(fmt.Sprint(body["error"]), "did not mint") || strings.Contains(fmt.Sprint(body["error"]), service.storeRoot) {
			t.Fatalf("a dangling link where a session would be: %d %v", code, body)
		}
		if code, body := authed(t, restartedServer, "/act", noDecisionInto("act-9"), token); code != http.StatusBadRequest || body["refusedAt"] != "session" {
			t.Fatalf("a dangling link is named as the session before a missing decision: %d %v", code, body)
		}
	}
	// A new session on the restarted engine passes the session step and
	// reaches the evidence, which is what the store holds.
	fresh := strings.Replace(good("act-1", "0", signature, record), `"session":"act-1"`, `"session":"act-3"`, 1)
	if code, body := authed(t, restartedServer, "/act", strings.Replace(fresh, `"tool":"update_ticket"`, `"tool":"close_ticket"`, 1), token); code != http.StatusBadRequest || body["refusedAt"] != "tool" {
		t.Fatalf("a fresh session after a restart reaches the tool step: %d %v", code, body)
	}
	// Arguments that do not parse in the canonical domain, or are not an
	// object, are refused at their own step, after the tool's: what is
	// committed to is what is sent, and the adapter sends an object.
	if code, body := authed(t, restartedServer, "/act", strings.Replace(fresh, `"arguments":{"id":"T-1"}`, `"arguments":{"n":1.5}`, 1), token); code != http.StatusBadRequest || body["refusedAt"] != "arguments" {
		t.Fatalf("unparseable arguments: %d %v", code, body)
	}
	// A citation with a member beyond its three is refused, not trimmed:
	// what the receipt would carry is exactly what was given.
	if code, body := authed(t, restartedServer, "/act", strings.Replace(fresh, `"signature":"`+signature+`"}]`, `"signature":"`+signature+`","note":"x"}]`, 1), token); code != http.StatusBadRequest || body["refusedAt"] != "cites" || !strings.Contains(fmt.Sprint(body["error"]), "note") {
		t.Fatalf("a citation with an extra member: %d %v", code, body)
	}
	if code, body := authed(t, restartedServer, "/act", strings.Replace(fresh, `"arguments":{"id":"T-1"}`, `"arguments":null`, 1), token); code != http.StatusBadRequest || body["refusedAt"] != "arguments" {
		t.Fatalf("null arguments: %d %v", code, body)
	}
	if code, body := authed(t, restartedServer, "/act", strings.Replace(fresh, `"arguments":{"id":"T-1"}`, `"arguments":["T-1"]`, 1), token); code != http.StatusBadRequest || body["refusedAt"] != "arguments" {
		t.Fatalf("array arguments: %d %v", code, body)
	}
	// A session another process puts in the store while a read into it is
	// admitted and running -- absent at admission, present at the stamp.
	// The stamp finds it there: it fails on a receipt already in place, or
	// lands beside an empty directory; either way this process did not make
	// the directory, so the session is not an action's, and an action into
	// it is refused at the session step with nothing run. Ownership taken
	// at admission would have called it this process's own.
	for _, foreign := range []struct {
		session string
		receipt bool
	}{{"act-10", true}, {"act-11", false}} {
		dir := t.TempDir()
		done := make(chan error, 1)
		go func() { _, err := service.acquire(foreign.session, "screening", barrierArg(dir), nil); done <- err }()
		waitForFile(t, filepath.Join(dir, startedFile))
		sessionDir := filepath.Join(service.storeRoot, "receipts", foreign.session)
		if err := os.Mkdir(sessionDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if foreign.receipt {
			if err := os.WriteFile(filepath.Join(sessionDir, "0.json"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		openBarrier(t, filepath.Join(dir, releaseFile))
		if err := <-done; (err != nil) != foreign.receipt {
			t.Fatalf("a read into %s with a foreign directory (receipt in it: %v) finished with %v", foreign.session, foreign.receipt, err)
		}
		before := service.started.Load()
		if code, body := authed(t, server, "/act", strings.Replace(good("act-1", "0", signature, record), `"session":"act-1"`, `"session":"`+foreign.session+`"`, 1), token); code != http.StatusBadRequest || body["refusedAt"] != "session" || !strings.Contains(fmt.Sprint(body["error"]), "did not mint") {
			t.Fatalf("an action into %s, a session another process put there during a read: %d %v", foreign.session, code, body)
		}
		if service.started.Load() != before {
			t.Fatalf("an executor ran into %s, a session another process put there during a read", foreign.session)
		}
	}
	// A seal landing between the evidence checks and admission -- the
	// session open at the session step, sealed by the time the action is
	// admitted -- is caught by admission's own check under the lock, and
	// nothing runs.
	if code, body := authed(t, server, "/acquire", `{"session":"act-12","source":"screening","arguments":{"q":"a"}}`, token); code != http.StatusOK {
		t.Fatalf("acquire into act-12: %d %v", code, body)
	}
	service.beforeAdmit = func() {
		if _, err := service.sealSession("act-12"); err != nil {
			t.Error(err)
		}
	}
	before := service.started.Load()
	if code, body := authed(t, server, "/act", strings.Replace(good("act-1", "0", signature, record), `"session":"act-1"`, `"session":"act-12"`, 1), token); code != http.StatusBadRequest || body["refusedAt"] != "session" || !strings.Contains(fmt.Sprint(body["error"]), "sealed") {
		t.Fatalf("a session sealed between the evidence checks and admission: %d %v", code, body)
	}
	service.beforeAdmit = nil
	if service.started.Load() != before {
		t.Fatal("an executor ran into a session sealed before its admission")
	}
}

// With no identity configured nobody is a requester, and the refusal comes
// before the body is read at all; act itself refuses a nil requester too,
// for a caller that is not the handler.
func TestActWithoutAnIdentityReadsNoBody(t *testing.T) {
	service, _ := testService(t)
	reader := &unreadBody{}
	req := httptest.NewRequest(http.MethodPost, "/act", reader)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	service.handler().ServeHTTP(recorder, req)
	var body map[string]any
	_ = json.NewDecoder(recorder.Body).Decode(&body)
	if recorder.Code != http.StatusUnauthorized || body["refusedAt"] != "requester" || recorder.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("no identity: %d %v", recorder.Code, body)
	}
	if reader.reads.Load() != 0 {
		t.Fatalf("the body was read %d times before the requester was refused", reader.reads.Load())
	}
	if _, err := service.act(json.RawMessage(`"s"`), json.RawMessage(`"tickets"`), json.RawMessage(`"update_ticket"`), json.RawMessage(`{}`), json.RawMessage(`{}`), json.RawMessage(`[]`), nil); err == nil || !strings.Contains(err.Error(), "requester") {
		t.Fatalf("act refuses a nil requester on its own: %v", err)
	}
}

// unreadBody counts the reads made of a request body that is never meant
// to be read: the handler is driven directly, so no client transport reads
// it to send it.
type unreadBody struct{ reads atomic.Int64 }

func (r *unreadBody) Read(p []byte) (int, error) {
	r.reads.Add(1)
	return 0, io.EOF
}

// The executor is started for the one tool requested, whatever the binding
// names beside it.
func TestActNarrowsTheExecutorToTheRequestedTool(t *testing.T) {
	image := "--image=x@sha256:" + strings.Repeat("0", 64)
	spec := sourceSpec{argv: []string{"adapter-mcp", image, "--tools=update,delete", "--endpoint=h", "--", "--tools=all", "--verbose"}, tools: []string{"update", "delete"}, shape: "mcp", endpoint: "h"}
	narrowed := narrowTools(spec, "delete")
	// The adapter's own flag is narrowed; the server's arguments after the
	// delimiter are the binding's and stay as stated.
	if strings.Join(narrowed.argv, " ") != "adapter-mcp "+image+" --tools=delete --endpoint=h -- --tools=all --verbose" || len(narrowed.tools) != 1 || narrowed.tools[0] != "delete" {
		t.Fatalf("narrowed: %+v", narrowed)
	}
	if strings.Join(spec.argv, " ") != "adapter-mcp "+image+" --tools=update,delete --endpoint=h -- --tools=all --verbose" || len(spec.tools) != 2 {
		t.Fatalf("the binding's own source is untouched: %+v", spec)
	}
}
