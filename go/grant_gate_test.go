package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The connection grant a delegated write is admitted under (SPEC.md §10,
// rule 3; gateway #368), with the custody stood in: the answers read, and
// where in the /act ladder the check falls.

// grantStandInAnswer is what the stand-in custody does: exit with code,
// write stdout and stderr, after sleeping for sleep milliseconds. With no
// answer written for the operation it passes the connection it was asked
// for.
type grantStandInAnswer struct {
	Exit   int    `json:"exit"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Sleep  int    `json:"sleep"`
}

// TestGrantCustodyStandIn is the stand-in custody program: it records each
// call -- its arguments, its environment and its request -- and answers as
// told.
func TestGrantCustodyStandIn(t *testing.T) {
	dir := os.Getenv("GRANT_STANDIN")
	if dir == "" {
		return
	}
	request, _ := io.ReadAll(os.Stdin)
	operation := strings.TrimPrefix(os.Args[len(os.Args)-1], "--grants=")
	call, _ := json.Marshal(map[string]any{"args": os.Args[2:], "env": os.Environ(), "request": string(request)})
	f, err := os.OpenFile(filepath.Join(dir, "grant-calls"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(7)
	}
	f.Write(append(call, '\n'))
	f.Close()
	var answer grantStandInAnswer
	raw, err := os.ReadFile(filepath.Join(dir, "grant-answer-"+operation))
	if err != nil {
		var q struct{ Provider, Connection string }
		_ = json.Unmarshal(request, &q)
		if operation == "check" {
			os.Stdout.WriteString(`{"check":"pass","connection":"` + q.Connection + `","provider":"` + q.Provider + `","version":1}` + "\n")
		} else {
			os.Stdout.WriteString(`{"admission":"admit","connection":"` + q.Connection + `","provider":"` + q.Provider + `","version":1}` + "\n")
		}
		os.Exit(0)
	}
	if json.Unmarshal(raw, &answer) != nil {
		os.Exit(8)
	}
	time.Sleep(time.Duration(answer.Sleep) * time.Millisecond)
	os.Stdout.WriteString(answer.Stdout)
	os.Stderr.WriteString(answer.Stderr)
	os.Exit(answer.Exit)
}

// grantStandIn is a gate to the stand-in custody, which keeps its calls and
// reads its answer under root.
func grantStandIn(t testing.TB, root string) *grantGate {
	t.Helper()
	return &grantGate{argv: []string{os.Args[0], "-test.run=^TestGrantCustodyStandIn$", "--"}, env: []string{"GRANT_STANDIN=" + root}, provider: "azure-devops", connection: "boards"}
}

func grantAnswer(t *testing.T, root, operation string, a *grantStandInAnswer) {
	t.Helper()
	path := filepath.Join(root, "grant-answer-"+operation)
	if a == nil {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		return
	}
	raw, _ := json.Marshal(a)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

type grantCall struct {
	Args    []string `json:"args"`
	Env     []string `json:"env"`
	Request string   `json:"request"`
}

func grantCalls(t *testing.T, root string) []grantCall {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "grant-calls"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var calls []grantCall
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var c grantCall
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, c)
	}
	return calls
}

// Only the custody's two answers are read: the admission of the connection
// asked for, and one refusal of a use, each exactly. Anything else is
// grant-unreadable, never a grant that is not there and never one that
// admits; and the custody is asked with the request alone, under an
// environment of the gate's alone.
func TestGrantGateReadsOnlyTheCustodysAnswers(t *testing.T) {
	root := t.TempDir()
	g := &gatewayService{ctx: t.Context(), waitDelay: time.Second}
	gate := grantStandIn(t, root)
	if refusal := g.askCustody(gate, grantCheck); refusal != nil {
		t.Fatalf("a check: %v", refusal)
	}
	if refusal := g.askCustody(gate, grantAdmit); refusal != nil {
		t.Fatalf("an admission: %v", refusal)
	}
	calls := grantCalls(t, root)
	if len(calls) != 2 || calls[0].Request != `{"connection":"boards","provider":"azure-devops"}`+"\n" || len(calls[0].Env) != 1 || calls[0].Env[0] != "GRANT_STANDIN="+root ||
		strings.Join(calls[0].Args, " ") != "-- --grants=check" || strings.Join(calls[1].Args, " ") != "-- --grants=admit" {
		t.Fatalf("the custody was asked: %+v", calls)
	}
	// check answers in its own form, and never with an owner refusal: the
	// owner read is admit's alone.
	pass := `{"check":"pass","connection":"boards","provider":"azure-devops","version":1}` + "\n"
	for _, c := range []struct {
		name   string
		answer grantStandInAnswer
		want   string
	}{
		{"an admission for a check", grantStandInAnswer{Stdout: `{"admission":"admit","connection":"boards","provider":"azure-devops","version":1}` + "\n"}, "grant-unreadable: the connection custody's answer for the platform's grant could not be read"},
		{"a check for another connection", grantStandInAnswer{Stdout: strings.Replace(pass, "boards", "other", 1)}, "grant-unreadable: the connection custody's answer for the platform's grant could not be read"},
		{"an owner refusal from check", grantStandInAnswer{Exit: 1, Stderr: "grants: owner-unknown\n"}, "grant-unreadable: the connection custody's answer for the platform's grant could not be read"},
		{"an owner removed from check", grantStandInAnswer{Exit: 1, Stderr: "grants: owner-removed\n"}, "grant-unreadable: the connection custody's answer for the platform's grant could not be read"},
		{"quarantined at check", grantStandInAnswer{Exit: 1, Stderr: "grants: grant-quarantined\n"}, "grant-quarantined: the platform's connection grant is quarantined"},
	} {
		grantAnswer(t, root, grantCheck, &c.answer)
		if refusal := g.askCustody(gate, grantCheck); refusal == nil || refusal.Error() != c.want {
			t.Errorf("%s: %v", c.name, refusal)
		}
	}
	grantAnswer(t, root, grantCheck, &grantStandInAnswer{Stdout: pass})
	if refusal := g.askCustody(gate, grantCheck); refusal != nil {
		t.Fatalf("a check that passes: %v", refusal)
	}
	unreadable := "grant-unreadable: the connection custody's answer for the platform's grant could not be read"
	admit := `{"admission":"admit","connection":"boards","provider":"azure-devops","version":1}` + "\n"
	for _, c := range []struct {
		name   string
		answer grantStandInAnswer
		want   string
	}{
		{"another connection admitted", grantStandInAnswer{Stdout: `{"admission":"admit","connection":"other","provider":"azure-devops","version":1}` + "\n"}, unreadable},
		{"an admission with more", grantStandInAnswer{Stdout: `{"admission":"admit","connection":"boards","extra":1,"provider":"azure-devops","version":1}` + "\n"}, unreadable},
		{"an admission unterminated", grantStandInAnswer{Stdout: strings.TrimSuffix(admit, "\n")}, unreadable},
		{"an admission and a complaint", grantStandInAnswer{Stdout: admit, Stderr: "warning\n"}, unreadable},
		{"nothing said", grantStandInAnswer{}, unreadable},
		{"quarantined", grantStandInAnswer{Exit: 1, Stderr: "grants: grant-quarantined\n"}, "grant-quarantined: the platform's connection grant is quarantined"},
		{"revoked", grantStandInAnswer{Exit: 1, Stderr: "grants: grant-revoked\n"}, "grant-revoked: the platform's connection grant is revoked"},
		{"idle", grantStandInAnswer{Exit: 1, Stderr: "grants: grant-idle-expired\n"}, "grant-idle-expired: the platform's connection grant passed its idle expiry and is revoked"},
		{"owner removed", grantStandInAnswer{Exit: 1, Stderr: "grants: owner-removed\n"}, "owner-removed: the owner of the platform's connection grant was removed"},
		{"owner unknown", grantStandInAnswer{Exit: 1, Stderr: "grants: owner-unknown\n"}, "owner-unknown: the standing of the owner of the platform's connection grant could not be read"},
		{"no record", grantStandInAnswer{Exit: 1, Stderr: "grants: grant-unknown\n"}, "grant-unknown: the connection custody holds no grant of the platform's connection"},
		{"excess, its scopes not repeated", grantStandInAnswer{Exit: 1, Stderr: "grants: excess-scope: vso.code_write\n"}, "excess-scope: the platform's connection grant holds a scope no operation declares"},
		{"excess unnamed", grantStandInAnswer{Exit: 1, Stderr: "grants: excess-scope\n"}, unreadable},
		{"excess naming nothing", grantStandInAnswer{Exit: 1, Stderr: "grants: excess-scope: \n"}, unreadable},
		{"excess and another line", grantStandInAnswer{Exit: 1, Stderr: "grants: excess-scope: vso.code_write\ngrants: grant-revoked\n"}, unreadable},
		{"custody unreadable", grantStandInAnswer{Exit: 1, Stderr: "grants: private-storage-unavailable\n"}, unreadable},
		{"connection changed", grantStandInAnswer{Exit: 1, Stderr: "grants: connect-required\n"}, unreadable},
		{"a refusal unterminated", grantStandInAnswer{Exit: 1, Stderr: "grants: grant-unknown"}, unreadable},
		{"two refusals", grantStandInAnswer{Exit: 1, Stderr: "grants: grant-unknown\ngrants: grant-revoked\n"}, unreadable},
		{"a refusal and an answer", grantStandInAnswer{Exit: 1, Stdout: admit, Stderr: "grants: grant-unknown\n"}, unreadable},
		{"a refusal at another exit", grantStandInAnswer{Exit: 2, Stderr: "grants: grant-unknown\n"}, unreadable},
		{"a refusal without its prefix", grantStandInAnswer{Exit: 1, Stderr: "grant-unknown\n"}, unreadable},
		{"stderr past its bound", grantStandInAnswer{Exit: 1, Stderr: "grants: grant-unknown\n" + strings.Repeat("x", grantAnswerBytes)}, unreadable},
		// The bound's two ends: a refusal of exactly grantAnswerBytes is read,
		// one byte more is not, whatever it would have said.
		{"excess at its bound", grantStandInAnswer{Exit: 1, Stderr: "grants: excess-scope: " + strings.Repeat("s", grantAnswerBytes-len("grants: excess-scope: \n")) + "\n"}, "excess-scope: the platform's connection grant holds a scope no operation declares"},
		{"excess past its bound", grantStandInAnswer{Exit: 1, Stderr: "grants: excess-scope: " + strings.Repeat("s", grantAnswerBytes+1-len("grants: excess-scope: \n")) + "\n"}, unreadable},
		{"stdout past its bound", grantStandInAnswer{Stdout: admit + strings.Repeat(" ", grantAnswerBytes)}, unreadable},
	} {
		grantAnswer(t, root, grantAdmit, &c.answer)
		refusal := g.askCustody(gate, grantAdmit)
		if c.want == "" && refusal != nil || c.want != "" && (refusal == nil || refusal.Error() != c.want || refusal.at != "grant") {
			t.Errorf("%s: %v", c.name, refusal)
		}
	}
	// A custody that does not answer in time.
	before := grantGateTimeout
	grantGateTimeout = 200 * time.Millisecond
	t.Cleanup(func() { grantGateTimeout = before })
	grantAnswer(t, root, grantAdmit, &grantStandInAnswer{Stdout: admit, Sleep: 2000})
	if refusal := g.askCustody(gate, grantAdmit); refusal == nil || refusal.Error() != unreadable {
		t.Fatalf("a late answer: %v", refusal)
	}
	// A custody program that is not there.
	absent := &grantGate{argv: []string{filepath.Join(root, "absent")}, env: []string{}, provider: "azure-devops", connection: "boards"}
	if refusal := g.askCustody(absent, grantCheck); refusal == nil || refusal.Error() != unreadable {
		t.Fatalf("no custody program: %v", refusal)
	}
	if refusal := g.askCustody(nil, grantCheck); refusal == nil || refusal.name != refusalGrantUnknown {
		t.Fatalf("no gate: %v", refusal)
	}
}

// presentRaw is present, answering the status and the body's bytes.
func (h *delegationHarness) presentRaw(t *testing.T, path, body, credential string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "DPoP "+credential)
	req.Header.Set("DPoP", h.proof(t, path, credential, nil, nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func (h *delegationHarness) setGrant(gate *grantGate) {
	spec := h.g.sources["tickets/write"]
	spec.grant = gate
	h.g.sources["tickets/write"] = spec
}

// A delegated write on a platform that names no grant is refused before
// anything: no custody asked, no admission read, nothing sent; a grant whose
// state the custody refuses is refused before the issuing host is read, so
// nothing is counted. The owner read is made after the counting admission
// answers admit (RFC 0030 §2): a call step 12 refuses reports step 12's
// refusal and is never taken to the owner read; one the owner read refuses
// sends nothing and leaves its count used. The refused key is free once the
// grant admits. An undelegated write is the operator's own and asks no
// custody.
func TestDelegatedWriteIsHeldToTheGrantFirst(t *testing.T) {
	h := newDelegationHarness(t, false)
	cred := h.credential(t, statement(t, nil))
	reads := h.host.readCount()

	h.setGrant(nil)
	key := delegationKey(1)
	status, raw := h.presentRaw(t, "/act", h.actBody("s-none", key, ""), cred)
	if status != http.StatusForbidden || raw != `{"error":"grant-unknown: platform tickets names no connection grant, and a delegated write is admitted only under one","refusal":"grant-unknown","refusedAt":"grant"}` {
		t.Fatalf("no grant named: %d %s", status, raw)
	}
	if h.sent(key) != 0 || h.host.readCount() != reads || len(grantCalls(t, h.root)) != 0 {
		t.Fatalf("a write on a platform with no grant reached something: sent %d, reads %d->%d, custody %d", h.sent(key), reads, h.host.readCount(), len(grantCalls(t, h.root)))
	}

	h.setGrant(grantStandIn(t, h.root))
	grantAnswer(t, h.root, grantCheck, &grantStandInAnswer{Exit: 1, Stderr: "grants: grant-quarantined\n"})
	key = delegationKey(2)
	status, raw = h.presentRaw(t, "/act", h.actBody("s-quarantined", key, ""), cred)
	if status != http.StatusForbidden || raw != `{"error":"grant-quarantined: the platform's connection grant is quarantined","refusal":"grant-quarantined","refusedAt":"grant"}` {
		t.Fatalf("a quarantined grant: %d %s", status, raw)
	}
	if h.sent(key) != 0 || h.host.readCount() != reads || h.host.counted() != 0 || len(grantCalls(t, h.root)) != 1 {
		t.Fatalf("a refused grant reached the host or the target: sent %d, reads %d->%d, counted %d", h.sent(key), reads, h.host.readCount(), h.host.counted())
	}

	// Both step 12 and the owner read would refuse: step 12's is reported.
	grantAnswer(t, h.root, grantCheck, nil)
	grantAnswer(t, h.root, grantAdmit, &grantStandInAnswer{Exit: 1, Stderr: "grants: owner-removed\n"})
	h.host.setAnswer(func(b map[string]any) (int, string) {
		return http.StatusOK, `{"admission":"refuse","refusal":"subject-unauthorized"}`
	})
	status, raw = h.presentRaw(t, "/act", h.actBody("s-both", key, ""), cred)
	if status != http.StatusForbidden || raw != `{"error":"subject-unauthorized: the issuing host answers subject-unauthorized","refusal":"subject-unauthorized","refusedAt":"delegation"}` {
		t.Fatalf("step 12 and the owner both refusing: %d %s", status, raw)
	}
	if calls := grantCalls(t, h.root); h.sent(key) != 0 || h.host.counted() != 1 || len(calls) != 2 || strings.Join(calls[1].Args, " ") != "-- --grants=check" {
		t.Fatalf("step 12 refusing: sent %d, counted %d, custody %+v", h.sent(key), h.host.counted(), calls)
	}
	// The owner read alone refuses: after the count, nothing sent.
	h.host.setAnswer(nil)
	status, raw = h.presentRaw(t, "/act", h.actBody("s-owner", key, ""), cred)
	if status != http.StatusForbidden || raw != `{"error":"owner-removed: the owner of the platform's connection grant was removed","refusal":"owner-removed","refusedAt":"grant"}` {
		t.Fatalf("the owner removed: %d %s", status, raw)
	}
	if calls := grantCalls(t, h.root); h.sent(key) != 0 || h.host.counted() != 2 || len(calls) != 4 || strings.Join(calls[3].Args, " ") != "-- --grants=admit" {
		t.Fatalf("the owner refusing: sent %d, counted %d, custody %d", h.sent(key), h.host.counted(), len(calls))
	}

	grantAnswer(t, h.root, grantAdmit, nil)
	status, raw = h.presentRaw(t, "/act", h.actBody("s-admitted", key, ""), cred)
	if status != http.StatusOK || h.sent(key) != 1 || h.host.counted() != 3 || len(grantCalls(t, h.root)) != 6 {
		t.Fatalf("the grant admitting: %d %s, sent %d, counted %d", status, raw, h.sent(key), h.host.counted())
	}

	// The operator's own write: the custody is never asked, whatever it
	// would answer.
	grantAnswer(t, h.root, grantCheck, &grantStandInAnswer{Exit: 1, Stderr: "grants: grant-revoked\n"})
	undelegated := delegationKey(3)
	out, err := h.g.act(json.RawMessage(`"s-operator"`), json.RawMessage(`"tickets"`), json.RawMessage(`"query"`), json.RawMessage(`{"ticket":"T-1"}`), h.call.Decision, h.call.Cites, actionKeysWho, json.RawMessage(`"`+undelegated+`"`))
	if err != nil || out["receipt"] == nil || actionKeysSent(h.root, undelegated) != 1 || len(grantCalls(t, h.root)) != 6 {
		t.Fatalf("an undelegated write: %v %v, sent %d, custody %d", out, err, actionKeysSent(h.root, undelegated), len(grantCalls(t, h.root)))
	}
}
