//go:build linux || darwin

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A delegated write through /act, admitted under a connection grant the
// real connection custody holds (gateway #368, SPEC.md §10 rule 3): the
// custody program built from ../adapters, over a Notion custody written as
// custody keeps it.

// buildCustody builds gateway-connections into a directory of the test's.
func buildCustody(t *testing.T) string {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH")
	}
	bin := filepath.Join(t.TempDir(), "gateway-connections")
	build := exec.Command(goTool, "build", "-buildvcs=false", "-o", bin, "./cmd/gateway-connections")
	build.Dir = filepath.Join("..", "adapters")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the custody: %v\n%s", err, out)
	}
	return bin
}

// notionCustody is a custody root holding one Notion connection for the
// principal operator.
func notionCustody(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sum := sha256.Sum256([]byte("operator"))
	held := filepath.Join(dir, "notion", hex.EncodeToString(sum[:]))
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(held, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "notion"), 0o700); err != nil {
		t.Fatal(err)
	}
	state := `{"epoch":"e1","client":{"clientId":"","clientSecret":""},"connection":{"id":"notion-connection-1","account":{"id":"","email":"","name":""},"access":"notion-access-private","refresh":"","expires":0},"disabled":false}`
	if err := os.WriteFile(filepath.Join(held, "state.json"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// custodyGrants runs one of the operator's grant operations.
func custodyGrants(t *testing.T, bin, dir, operation, request string) string {
	t.Helper()
	cmd := exec.Command(bin, "--grants="+operation, "--state-dir="+dir, "--principal=operator", "--provider=notion")
	cmd.Env = []string{}
	cmd.Stdin = strings.NewReader(request)
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			t.Fatalf("grants %s: %v: %s", operation, err, exit.Stderr)
		}
		t.Fatal(err)
	}
	return string(out)
}

func custodyGate(bin, dir, provider, connection string) *grantGate {
	return &grantGate{argv: []string{bin, "--state-dir=" + dir, "--principal=operator", "--provider=" + provider}, env: []string{}, provider: provider, connection: connection}
}

func TestDelegatedWriteIsAdmittedUnderTheCustodysGrant(t *testing.T) {
	bin := buildCustody(t)
	h := newDelegationHarness(t, false)
	cred := h.credential(t, statement(t, nil))
	dir := notionCustody(t)
	h.setGrant(custodyGate(bin, dir, "notion", "notion"))

	// Admitted: the write is sent once, and the grant records its use.
	key := delegationKey(1)
	if status, raw := h.presentRaw(t, "/act", h.actBody("s-admitted", key, ""), cred); status != http.StatusOK || h.sent(key) != 1 || h.host.counted() != 1 {
		t.Fatalf("an admitted write: %d %s, sent %d, counted %d", status, raw, h.sent(key), h.host.counted())
	}
	var report struct {
		Connections []struct {
			Connection string  `json:"connection"`
			LastUsedAt *string `json:"lastUsedAt"`
			State      string  `json:"state"`
		} `json:"connections"`
	}
	if err := json.Unmarshal([]byte(custodyGrants(t, bin, dir, "report", "")), &report); err != nil || len(report.Connections) != 1 || report.Connections[0].LastUsedAt == nil || report.Connections[0].State != "active" {
		t.Fatalf("the use is not recorded: %+v %v", report, err)
	}

	// Each refusal of the grant's state is reached before the issuing host is
	// read and before the write's credential is read or anything is sent.
	// The owner read is made after the counting admission answers admit
	// (RFC 0030 §2): its refusal sends nothing and leaves the count used.
	refusedAfter := func(name, session string, n int, want string, hostReads int) {
		t.Helper()
		reads, counted, key := h.host.readCount(), h.host.counted(), delegationKey(n)
		status, raw := h.presentRaw(t, "/act", h.actBody(session, key, ""), cred)
		if status != http.StatusForbidden || raw != want {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if h.sent(key) != 0 || h.host.readCount() != reads+hostReads || h.host.counted() != counted+hostReads {
			t.Fatalf("%s: sent %d, the host read %d->%d, counted %d->%d", name, h.sent(key), reads, h.host.readCount(), counted, h.host.counted())
		}
	}
	refused := func(name, session string, n int, want string) { t.Helper(); refusedAfter(name, session, n, want, 0) }
	const owner = `{"provider":"notion","connection":"notion","owner":{"kind":"person","issuer":"https://login.example","subject":"approver-7"},"ownerHost":"desk"}`
	custodyGrants(t, bin, dir, "set-owner", owner)
	refusedAfter("owner-unknown", "s-owner", 2, `{"error":"owner-unknown: the standing of the owner of the platform's connection grant could not be read","refusal":"owner-unknown","refusedAt":"grant"}`, 1)
	// Step 12 and the owner read would both refuse: step 12's refusal is the
	// one reported, and the owner read is not made.
	h.host.setAnswer(func(b map[string]any) (int, string) {
		return http.StatusOK, `{"admission":"refuse","refusal":"subject-unauthorized"}`
	})
	refusedAfter("step 12 before the owner", "s-both", 11, `{"error":"subject-unauthorized: the issuing host answers subject-unauthorized","refusal":"subject-unauthorized","refusedAt":"delegation"}`, 1)
	h.host.setAnswer(nil)
	custodyGrants(t, bin, dir, "remove-owner", `{"owner":{"kind":"person","issuer":"https://login.example","subject":"approver-7"},"ownerHost":"desk","removal":"quarantine"}`)
	refused("grant-quarantined", "s-quarantined", 3, `{"error":"grant-quarantined: the platform's connection grant is quarantined","refusal":"grant-quarantined","refusedAt":"grant"}`)
	custodyGrants(t, bin, dir, "revoke", `{"provider":"notion","connection":"notion"}`)
	refused("grant-revoked", "s-revoked", 4, `{"error":"grant-revoked: the platform's connection grant is revoked","refusal":"grant-revoked","refusedAt":"grant"}`)

	idle := notionCustody(t)
	h.setGrant(custodyGate(bin, idle, "notion", "notion"))
	custodyGrants(t, bin, idle, "set-idle-expiry", `{"provider":"notion","connection":"notion","idleExpiry":1}`)
	time.Sleep(10 * time.Millisecond)
	refused("grant-idle-expired", "s-idle", 5, `{"error":"grant-idle-expired: the platform's connection grant passed its idle expiry and is revoked","refusal":"grant-idle-expired","refusedAt":"grant"}`)

	// A scope granted since that no operation declares (drift).
	excess := notionCustody(t)
	h.setGrant(custodyGate(bin, excess, "notion", "notion"))
	custodyGrants(t, bin, excess, "set-idle-expiry", `{"provider":"notion","connection":"notion","idleExpiry":null}`)
	sum := sha256.Sum256([]byte("operator"))
	ledger := filepath.Join(excess, "notion", hex.EncodeToString(sum[:]), "connection-grants.json")
	raw, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(raw), `"granted":["default"]`, `"granted":["default","insert_content"]`, 1)
	if edited == string(raw) {
		t.Fatalf("the ledger names no granted scope: %s", raw)
	}
	if err := os.WriteFile(ledger, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	refused("excess-scope", "s-excess", 6, `{"error":"excess-scope: the platform's connection grant holds a scope no operation declares","refusal":"excess-scope","refusedAt":"grant"}`)

	// No record: a connection the custody does not hold, and a provider
	// with no custody at all.
	other := notionCustody(t)
	unknown := `{"error":"grant-unknown: the connection custody holds no grant of the platform's connection","refusal":"grant-unknown","refusedAt":"grant"}`
	h.setGrant(custodyGate(bin, other, "notion", "another"))
	refused("no such connection", "s-another", 7, unknown)
	h.setGrant(custodyGate(bin, other, "gmail", "gmail"))
	refused("no custody", "s-gmail", 8, unknown)
	if _, err := os.Lstat(filepath.Join(other, "gmail")); !os.IsNotExist(err) {
		t.Fatalf("the admission made a custody: %v", err)
	}

	// A custody that cannot be read refuses; it is never taken for one that
	// is not there. Once it can be, the refused key is the write's.
	unreadable := `{"error":"grant-unreadable: the connection custody's answer for the platform's grant could not be read","refusal":"grant-unreadable","refusedAt":"grant"}`
	h.setGrant(custodyGate(bin, other, "notion", "notion"))
	if err := os.Chmod(other, 0o750); err != nil {
		t.Fatal(err)
	}
	refused("an unreadable custody", "s-unreadable", 9, unreadable)
	if err := os.Chmod(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if status, raw := h.presentRaw(t, "/act", h.actBody("s-readable", delegationKey(9), ""), cred); status != http.StatusOK || h.sent(delegationKey(9)) != 1 {
		t.Fatalf("the custody readable again: %d %s", status, raw)
	}
	h.setGrant(custodyGate(filepath.Join(t.TempDir(), "absent"), other, "notion", "notion"))
	refused("no custody program", "s-absent", 10, unreadable)
}

// A delegated acquisition and the read-back of a delegated key's uncertain
// action, each admitted under the grant the real connection custody holds
// (gateway #372, SPEC.md §10 rule 3).
func TestDelegatedReadsAreAdmittedUnderTheCustodysGrant(t *testing.T) {
	bin := buildCustody(t)
	h := newDelegationHarness(t, false)
	reads := h.countReads(t)
	cred := h.credential(t, statement(t, nil))
	dir := notionCustody(t)
	h.setGrant(custodyGate(bin, dir, "notion", "notion"))
	report := func(dir string) (lastUsedAt *string, state string) {
		t.Helper()
		var r struct {
			Connections []struct {
				LastUsedAt *string `json:"lastUsedAt"`
				State      string  `json:"state"`
			} `json:"connections"`
		}
		if err := json.Unmarshal([]byte(custodyGrants(t, bin, dir, "report", "")), &r); err != nil || len(r.Connections) != 1 {
			t.Fatalf("the report: %+v %v", r, err)
		}
		return r.Connections[0].LastUsedAt, r.Connections[0].State
	}

	// Admitted: the acquisition runs once, counted once, and the grant
	// records its use.
	if status, raw := h.presentRaw(t, "/acquire", h.acquireBody("a-admitted", "query"), cred); status != http.StatusOK || reads() != 1 || h.host.counted() != 1 {
		t.Fatalf("an admitted acquisition: %d %s, reads %d, counted %d", status, raw, reads(), h.host.counted())
	}
	if used, state := report(dir); used == nil || state != "active" {
		t.Fatalf("the use is not recorded: %v %s", used, state)
	}
	// An uncertain write under the same grant, read back while it is live.
	actionKeysMode(t, h.root, "write", "drop")
	key := delegationKey(1)
	status, out := h.present(t, "/act", h.actBody("w-uncertain", key, ""), cred)
	if status != http.StatusOK || h.sent(key) != 1 || reads() != 2 {
		t.Fatalf("the uncertain write: %d %v, sent %d, reads %d", status, out, h.sent(key), reads())
	}
	reconciledBy(t, out)

	// A refused acquisition runs nothing; one refused by the grant's state
	// reads no issuing host and counts nothing, and the owner read follows
	// the counting admission.
	acquisition := func(name, session, want string, hostReads int) {
		t.Helper()
		before, counted := h.host.readCount(), h.host.counted()
		status, raw := h.presentRaw(t, "/acquire", h.acquireBody(session, "query"), cred)
		if status != http.StatusForbidden || raw != want {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if reads() != 2 || h.host.readCount() != before+hostReads || h.host.counted() != counted+hostReads {
			t.Fatalf("%s: reads %d, the host read %d->%d, counted %d->%d", name, reads(), before, h.host.readCount(), counted, h.host.counted())
		}
	}
	// A refused read-back runs nothing, sends nothing again and counts
	// nothing: the key answers with its uncertain record.
	const prefix = "action-reconciliation-unavailable: the platform's connection grant refused the read-back, and it did not run: "
	readBack := func(name, session, want string) {
		t.Helper()
		counted := h.host.counted()
		status, raw := h.presentRaw(t, "/act", h.actBody(session, key, ""), cred)
		var body map[string]any
		if err := json.Unmarshal([]byte(raw), &body); err != nil || status != http.StatusConflict || body["error"] != prefix+want || body["action"] == nil || len(body) != 2 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if h.sent(key) != 1 || reads() != 2 || h.host.counted() != counted {
			t.Fatalf("%s: sent %d, reads %d, counted %d->%d", name, h.sent(key), reads(), counted, h.host.counted())
		}
	}
	const owner = `{"provider":"notion","connection":"notion","owner":{"kind":"person","issuer":"https://login.example","subject":"approver-7"},"ownerHost":"desk"}`
	custodyGrants(t, bin, dir, "set-owner", owner)
	acquisition("owner-unknown", "a-owner", `{"error":"owner-unknown: the standing of the owner of the platform's connection grant could not be read","refusal":"owner-unknown"}`, 1)
	readBack("owner-unknown", "w-owner", "owner-unknown: the standing of the owner of the platform's connection grant could not be read")
	if _, state := report(dir); state != "active" {
		t.Fatalf("an unanswered owner read changed the grant: %s", state)
	}
	custodyGrants(t, bin, dir, "remove-owner", `{"owner":{"kind":"person","issuer":"https://login.example","subject":"approver-7"},"ownerHost":"desk","removal":"quarantine"}`)
	acquisition("grant-quarantined", "a-quarantined", `{"error":"grant-quarantined: the platform's connection grant is quarantined","refusal":"grant-quarantined"}`, 0)
	readBack("grant-quarantined", "w-quarantined", "grant-quarantined: the platform's connection grant is quarantined")
	custodyGrants(t, bin, dir, "revoke", `{"provider":"notion","connection":"notion"}`)
	acquisition("grant-revoked", "a-revoked", `{"error":"grant-revoked: the platform's connection grant is revoked","refusal":"grant-revoked"}`, 0)
	readBack("grant-revoked", "w-revoked", "grant-revoked: the platform's connection grant is revoked")
	// The read-back's own scope before the grant: a link that excludes the
	// live source is refused as unauthenticated, the grant revoked or not.
	writeOnly := h.credential(t, statement(t, map[string]any{"id": strings.Repeat("88", 16), "scope": map[string]any{"sources": []any{scopeOf("tickets/write", []any{"query"}, []any{"act"}, map[string]any{})}}}))
	if status, raw := h.presentRaw(t, "/act", h.actBody("w-narrow", key, ""), writeOnly); status != http.StatusForbidden || raw != `{"error":"action-key-unauthenticated","refusal":"action-key-unauthenticated","refusedAt":"action-key"}` || h.sent(key) != 1 || reads() != 2 {
		t.Fatalf("a link without the live source: %d %s", status, raw)
	}

	idle := notionCustody(t)
	h.setGrant(custodyGate(bin, idle, "notion", "notion"))
	custodyGrants(t, bin, idle, "set-idle-expiry", `{"provider":"notion","connection":"notion","idleExpiry":1}`)
	time.Sleep(10 * time.Millisecond)
	acquisition("grant-idle-expired", "a-idle", `{"error":"grant-idle-expired: the platform's connection grant passed its idle expiry and is revoked","refusal":"grant-idle-expired"}`, 0)

	excess := notionCustody(t)
	h.setGrant(custodyGate(bin, excess, "notion", "notion"))
	custodyGrants(t, bin, excess, "set-idle-expiry", `{"provider":"notion","connection":"notion","idleExpiry":null}`)
	sum := sha256.Sum256([]byte("operator"))
	ledger := filepath.Join(excess, "notion", hex.EncodeToString(sum[:]), "connection-grants.json")
	raw, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(raw), `"granted":["default"]`, `"granted":["default","insert_content"]`, 1)
	if edited == string(raw) {
		t.Fatalf("the ledger names no granted scope: %s", raw)
	}
	if err := os.WriteFile(ledger, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	acquisition("excess-scope", "a-excess", `{"error":"excess-scope: the platform's connection grant holds a scope no operation declares","refusal":"excess-scope"}`, 0)
	readBack("excess-scope", "w-excess", "excess-scope: the platform's connection grant holds a scope no operation declares")

	// A custody that cannot be read refuses both; it is never taken for one
	// that is not there. Once it can be, the key reads back.
	other := notionCustody(t)
	h.setGrant(custodyGate(bin, other, "notion", "notion"))
	if err := os.Chmod(other, 0o750); err != nil {
		t.Fatal(err)
	}
	acquisition("an unreadable custody", "a-unreadable", `{"error":"grant-unreadable: the connection custody's answer for the platform's grant could not be read","refusal":"grant-unreadable"}`, 0)
	readBack("an unreadable custody", "w-unreadable", "grant-unreadable: the connection custody's answer for the platform's grant could not be read")
	if err := os.Chmod(other, 0o700); err != nil {
		t.Fatal(err)
	}
	status, out = h.present(t, "/act", h.actBody("w-readable", key, ""), cred)
	if status != http.StatusOK || h.sent(key) != 1 || reads() != 3 {
		t.Fatalf("the custody readable again: %d %v, sent %d, reads %d", status, out, h.sent(key), reads())
	}
	reconciledBy(t, out)
}
