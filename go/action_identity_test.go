package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// actionKeysRelease is the sources of actionKeysSources as one release
// composes the adapter's command line: release 1 derives two flags, and
// release 2 adds a third and emits them in another order. The approved
// content -- binding, tools, endpoint, recovery contract -- is the same.
func actionKeysRelease(t testing.TB, root string, release int) map[string]sourceSpec {
	t.Helper()
	sources := actionKeysSources(t, root, os.Args[0])
	for _, name := range []string{"tickets/write", "tickets/live"} {
		spec := sources[name]
		switch release {
		case 1:
			spec.argv = []string{os.Args[0], "-test.run=^TestActionKeysTarget$", "-test.v=false"}
		case 2:
			spec.argv = []string{os.Args[0], "-test.count=1", "-test.v=false", "-test.run=^TestActionKeysTarget$"}
		}
		sources[name] = spec
	}
	return sources
}

// actionKeysIdentity is the identity act computes for actionKeysAct's
// request under key.
func actionKeysIdentity(t testing.TB, sources map[string]sourceSpec, c actionKeysCall, key string) actionIdentity {
	t.Helper()
	args, _ := parseJSON([]byte(`{"ticket":"T-1","request_id":"` + key + `"}`))
	decision, _ := parseJSON(c.Decision)
	cites, _ := parseJSON(c.Cites)
	write := narrowTools(sources["tickets/write"], "query")
	identity, err := actionFingerprint("tickets", "query", args, decision, cites, write, write.actionRecovery["query"], sources["tickets/live"])
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

// #355: a release that adds a derived flag and reorders the others, installed
// while keys are pending, leaves each pending key its own. A reservation that
// never dispatched is dispatched once; one whose dispatch may have begun is
// read back and never sent; one whose write committed and lost its answer is
// read back; a completed one is replayed. None is an action-key-conflict.
func TestActionUpgradeThatChangesDerivedFlagsKeepsPendingKeys(t *testing.T) {
	root, _, c := actionKeysSetup(t)
	before := actionKeysRelease(t, root, 1)
	after := actionKeysRelease(t, root, 2)
	if a, b := actionKeysIdentity(t, before, c, strings.Repeat("0", 64)), actionKeysIdentity(t, after, c, strings.Repeat("0", 64)); a.previous == b.previous {
		t.Fatal("the two releases' command lines do not differ as identity version 1 reads them; the test shows nothing")
	}
	g := actionKeysService(t, root, before)
	journal, err := openActionJournal(g.storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.close()

	// Reserved by release 1, killed before its dispatch marker.
	reserved := strings.Repeat("a", 64)
	claim, err := journal.reserve(g.actionNamespace(actionKeysWho, reserved), actionKeysIdentity(t, before, c, reserved))
	if err != nil {
		t.Fatal(err)
	}
	claim.close()
	// Reserved by release 1 and killed after its dispatch marker.
	marked := strings.Repeat("b", 64)
	if claim, err = journal.reserve(g.actionNamespace(actionKeysWho, marked), actionKeysIdentity(t, before, c, marked)); err != nil {
		t.Fatal(err)
	}
	if err = claim.claimDispatch(1); err != nil {
		t.Fatal(err)
	}
	claim.close()
	// Committed under release 1, its answer lost: recorded as uncertain.
	dropped := strings.Repeat("d", 64)
	actionKeysMode(t, root, "write", "drop")
	if _, err = actionKeysAct(g, c, "dropped-before", dropped); err != nil {
		t.Fatal(err)
	}
	actionKeysMode(t, root, "write", "respond")
	// Completed under release 1.
	completed := strings.Repeat("e", 64)
	first, err := actionKeysAct(g, c, "completed-before", completed)
	if err != nil {
		t.Fatal(err)
	}

	upgraded := actionKeysService(t, root, after)
	if _, err = actionKeysAct(upgraded, c, "reserved-after", reserved); err != nil {
		t.Fatalf("a reservation that never dispatched was refused after the upgrade: %v", err)
	}
	if sent := actionKeysSent(root, reserved); sent != 1 {
		t.Fatalf("a reservation that never dispatched was sent %d times after the upgrade", sent)
	}
	for _, key := range []string{marked, dropped} {
		out, err := actionKeysAct(upgraded, c, "pending-after-"+key[:1], key)
		if err != nil {
			t.Fatalf("a pending uncertain key was refused after the upgrade: %v", err)
		}
		if out["reconciliation"] == nil {
			t.Fatalf("a pending uncertain key was not read back: %v", out)
		}
	}
	if actionKeysSent(root, marked) != 0 || actionKeysSent(root, dropped) != 1 {
		t.Fatal("the upgrade sent a write that may have been sent")
	}
	startedBefore := upgraded.started.Load()
	again, err := actionKeysAct(upgraded, c, "completed-after", completed)
	if err != nil {
		t.Fatalf("a completed key was refused after the upgrade: %v", err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(again)
	if string(a) != string(b) || upgraded.started.Load() != startedBefore || actionKeysSent(root, completed) != 1 {
		t.Fatal("a completed key was not replayed after the upgrade")
	}
	// Different content under a pending key is still a conflict.
	if _, err = upgraded.act(json.RawMessage(`"changed-after"`), json.RawMessage(`"tickets"`), json.RawMessage(`"query"`), json.RawMessage(`{"ticket":"T-2"}`), c.Decision, c.Cites, actionKeysWho, json.RawMessage(`"`+marked+`"`)); err == nil || !strings.Contains(err.Error(), "action-key-conflict") {
		t.Fatalf("changed content under a pending key: %v", err)
	}
}

// actionKeysV0230Fingerprint is identity version 1 of actionKeysAct's request
// under key, written out by hand as v0.23.0 composed it: the canonical text of
// the request and both sources' command lines less argv[0], hashed under the
// action-intent domain.
func actionKeysV0230Fingerprint(t testing.TB, c actionKeysCall, key, ticket string) string {
	t.Helper()
	var decision struct{ RecordDigest, PackDigest string }
	var cites []struct{ Signature string }
	if json.Unmarshal(c.Decision, &decision) != nil || json.Unmarshal(c.Cites, &cites) != nil || len(cites) != 1 {
		t.Fatal("unexpected call")
	}
	source := `{"argv":["-test.run=^TestActionKeysTarget$"],"binding":"tickets@sha256:` + strings.Repeat("b", 64) + `","endpoint":"","sandbox":null,"transport":""}`
	recovery := actionKeysSources(t, t.TempDir(), "unused")["tickets/write"].actionRecovery["query"].digest()
	text := `{"arguments":{"request_id":"` + key + `","ticket":"` + ticket + `"},` +
		`"binding":"tickets@sha256:` + strings.Repeat("b", 64) + `",` +
		`"cites":[{"callIndex":0,"sessionId":"read","signature":"` + cites[0].Signature + `"}],` +
		`"decision":{"packDigest":"` + decision.PackDigest + `","recordDigest":"` + decision.RecordDigest + `"},` +
		`"platform":"tickets","readSource":` + source + `,"recovery":"` + recovery + `","tool":"query","writeSource":` + source + `}`
	sum := sha256.Sum256([]byte("judgment-pack-gateway/action-intent/1:" + text))
	return hex.EncodeToString(sum[:])
}

// writeV0230Intent puts a reservation as v0.23.0 wrote it: journal version 2,
// no identityVersion, the version 1 fingerprint.
func writeV0230Intent(t testing.TB, g *gatewayService, key, intent string) string {
	t.Helper()
	dir := filepath.Join(g.storeRoot, "actions", g.actionNamespace(actionKeysWho, key))
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(dir), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "intent.json")
	os.Remove(path)
	if err := os.WriteFile(path, []byte(intent), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// #355: keys v0.23.0 recorded keep answering. A reservation recorded under
// identity version 1 is held to the request's version 1 identity: the same
// content dispatches once, replays or reads back as before; other content is
// a conflict; an identity version this release does not read refuses.
func TestActionKeysRecordedByV0230StillAnswer(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	legacy := func(key, ticket string) string {
		return `{"journalVersion":"2","fingerprint":"` + actionKeysV0230Fingerprint(t, c, key, ticket) + `"}`
	}
	// The hand-written text is what this release computes as version 1.
	if key := strings.Repeat("0", 64); actionKeysIdentity(t, g.sources, c, key).previous != actionKeysV0230Fingerprint(t, c, key, "T-1") {
		t.Fatal("identity version 1 is not v0.23.0's")
	}

	// A completed action whose reservation v0.23.0 wrote: replayed.
	completed := strings.Repeat("1", 64)
	first, err := actionKeysAct(g, c, "completed", completed)
	if err != nil {
		t.Fatal(err)
	}
	writeV0230Intent(t, g, completed, legacy(completed, "T-1"))
	restarted := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
	again, err := actionKeysAct(restarted, c, "completed-again", completed)
	if err != nil {
		t.Fatalf("a completed v0.23.0 key was refused: %v", err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(again)
	if string(a) != string(b) || restarted.started.Load() != 0 || actionKeysSent(root, completed) != 1 {
		t.Fatal("a completed v0.23.0 key was not replayed")
	}

	// A reservation v0.23.0 made and never dispatched: dispatched once.
	reserved := strings.Repeat("2", 64)
	writeV0230Intent(t, g, reserved, legacy(reserved, "T-1"))
	if _, err = actionKeysAct(restarted, c, "reserved", reserved); err != nil {
		t.Fatalf("a v0.23.0 reservation was refused: %v", err)
	}
	if _, err = actionKeysAct(restarted, c, "reserved-again", reserved); err != nil {
		t.Fatal(err)
	}
	if actionKeysSent(root, reserved) != 1 {
		t.Fatal("a v0.23.0 reservation was not dispatched exactly once")
	}

	// A v0.23.0 reservation whose dispatch may have begun: read back, not sent.
	marked := strings.Repeat("3", 64)
	dir := writeV0230Intent(t, g, marked, legacy(marked, "T-1"))
	if err = os.WriteFile(filepath.Join(dir, "dispatch-1.json"), []byte(`{"attempt":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := actionKeysAct(restarted, c, "marked", marked)
	if err != nil || out["reconciliation"] == nil || actionKeysSent(root, marked) != 0 {
		t.Fatalf("a v0.23.0 key that may have dispatched was not read back without a send: %v", err)
	}

	// A v0.23.0 reservation of other content: a conflict, nothing sent.
	other := strings.Repeat("4", 64)
	writeV0230Intent(t, g, other, legacy(other, "T-2"))
	if _, err = actionKeysAct(restarted, c, "other", other); err == nil || !strings.Contains(err.Error(), "action-key-conflict") {
		t.Fatalf("a v0.23.0 reservation of other content: %v", err)
	}
	// Version 2's fingerprint recorded as version 1 is not the same content:
	// each version is held to its own identity.
	crossed := strings.Repeat("5", 64)
	writeV0230Intent(t, g, crossed, `{"journalVersion":"2","fingerprint":"`+actionKeysIdentity(t, restarted.sources, c, crossed).fingerprint+`"}`)
	if _, err = actionKeysAct(restarted, c, "crossed", crossed); err == nil || !strings.Contains(err.Error(), "action-key-conflict") {
		t.Fatalf("a version 2 fingerprint was read as version 1: %v", err)
	}
	// An identity version this release does not read.
	for i, version := range []string{`"1"`, `"3"`, `""`, `2`, `null`} {
		key := strings.Repeat(string("6789c"[i]), 64)
		writeV0230Intent(t, g, key, `{"journalVersion":"2","identityVersion":`+version+`,"fingerprint":"`+actionKeysIdentity(t, restarted.sources, c, key).fingerprint+`"}`)
		if _, err = actionKeysAct(restarted, c, "unread-"+key[:1], key); err == nil || !strings.Contains(err.Error(), "action-journal-invalid") {
			t.Fatalf("identity version %s: %v", version, err)
		}
	}
	for _, key := range []string{other, crossed} {
		if actionKeysSent(root, key) != 0 {
			t.Fatal("a refused key was sent")
		}
	}
	// A new reservation records identity version 2.
	fresh := strings.Repeat("f", 64)
	if _, err = actionKeysAct(restarted, c, "fresh", fresh); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(g.storeRoot, "actions", g.actionNamespace(actionKeysWho, fresh), "intent.json"))
	if err != nil || string(raw) != `{"journalVersion":"2","identityVersion":"2","fingerprint":"`+actionKeysIdentity(t, restarted.sources, c, fresh).fingerprint+`"}` {
		t.Fatalf("a new reservation: %s %v", raw, err)
	}
}

// #355: every approval a derived command line carries is a named field of the
// source's approval, read from the configuration and not from the command
// line: the server, the platform endpoint, the descriptor and owner
// declaration pins with what they approve, and the sandbox selector.
func TestDerivedSourcesCarryTheirApproval(t *testing.T) {
	workspace := t.TempDir()
	taxonomies := func(effect string) string {
		return `{"query":{"operation":"` + map[string]string{"act": "act", "read-external": "read"}[effect] + `","effect":"` + effect + `"}}`
	}
	operation := func(server, effect string) string {
		return `{"shape":"mcp","server":` + server + `,"tools":["query"],"toolTaxonomies":` + taxonomies(effect) + `,"licence":"fixture"}`
	}
	image := `{"image":"registry.example/tickets@sha256:` + strings.Repeat("a", 64) + `","args":["--read-only","--tenant=one"]}`
	remote := `{"url":"https://tickets.example/mcp","bearer":"token","headers":["X-Mode=read","X-Tenant=one"]}`
	command := `{"command":["/opt/server/bin/tickets","serve"],"workspace":"` + workspace + `"}`
	for name, text := range map[string]string{
		"image":   `{"bindingVersion":"2","platform":"tickets","operations":{"live":` + operation(image, "read-external") + `,"write":` + operation(image, "act") + `}}`,
		"remote":  `{"bindingVersion":"2","platform":"tickets","operations":{"live":` + operation(remote, "read-external") + `,"write":` + operation(remote, "act") + `}}`,
		"command": `{"bindingVersion":"2","customer":true,"platform":"tickets","operations":{"live":` + operation(command, "read-external") + `,"write":` + operation(command, "act") + `}}`,
	} {
		b, err := parseBinding([]byte(text))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		p := platformConfig{name: "tickets", binding: "tickets@sha256:" + strings.Repeat("b", 64), endpoint: "tickets.internal", write: true,
			credentials:          map[string]string{"live": "/run/secrets/live", "write": "/run/secrets/write"},
			operationDescriptors: map[string]string{"live": "sha256:" + strings.Repeat("c", 64), "write": "sha256:" + strings.Repeat("d", 64)}}
		cfg := engineConfig{runtime: "docker", configPath: "/etc/engine.json", platforms: []platformConfig{p}}
		for source, spec := range deriveSources(cfg, map[string]binding{"tickets": b}) {
			a := spec.approval
			if a == nil {
				t.Fatalf("%s %s: no approval", name, source)
			}
			// What the command line says, flag by flag.
			flags := map[string][]string{}
			var server []string
			own := true
			for _, word := range spec.argv[1:] {
				if word == "--" {
					own = false
					continue
				}
				if !own {
					server = append(server, word)
					continue
				}
				flag, value, _ := strings.Cut(word, "=")
				flags[flag] = append(flags[flag], value)
			}
			one := func(flag string) string { return strings.Join(flags[flag], "\x00") }
			for flag, field := range map[string]string{
				"--image": a.image, "--url": a.url, "--endpoint": a.platformEndpoint,
				"--descriptor-pin": a.descriptorPin, "--owner-declaration-pin": a.ownerDeclarationPin,
				"--approved-operation": a.approvedOperation, "--approved-platform": a.approvedPlatform, "--approved-binding": a.approvedBinding,
				"--sandbox-source": a.sandboxSource,
			} {
				if one(flag) != field {
					t.Errorf("%s %s: %s is %q on the command line and %q in the approval", name, source, flag, one(flag), field)
				}
			}
			if strings.Join(flags["--header"], "|") != strings.Join(a.headers, "|") {
				t.Errorf("%s %s: headers %q and %q", name, source, flags["--header"], a.headers)
			}
			if _, customer := flags["--customer-binding"]; customer != a.customer {
				t.Errorf("%s %s: customer %v and %v", name, source, customer, a.customer)
			}
			if strings.Join(server, "|") != strings.Join(append(append([]string(nil), a.serverArgs...), a.command...), "|") {
				t.Errorf("%s %s: server command line %q and %q, %q", name, source, server, a.serverArgs, a.command)
			}
			if a.descriptorPin == "" || a.ownerDeclarationPin == "" || (name == "command") != (a.sandboxSource != "") {
				t.Errorf("%s %s: the case does not exercise the approval: %+v", name, source, a)
			}
		}
	}
}
