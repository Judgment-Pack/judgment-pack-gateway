package main

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// gateway remove-scope, run as the command, on a scoped action: refused,
// naming the key and removing nothing, while the key is pending; and once
// none is, the scope's journal goes with its sessions.
func TestActScopeRemoveScopeCommand(t *testing.T) {
	seed := writeSeedFile(t, t.TempDir(), testSeed)
	seal := func(t *testing.T, h *actScopeHarness, sessions ...string) {
		for _, s := range sessions {
			if code, out := authed(t, h.server, "/seal", `{"session":"`+s+`"}`, h.tokenB); code != http.StatusOK {
				t.Fatalf("seal %s: %d %v", s, code, out)
			}
		}
	}
	t.Run("a pending key", func(t *testing.T) {
		h := actScopeSetup(t)
		actionKeysMode(t, h.root, "write", "drop")
		actionKeysMode(t, h.root, "live", "drop")
		key := strings.Repeat("9", 64)
		if code, out := authed(t, h.server, "/act", h.body("act-s", "tickets-b", scopeB, key, h.decisionB, h.cite("b-read", h.scopedSig)), h.tokenB); code != http.StatusConflict {
			t.Fatalf("an uncertain action whose read-back fails: %d %v", code, out)
		}
		seal(t, h, "b-read", "act-s")
		before := journalFiles(t, h.g.storeRoot)
		code, stdout, stderr := removeScopeOn(t, h.g, seed, "--scope", callerScopeB, "--by", "operator")
		if code != 1 || stdout != "" || !strings.Contains(stderr, "key "+key) || !strings.Contains(stderr, "nothing was removed") {
			t.Fatalf("remove-scope with a pending key: %d %q %q", code, stdout, stderr)
		}
		if journalFiles(t, h.g.storeRoot) != before {
			t.Fatal("the refused removal changed the journal")
		}
		if sessions, err := listSessions(h.g.storeRoot); err != nil || !contains(sessions, "act-s") {
			t.Fatalf("the refused removal took the session: %v %v", sessions, err)
		}
	})
	t.Run("nothing pending", func(t *testing.T) {
		h := actScopeSetup(t)
		if code, out := authed(t, h.server, "/act", h.body("act-b", "tickets-b", scopeB, strings.Repeat("a", 64), h.decisionB, h.cite("b-read", h.scopedSig)), h.tokenB); code != http.StatusOK {
			t.Fatalf("the scoped action: %d %v", code, out)
		}
		seal(t, h, "b-read", "act-b")
		code, _, stderr := removeScopeOn(t, h.g, seed, "--scope", callerScopeB, "--by", "operator")
		if code != 0 || !strings.Contains(stderr, "removed the scope identifier's action journal") {
			t.Fatalf("remove-scope: %d %q", code, stderr)
		}
		if _, err := os.Lstat(scopedActionJournalPath(h.g.storeRoot, callerScopeB)); !os.IsNotExist(err) {
			t.Fatalf("the scope's journal is still there: %v", err)
		}
		// a journal left with no session, as a run stopped after the sessions
		// leaves it: the second run removes it and says nothing else was
		if err := os.MkdirAll(scopedActionJournalPath(h.g.storeRoot, callerScopeB), 0o700); err != nil {
			t.Fatal(err)
		}
		code, _, stderr = removeScopeOn(t, h.g, seed, "--scope", callerScopeB, "--by", "operator")
		if code != 0 || !strings.Contains(stderr, "removed the scope identifier's action journal\n") ||
			!strings.Contains(stderr, "no session of the scope identifier is in the store; nothing else was removed\n") || strings.Contains(stderr, "; nothing was removed") {
			t.Fatalf("the second run: %d %q", code, stderr)
		}
		if _, err := os.Lstat(scopedActionJournalPath(h.g.storeRoot, callerScopeB)); !os.IsNotExist(err) {
			t.Fatalf("the left journal is still there: %v", err)
		}
	})
}

// parseEngineConfig holds a scoped write platform to its load checks
// (ADR-0054, decision 1): callerScopes checked, and a decisionRecords of its
// own, apart from the gateway's and from another scope's.
func TestActScopeConfigurationLoadChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a scoped write needs durable keyed actions, which this platform does not have (action_journal.go), and these cases name POSIX paths")
	}
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	keys, apart := abs(t, t.TempDir(), "keys.json"), t.TempDir()
	platform := func(name, scope, dir string) string {
		return platformJSONFor(t, name, ref, "engine-"+name, `,"write":true,"scope":"`+scope+`","decisionRecords":"`+dir+`"`, "history", "live", "write")
	}
	gatewayDir := regexp.MustCompile(`"decisionRecords":"([^"]*)"`)
	config := func(callers string, platforms ...string) []byte {
		identity := `,"identity":{"issuer":"https://login.example","audience":"gateway:acme","keys":"` + keys + `","callerScopes":` + callers + `}`
		text := strings.Replace(engineJSON(t, catalog, identity, strings.Join(platforms, ",")), `"engineVersion":"1"`, `"engineVersion":"`+actScopeVersion+`"`, 1)
		gateway := gatewayDir.FindStringSubmatch(text)[1]
		return []byte(strings.ReplaceAll(strings.ReplaceAll(text, "@GATEWAY@", gateway), "@ABOVE@", filepath.Dir(gateway)))
	}
	checked := `{"s-1":["` + callerScopeB + `"],"s-2":["` + callerScopeA + `"]}`
	if _, err := parseEngineConfig(config(checked, platform("tickets-b", callerScopeB, abs(t, apart, "b")))); err != nil {
		t.Fatalf("a scoped write with its own directory: %v", err)
	}
	for _, c := range []struct {
		name, callers string
		platforms     []string
		want          string
	}{
		{"unchecked caller scopes", `"unchecked"`, []string{platform("tickets-b", callerScopeB, abs(t, apart, "b"))}, "needs identity.callerScopes as an object"},
		{"the gateway's directory", checked, []string{platform("tickets-b", callerScopeB, "@GATEWAY@")}, "is the gateway's decisionRecords, or beneath or above it"},
		{"beneath the gateway's", checked, []string{platform("tickets-b", callerScopeB, "@GATEWAY@/b")}, "is the gateway's decisionRecords, or beneath or above it"},
		{"above the gateway's", checked, []string{platform("tickets-b", callerScopeB, "@ABOVE@")}, "is the gateway's decisionRecords, or beneath or above it"},
		{"another scope's directory", checked, []string{platform("tickets-b", callerScopeB, abs(t, apart, "x")), platform("tickets-a", callerScopeA, abs(t, apart, "x"))}, "are fixed to different scope identifiers"},
		{"beneath another scope's", checked, []string{platform("tickets-b", callerScopeB, abs(t, apart, "x")), platform("tickets-a", callerScopeA, abs(t, apart, "x", "a"))}, "are fixed to different scope identifiers"},
	} {
		if _, err := parseEngineConfig(config(c.callers, c.platforms...)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}
