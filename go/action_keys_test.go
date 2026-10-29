package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestActionKeysTarget is a subprocess target whose behaviour is read from a
// mode file, so a test changes what it does without changing the source's
// command line. Every write appends the request's key to the state file.
func TestActionKeysTarget(t *testing.T) {
	modeFile := os.Getenv("ACTION_KEYS_MODE")
	if modeFile == "" {
		return
	}
	raw, _ := os.ReadFile(modeFile)
	mode := strings.TrimSpace(string(raw))
	var request struct {
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		os.Exit(3)
	}
	state := os.Getenv("ACTION_KEYS_STATE")
	wanted, _ := request.Arguments["key"].(string)
	if mode != "read" {
		key, _ := request.Arguments["request_id"].(string)
		wanted = key
		switch mode {
		case "slow":
			time.Sleep(300 * time.Millisecond)
		case "rendezvous":
			// Both writes must be in flight at once: each waits for the other.
			dir := os.Getenv("ACTION_KEYS_RENDEZVOUS")
			if err := os.WriteFile(filepath.Join(dir, key), nil, 0600); err != nil {
				os.Exit(4)
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				entries, _ := os.ReadDir(dir)
				if len(entries) >= 2 {
					break
				}
				if time.Now().After(deadline) {
					os.Exit(8)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		f, err := os.OpenFile(state, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			os.Exit(5)
		}
		fmt.Fprintln(f, key)
		f.Sync()
		f.Close()
		if mode == "drop" {
			os.Exit(2)
		}
	}
	data, _ := os.ReadFile(state)
	found := ""
	for _, line := range strings.Split(string(data), "\n") {
		if line != "" && line == wanted {
			found = line
		}
	}
	fmt.Printf(`{"result":{"key":%q,"state":"done"},"acquisition":{"adapter":{"name":"fixture","version":"1","digest":"sha256:%s"},"endpoint":null,"statement":null,"snapshot":null,"peerIdentity":null,"schema":null,"upstreamToken":null,"observedAt":"2026-10-29T00:00:00Z"}}`, found, strings.Repeat("a", 64))
	os.Exit(0)
}

type actionKeysCall struct{ Decision, Cites json.RawMessage }

var actionKeysWho = &caller{issuer: "https://issuer.test", subject: "subject", tokenDigest: "sha256:" + strings.Repeat("c", 64)}

func actionKeysMode(t testing.TB, root, which, mode string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, which+"-mode"), []byte(mode), 0600); err != nil {
		t.Fatal(err)
	}
}

// actionKeysSources runs program as the write and read-back target, with the
// extra environment given.
func actionKeysSources(t testing.TB, root, program string, extraEnv ...string) map[string]sourceSpec {
	t.Helper()
	recoveryValue, _ := parseJSON([]byte(recoveryDeclaration))
	b := binding{write: &operation{tools: []string{"query", "sibling"}}, live: &operation{tools: []string{"query"}, taxonomies: map[string]ToolTaxonomy{"query": {Operation: "read", Effect: "read-external"}}}}
	recovery, err := parseActionRecovery(recoveryValue, b)
	if err != nil {
		t.Fatal(err)
	}
	source := func(which string) sourceSpec {
		env := append([]string{"ACTION_KEYS_MODE=" + filepath.Join(root, which+"-mode"), "ACTION_KEYS_STATE=" + filepath.Join(root, "target-state"), "ACTION_KEYS_RENDEZVOUS=" + filepath.Join(root, "rendezvous")}, extraEnv...)
		return sourceSpec{argv: []string{program, "-test.run=^TestActionKeysTarget$"}, env: env, shape: "mcp", tools: []string{"query"}, binding: "tickets@sha256:" + strings.Repeat("b", 64), actionRecovery: recovery}
	}
	return map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}, "tickets/write": source("write"), "tickets/live": source("live")}
}

func actionKeysService(t testing.TB, root string, sources map[string]sourceSpec) *gatewayService {
	t.Helper()
	g, err := newGatewayService(filepath.Join(root, "store"), testSeed, "gateway:test", filepath.Join(root, "registry.jsonl"), sources)
	if err != nil {
		t.Fatal(err)
	}
	g.decisionRecords = filepath.Join(root, "decisions")
	g.requireActionKey = true
	return g
}

// actionKeysPrepare makes the cited read and the decision record, and keeps
// the request members where a child process reads them.
func actionKeysPrepare(t testing.TB, g *gatewayService, root string) actionKeysCall {
	t.Helper()
	first, err := g.acquire("read", "screening", newObject(), actionKeysWho)
	if err != nil {
		t.Fatal(err)
	}
	signature := first["receipt"].(map[string]any)["signature"].(string)
	line := `{"kind":"evaluation","cites":[{"sessionId":"read","callIndex":0,"signature":"` + signature + `"}]}`
	if err = os.MkdirAll(g.decisionRecords, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(g.decisionRecords, "decision.json"), []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	c := actionKeysCall{
		Decision: json.RawMessage(`{"recordDigest":"` + digestOf(line) + `","packDigest":"sha256:` + strings.Repeat("d", 64) + `"}`),
		Cites:    json.RawMessage(`[{"sessionId":"read","callIndex":0,"signature":"` + signature + `"}]`),
	}
	raw, _ := json.Marshal(c)
	if err = os.WriteFile(filepath.Join(root, "call.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(root, "rendezvous"), 0700); err != nil {
		t.Fatal(err)
	}
	return c
}

func actionKeysAct(g *gatewayService, c actionKeysCall, session, key string) (map[string]any, error) {
	return g.act(json.RawMessage(`"`+session+`"`), json.RawMessage(`"tickets"`), json.RawMessage(`"query"`), json.RawMessage(`{"ticket":"T-1"}`), c.Decision, c.Cites, actionKeysWho, json.RawMessage(`"`+key+`"`))
}

func actionKeysSent(root, key string) int {
	data, _ := os.ReadFile(filepath.Join(root, "target-state"))
	return strings.Count(string(data), key+"\n")
}

func actionKeysSetup(t *testing.T) (string, *gatewayService, actionKeysCall) {
	t.Helper()
	if !actionJournalSupported {
		t.Skip("keyed dispatch fails closed on this host")
	}
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	actionKeysMode(t, root, "write", "respond")
	actionKeysMode(t, root, "live", "read")
	g := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
	return root, g, actionKeysPrepare(t, g, root)
}

// #351 M2: two keys never wait on each other. Each write waits until the
// other is in flight, so serialized keys fail at the target's deadline.
func TestDistinctActionKeysProceedConcurrently(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	actionKeysMode(t, root, "write", "rendezvous")
	var wg sync.WaitGroup
	for i, key := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64)} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := actionKeysAct(g, c, fmt.Sprintf("act-%d", i), key)
			if err != nil {
				t.Errorf("key %d: %v", i, err)
				return
			}
			receipt, answered := out["receipt"].(map[string]any)
			if !answered {
				t.Errorf("key %d was not answered by its write: %v", i, out)
				return
			}
			delivery := receipt["action"].(map[string]any)["delivery"].(map[string]any)
			if delivery["outcome"] != "response" {
				t.Errorf("key %d: %v", i, delivery)
			}
		}()
	}
	wg.Wait()
}

// TestActionKeysChild is one gateway process sending one keyed action.
func TestActionKeysChild(t *testing.T) {
	root := os.Getenv("ACTION_KEYS_CHILD_ROOT")
	if root == "" {
		return
	}
	if kill := os.Getenv("ACTION_KEYS_CHILD_KILL"); kill != "" {
		// Die while the named journal record is being made durable.
		syncActionFile = func(f *os.File) error {
			if filepath.Base(f.Name()) == kill {
				p, _ := os.FindProcess(os.Getpid())
				p.Kill()
				time.Sleep(time.Hour)
			}
			return f.Sync()
		}
	}
	if barrier := os.Getenv("ACTION_KEYS_CHILD_BARRIER"); barrier != "" {
		for {
			if _, err := os.Stat(barrier); err == nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
	}
	var c actionKeysCall
	raw, _ := os.ReadFile(filepath.Join(root, "call.json"))
	if err := json.Unmarshal(raw, &c); err != nil {
		os.Exit(1)
	}
	g := actionKeysService(t, root, actionKeysSources(t, root, os.Getenv("ACTION_KEYS_CHILD_PROGRAM")))
	_, err := actionKeysAct(g, c, os.Getenv("ACTION_KEYS_CHILD_SESSION"), os.Getenv("ACTION_KEYS_CHILD_KEY"))
	fmt.Println("CHILD:", err)
	os.Exit(0)
}

func actionKeysChild(root, session, key string, extra ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestActionKeysChild$")
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "ACTION_KEYS_") && !strings.HasPrefix(e, envSourceHelper+"=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, append([]string{"ACTION_KEYS_CHILD_ROOT=" + root, "ACTION_KEYS_CHILD_PROGRAM=" + os.Args[0], "ACTION_KEYS_CHILD_SESSION=" + session, "ACTION_KEYS_CHILD_KEY=" + key}, extra...)...)
	return cmd
}

// #351 M2: one key stays exclusive across processes. Gateway processes on
// one store send the same key at once; the target sees one write.
func TestOneActionKeyIsExclusiveAcrossProcesses(t *testing.T) {
	root, _, _ := actionKeysSetup(t)
	actionKeysMode(t, root, "write", "slow")
	for round := range 3 {
		key := fmt.Sprintf("%064x", round+1)
		barrier := filepath.Join(root, fmt.Sprintf("go-%d", round))
		var cmds []*exec.Cmd
		var outputs []*bytes.Buffer
		for i := range 4 {
			cmd := actionKeysChild(root, fmt.Sprintf("round-%d-%d", round, i), key, "ACTION_KEYS_CHILD_BARRIER="+barrier)
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			cmds, outputs = append(cmds, cmd), append(outputs, &out)
		}
		time.Sleep(300 * time.Millisecond)
		if err := os.WriteFile(barrier, nil, 0600); err != nil {
			t.Fatal(err)
		}
		for _, cmd := range cmds {
			cmd.Wait()
		}
		if sent := actionKeysSent(root, key); sent != 1 {
			for _, out := range outputs {
				t.Log(out.String())
			}
			t.Fatalf("round %d: the target received %d writes under one key", round, sent)
		}
	}
}

// #351 M2 and L1: a gateway killed in each window of a keyed action, then
// restarted and retried twice, never sends the write twice; a reservation
// killed before its dispatch marker sends it exactly once.
func TestActionKeyCrashWindowsNeverSendTwice(t *testing.T) {
	root, _, c := actionKeysSetup(t)
	for i, window := range []struct {
		kill, write string
		sent        int
	}{
		{"intent.json", "respond", 1},     // nothing dispatched: the retry takes the attempt over
		{"dispatch-1.json", "respond", 0}, // the marker may be durable: dispatch may have begun
		{"action.json", "respond", 1},     // the write answered; its record may be lost
		{"", "drop", 1},                   // the write committed and dropped its answer
	} {
		key := fmt.Sprintf("%064x", 100+i)
		actionKeysMode(t, root, "write", window.write)
		cmd := actionKeysChild(root, fmt.Sprintf("crash-%d", i), key, "ACTION_KEYS_CHILD_KILL="+window.kill)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		cmd.Run()
		actionKeysMode(t, root, "write", "respond")
		restarted := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
		for attempt := range 2 {
			actionKeysAct(restarted, c, fmt.Sprintf("retry-%d-%d", i, attempt), key)
		}
		if killed := !strings.Contains(out.String(), "CHILD:"); killed != (window.kill != "") {
			t.Fatalf("window %q: killed %v\n%s", window.kill, killed, out.String())
		}
		if sent := actionKeysSent(root, key); sent != window.sent {
			t.Fatalf("killed at %q: the target received %d writes, want %d\n%s", window.kill, sent, window.sent, out.String())
		}
	}
}

// #351 L1: a write program that was never started sent nothing. The journal
// answers the attempt, the key stays the request's, and the retry -- once the
// program is there -- dispatches it exactly once.
func TestActionNotDispatchedFreesTheKey(t *testing.T) {
	root, _, c := actionKeysSetup(t)
	key := strings.Repeat("9", 64)
	missing := filepath.Join(root, "not-installed", "adapter-mcp")
	g := actionKeysService(t, root, actionKeysSources(t, root, missing))
	_, err := actionKeysAct(g, c, "missing-program", key)
	if err == nil || !strings.Contains(err.Error(), "action-not-dispatched") {
		t.Fatalf("a start failure was not reported as not dispatched: %v", err)
	}
	var uncertain *actionUncertain
	if errors.As(err, &uncertain) {
		t.Fatal("a start failure was recorded as uncertain")
	}
	namespace := g.actionNamespace(actionKeysWho, key)
	for _, name := range []string{"dispatch-1.json", "not-dispatched-1.json"} {
		if _, err := os.Stat(filepath.Join(g.storeRoot, "actions", namespace, name)); err != nil {
			t.Fatalf("journal has no %s: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(g.storeRoot, "receipts", "missing-program", "0.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a write that was never sent was receipted")
	}
	installed := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
	first, err := actionKeysAct(installed, c, "installed", key)
	if err != nil {
		t.Fatal(err)
	}
	again, err := actionKeysAct(installed, c, "installed-again", key)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(again)
	if string(a) != string(b) || actionKeysSent(root, key) != 1 {
		t.Fatalf("the freed key was not dispatched exactly once and then replayed: %d", actionKeysSent(root, key))
	}
}

// #351 M1: moving the programs to another install directory and adding an
// environment variable leaves a completed action's key its own: the retry is
// answered with the retained response, and no target is called.
func TestActionRetryAfterAnInstallMoveReplays(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	key := strings.Repeat("8", 64)
	first, err := actionKeysAct(g, c, "before-upgrade", key)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(root, "gateway-2", "adapter-mcp")
	if err = os.MkdirAll(filepath.Dir(moved), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(os.Args[0], moved); err != nil {
		t.Fatal(err)
	}
	upgraded := actionKeysService(t, root, actionKeysSources(t, root, moved, "TZ=UTC"))
	again, err := actionKeysAct(upgraded, c, "after-upgrade", key)
	if err != nil {
		t.Fatalf("a retry after an install move was refused: %v", err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(again)
	if string(a) != string(b) || upgraded.started.Load() != 0 || actionKeysSent(root, key) != 1 {
		t.Fatal("the retained response was not replayed without a target call")
	}
}
