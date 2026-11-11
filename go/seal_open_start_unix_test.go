//go:build unix

package main

// The switch at a gateway's start (gateway #395; SPEC.md §3c), through the
// two serve commands' entry points, run in this process: off, a session an
// earlier process left open stays open, as it did before the switch; on, the
// start seals it after the interruption, under its registry lock and before
// it serves, names each session it cannot seal and serves, and does not
// start when a session cannot be read.

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// startCommands are the serve commands, each with the authority its files
// name and the switch turned on in its command line or its configuration.
var startCommands = []struct {
	name      string
	start     func(t *testing.T) ([]string, gatewayFiles)
	authority string
	on        func(t *testing.T, args []string) []string
}{
	{"serve", servedFiles, "gateway:test", func(t *testing.T, args []string) []string {
		return append(args, "--seal-open-at-start")
	}},
	{"serve --config", engineFiles, "gateway:rotation", func(t *testing.T, args []string) []string {
		config := readFile(t, args[1])
		raised := strings.Replace(strings.Replace(config, `"engineVersion":"6"`, `"engineVersion":"17"`, 1), `"platforms":{}}`, `"platforms":{},"sealOpenAtStart":true}`, 1)
		if raised == config || !strings.Contains(raised, `"sealOpenAtStart":true`) {
			t.Fatalf("the configuration was not raised: %s", config)
		}
		if err := os.WriteFile(args[1], []byte(raised), 0o600); err != nil {
			t.Fatal(err)
		}
		return args
	}},
}

// leaveOpen is an earlier process on a gateway's files, which acquired into
// each session named and sealed none: each holds receipts and no seal.
func leaveOpen(t *testing.T, f gatewayFiles, authority string, sessions ...string) {
	t.Helper()
	t.Setenv(envSourceHelper, "1")
	earlier, err := newGatewayService(f.store, testSeed, authority, f.registry,
		map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}})
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range sessions {
		for _, q := range []string{"x", "y"} {
			if _, err := earlier.acquire(session, "screening", vString(q), nil); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// startSealOf is the seal the start appended for session "left", read from
// the registry: the one line there, which must be the seal SPEC.md §3c
// gives, written by hand, at the time the line names.
func startSealOf(t *testing.T, f gatewayFiles) string {
	t.Helper()
	registry := readFile(t, f.registry)
	var line struct {
		SealedAt string `json:"sealedAt"`
	}
	if err := json.Unmarshal([]byte(registry), &line); err != nil || !witnessTimeForm.MatchString(line.SealedAt) {
		t.Fatalf("the registry holds no seal of the start's: %q (%v)", registry, err)
	}
	priv := ed25519.NewKeyFromSeed(testSeed)
	want := interruptionSealLineBy(priv, keyIDFor(publicOf(priv)), "left", 2, receiptSignature(t, f.store, "left", 1), line.SealedAt, "start")
	if registry != want+"\n" {
		t.Fatalf("the registry is\n%s\nnot\n%s", registry, want)
	}
	return want
}

// With the switch on, either serve command seals at its start each session
// left open whose receipts are whole, sealedVia start, says so on stderr as
// the registry line, names a session that is not whole, which stays open,
// and serves; the store then verifies but for that one.
func TestTheStartSealsWhatWasLeftOpenWithTheSwitchOn(t *testing.T) {
	for _, command := range startCommands {
		t.Run(command.name, func(t *testing.T) {
			args, f := command.start(t)
			leaveOpen(t, f, command.authority, "left", "torn")
			torn := filepath.Join(f.store, "receipts", "torn", "1.json")
			text := readFile(t, torn)
			if err := os.WriteFile(torn, []byte(text[:len(text)/2]), 0o600); err != nil {
				t.Fatal(err)
			}
			g := serveInProcess(t, command.on(t, args))
			if g.exited {
				t.Fatalf("the gateway did not start: exit %d: %s", g.code, g.stderr())
			}
			g.stop()
			want := startSealOf(t, f)
			out := g.stderr()
			if !strings.Contains(out, "start: sealed after an interruption: "+want+"\n") ||
				!strings.Contains(out, "start: session torn is not whole, so it is not sealed: file 1.json malformed; gateway verify reports what it finds of it, and nothing is changed or deleted\n") {
				t.Fatalf("stderr: %s", out)
			}
			if readFile(t, torn) != text[:len(text)/2] {
				t.Fatal("the start changed a receipt it could not seal")
			}
			rep, err := verifyWithRegistry(f.store, f.registry, command.authority, publicOf(ed25519.NewKeyFromSeed(testSeed)))
			if err != nil {
				t.Fatal(err)
			}
			if got := interruptedLines(rep); strings.Join(got, " ") != "left/1/sealed-after-interruption" {
				t.Fatalf("observations: %v", rep.Observations)
			}
		})
	}
}

// With the switch off -- the default -- the start seals nothing: the
// session left open stays so, and the store's verdict is what it was.
func TestTheStartLeavesWhatWasLeftOpenWithTheSwitchOff(t *testing.T) {
	for _, command := range startCommands {
		t.Run(command.name, func(t *testing.T) {
			args, f := command.start(t)
			leaveOpen(t, f, command.authority, "left")
			g := serveInProcess(t, args)
			if g.exited {
				t.Fatalf("the gateway did not start: exit %d: %s", g.code, g.stderr())
			}
			g.stop()
			if registry := readFile(t, f.registry); registry != "" {
				t.Fatalf("the start wrote %q", registry)
			}
			if strings.Contains(g.stderr(), "sealed after an interruption") {
				t.Fatalf("stderr: %s", g.stderr())
			}
			rep, err := verifyWithRegistry(f.store, f.registry, command.authority, publicOf(ed25519.NewKeyFromSeed(testSeed)))
			if err != nil {
				t.Fatal(err)
			}
			findings, _ := verdictLines(t, rep)
			if rep.OK || !strings.Contains(strings.Join(findings, " "), "left/<nil>/unregistered-session") {
				t.Fatalf("verdict: %v %v", rep.OK, findings)
			}
		})
	}
}

// With the switch on, a session that cannot be read is no answer to what
// was left open: the gateway does not start, and nothing is sealed, the
// whole session beside it among them.
func TestTheStartDoesNotServeWhenASessionCannotBeRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a directory's mode does not keep the superuser out")
	}
	for _, command := range startCommands {
		t.Run(command.name, func(t *testing.T) {
			args, f := command.start(t)
			leaveOpen(t, f, command.authority, "left")
			locked := filepath.Join(f.store, "receipts", "locked")
			if err := os.Mkdir(locked, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(locked, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(locked, 0o755) })
			g := serveInProcess(t, command.on(t, args))
			if !g.exited {
				g.stop()
				t.Fatal("the gateway started")
			}
			want := "start: sealing the sessions left open: session locked could not be read, and nothing was sealed: open " + locked + ": permission denied; the gateway does not start\n"
			if g.code != 1 || !strings.Contains(g.stderr(), want) {
				t.Fatalf("exit %d: %s", g.code, g.stderr())
			}
			if registry := readFile(t, f.registry); registry != "" {
				t.Fatalf("the start wrote %q", registry)
			}
		})
	}
}
