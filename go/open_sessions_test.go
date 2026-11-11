package main

// A session an earlier process left open (gateway #381): what a restart
// does with it, what the store has to hold for a session to be taken up,
// and what verification says of it.

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The refusals as an answer carries them, byte for byte.
const (
	leftOpenAnswer = `{"error":"session left was left open by an earlier process: the store holds receipts in it that this process did not mint, and no seal closes it; its chain is not continued from an empty memory, nor is it sealed from a count on disk, so acquire into a new session (gateway verify reports this one unregistered-session, and observes it session-open while its receipts are whole)"}`
	leftOpenText   = "session %s was left open by an earlier process: the store holds receipts in it that this process did not mint, and no seal closes it; its chain is not continued from an empty memory, nor is it sealed from a count on disk, so acquire into a new session (gateway verify reports this one unregistered-session, and observes it session-open while its receipts are whole)"
	notADirText    = "session %s is in the store as something other than a session directory, which this process did not make; nothing is taken up there"
	unreadText     = "session %s could not be read in the store, so whether an earlier process left receipts in it is not known; it is refused rather than taken for empty"
)

// sessionEntries is what the store holds under a session: each entry by
// name, a file as its bytes and anything else as its kind. A refusal leaves
// it as it was.
func sessionEntries(t *testing.T, storeRoot, session string) map[string]string {
	t.Helper()
	path := filepath.Join(storeRoot, "receipts", session)
	held := map[string]string{}
	entries, err := os.ReadDir(path)
	if err != nil {
		info, lerr := os.Lstat(path)
		if lerr != nil {
			if errors.Is(lerr, os.ErrNotExist) {
				return held
			}
			t.Fatal(lerr)
		}
		held["."] = info.Mode().Type().String()
		return held
	}
	for _, e := range entries {
		if e.Type().IsRegular() {
			held[e.Name()] = readFile(t, filepath.Join(path, e.Name()))
		} else {
			held[e.Name()] = e.Type().String()
		}
	}
	return held
}

func sameEntries(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for name, held := range a {
		if other, ok := b[name]; !ok || other != held {
			return false
		}
	}
	return true
}

func checkVerdict(t *testing.T, g *gatewayService, when string, findings, open []string) {
	t.Helper()
	rep, err := verifyWithRegistry(g.storeRoot, g.regPath, "gateway:test", g.publicKey)
	if err != nil {
		t.Fatalf("%s: no verdict: %v", when, err)
	}
	sort.Strings(findings)
	gotFindings, gotOpen := verdictLines(t, rep)
	if rep.OK || strings.Join(gotFindings, " ") != strings.Join(findings, " ") || strings.Join(gotOpen, " ") != strings.Join(open, " ") {
		t.Fatalf("%s: ok=%v findings %v open %v, want ok=false findings %v open %v", when, rep.OK, gotFindings, gotOpen, findings, open)
	}
}

// A gateway that stops leaves the sessions it had not sealed open in the
// store. The one that starts next takes none of them up: an acquisition
// into one is refused before its source runs, and so is a seal, each with
// the same words, and nothing in the store or the registry changes -- not
// even when the session's last receipt has been taken away between the
// stop and the start, which a seal of the count found there would sign
// over. Verification reads the session unregistered-session while it is
// open and after, and observes it session-open on its last receipt; a
// sealed session is observed nothing. A session new to both processes is
// served as ever.
func TestARestartTakesUpNoSessionAnEarlierProcessLeftOpen(t *testing.T) {
	earlier, earlierServer := testService(t)
	for _, body := range []string{
		`{"session":"left","source":"screening","arguments":{"q":"x"}}`,
		`{"session":"left","source":"screening","arguments":{"q":"y"}}`,
		`{"session":"closed","source":"screening","arguments":{"q":"x"}}`,
	} {
		if code, out := post(t, earlierServer, "/acquire", body); code != http.StatusOK {
			t.Fatalf("acquire %s: %d %v", body, code, out)
		}
	}
	if code, out := post(t, earlierServer, "/seal", `{"session":"closed"}`); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, out)
	}
	// while its gateway runs: open, whole, observed so -- over HTTP too
	before := []string{"closed/0/ok", "left/0/ok", "left/1/ok", "left/<nil>/unregistered-session"}
	checkVerdict(t, earlier, "while the session is open", before, []string{"left/1/session-open"})
	resp, err := http.Get(earlierServer.URL + "/verify")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	const answer = `{"findings":[{"callIndex":0,"sessionId":"closed","status":"ok"},{"callIndex":0,"sessionId":"left","status":"ok"},{"callIndex":1,"sessionId":"left","status":"ok"},{"sessionId":"left","status":"unregistered-session"}],"observations":[{"callIndex":1,"observation":"session-open","sessionId":"left"}],"ok":false}`
	if resp.StatusCode != http.StatusOK || string(raw) != answer {
		t.Fatalf("/verify while the session is open: %d %s", resp.StatusCode, raw)
	}

	earlierServer.Close()
	restarted, err := newGatewayService(earlier.storeRoot, testSeed, "gateway:test", earlier.regPath, earlier.sources)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(restarted.handler())
	t.Cleanup(server.Close)
	started := filepath.Join(t.TempDir(), "source-started")
	t.Setenv(envSourceReady, started)
	refusedEach := func(when string) {
		t.Helper()
		held := sessionEntries(t, earlier.storeRoot, "left")
		registry := readFile(t, earlier.regPath)
		for _, call := range []struct{ path, body string }{
			{"/acquire", `{"session":"left","source":"screening","arguments":{"q":"z"}}`},
			{"/seal", `{"session":"left"}`},
		} {
			code, raw := postRawWith(t, server, call.path, call.body, "")
			if code != http.StatusBadRequest || string(raw) != leftOpenAnswer {
				t.Fatalf("%s: %s: %d %s", when, call.path, code, raw)
			}
		}
		if _, err := os.Stat(started); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: the source ran for a session an earlier process left open (%v)", when, err)
		}
		if restarted.started.Load() != 0 {
			t.Fatalf("%s: %d sources started", when, restarted.started.Load())
		}
		restarted.mu.Lock()
		_, entered := restarted.sessions["left"]
		restarted.mu.Unlock()
		if entered {
			t.Fatalf("%s: the refused session entered the new process's map", when)
		}
		if !sameEntries(held, sessionEntries(t, earlier.storeRoot, "left")) {
			t.Fatalf("%s: the refusals changed what the store holds in the session", when)
		}
		if readFile(t, earlier.regPath) != registry {
			t.Fatalf("%s: the refusals changed the registry", when)
		}
	}
	refusedEach("after the restart")
	checkVerdict(t, restarted, "after the refusals", before, []string{"left/1/session-open"})

	// the last receipt taken away between the stop and the start: the
	// session reads as whole and shorter, which is why no seal is made of
	// the count on disk
	if err := os.Remove(filepath.Join(earlier.storeRoot, "receipts", "left", "1.json")); err != nil {
		t.Fatal(err)
	}
	refusedEach("after a rollback")
	checkVerdict(t, restarted, "after a rollback", []string{"closed/0/ok", "left/0/ok", "left/<nil>/unregistered-session"}, []string{"left/0/session-open"})

	// a session new to both processes is served, and sealed
	if code, out := post(t, server, "/acquire", `{"session":"fresh","source":"screening","arguments":{"q":"x"}}`); code != http.StatusOK {
		t.Fatalf("a new session after the restart: %d %v", code, out)
	}
	if _, err := os.Stat(started); err != nil {
		t.Fatalf("the source of a new session did not run: %v", err)
	}
	if code, out := post(t, server, "/seal", `{"session":"fresh"}`); code != http.StatusOK {
		t.Fatalf("sealing a new session after the restart: %d %v", code, out)
	}
	checkVerdict(t, restarted, "with a new session sealed", []string{"closed/0/ok", "fresh/0/ok", "left/0/ok", "left/<nil>/unregistered-session"}, []string{"left/0/session-open"})
}

// What the store holds where a session this process does not hold would be
// decides whether it is taken up. Nothing, an empty directory, a staging
// file an interrupted write left and an entry that is no receipt are taken
// up: the read runs and mints receipt 0. Any entry named as a receipt is
// refused before the source runs -- a whole receipt, a torn one, an empty
// one, one at another index, a directory so named, and one among far more
// entries than the directory is read in at once, which the listing's
// order, the filesystem's, all but always puts past the first read -- and
// so is an entry of another kind where the directory would be. A refused session's seal is refused in the same
// words, and the store is left as it was; a directory holding no receipt
// that no read has taken up is no session to seal.
func TestWhatTheStoreHoldsInASessionDecidesWhetherItIsTakenUp(t *testing.T) {
	service, _ := testService(t)
	if _, err := service.acquire("minted", "screening", vString("x"), nil); err != nil {
		t.Fatal(err)
	}
	receipt := readFile(t, filepath.Join(service.storeRoot, "receipts", "minted", "0.json"))
	mkdir := func(t *testing.T, path string) {
		t.Helper()
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(t *testing.T, path, text string) {
		t.Helper()
		mkdir(t, filepath.Dir(path))
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for i, tc := range []struct {
		name    string
		stand   func(t *testing.T, dir string)
		refusal string
	}{
		{"nothing there", func(t *testing.T, dir string) {}, ""},
		{"an empty directory", func(t *testing.T, dir string) { mkdir(t, dir) }, ""},
		{"a staging file an interrupted write left", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "0.json.4242.0a1b2c3d4e5f.tmp"), receipt[:len(receipt)/2])
		}, ""},
		{"an entry that is no receipt", func(t *testing.T, dir string) { write(t, filepath.Join(dir, "notes.txt"), "x") }, ""},
		{"a whole receipt", func(t *testing.T, dir string) { write(t, filepath.Join(dir, "0.json"), receipt) }, leftOpenText},
		{"a torn receipt", func(t *testing.T, dir string) { write(t, filepath.Join(dir, "0.json"), receipt[:len(receipt)/2]) }, leftOpenText},
		{"a whole receipt and a torn last one", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "0.json"), receipt)
			write(t, filepath.Join(dir, "1.json"), receipt[:len(receipt)/2])
		}, leftOpenText},
		{"a receipt at another index", func(t *testing.T, dir string) { write(t, filepath.Join(dir, "7.json"), receipt) }, leftOpenText},
		{"an empty file named as a receipt", func(t *testing.T, dir string) { write(t, filepath.Join(dir, "0.json"), "") }, leftOpenText},
		{"a directory named as a receipt", func(t *testing.T, dir string) { mkdir(t, filepath.Join(dir, "0.json")) }, leftOpenText},
		{"a receipt among more entries than one batch", func(t *testing.T, dir string) {
			for n := 0; n < 2000; n++ {
				write(t, filepath.Join(dir, fmt.Sprintf("0.json.%d.000000000000.tmp", n)), "")
			}
			write(t, filepath.Join(dir, "0.json"), receipt)
		}, leftOpenText},
		{"a file where the directory would be", func(t *testing.T, dir string) { write(t, dir, receipt) }, notADirText},
	} {
		session := fmt.Sprintf("case-%d", i)
		dir := filepath.Join(service.storeRoot, "receipts", session)
		tc.stand(t, dir)
		held := sessionEntries(t, service.storeRoot, session)
		started := filepath.Join(t.TempDir(), "source-started")
		t.Setenv(envSourceReady, started)
		before := service.started.Load()
		if tc.refusal == "" && tc.name != "nothing there" {
			// taken up by a read, not by a seal: a directory no read has
			// taken up holds no session this process can seal
			if _, err := service.sealSession(session); err == nil || err.Error() != "no such session: "+session {
				t.Fatalf("%s: seal before a read: %v", tc.name, err)
			}
		}
		_, err := service.acquire(session, "screening", vString("x"), nil)
		if tc.refusal == "" {
			if err != nil {
				t.Fatalf("%s: not taken up: %v", tc.name, err)
			}
			if _, err := os.Stat(filepath.Join(dir, "0.json")); err != nil {
				t.Fatalf("%s: no receipt 0 minted: %v", tc.name, err)
			}
			continue
		}
		want := fmt.Sprintf(tc.refusal, session)
		if err == nil || err.Error() != want || !errors.As(err, new(badRequest)) {
			t.Fatalf("%s: %v, want %q", tc.name, err, want)
		}
		if _, err := service.sealSession(session); err == nil || err.Error() != want || !errors.As(err, new(badRequest)) {
			t.Fatalf("%s: seal: %v, want %q", tc.name, err, want)
		}
		if _, err := os.Stat(started); !errors.Is(err, os.ErrNotExist) || service.started.Load() != before {
			t.Fatalf("%s: the source ran (%v)", tc.name, err)
		}
		service.mu.Lock()
		_, entered := service.sessions[session]
		service.mu.Unlock()
		if entered {
			t.Fatalf("%s: the refused session entered the map", tc.name)
		}
		if !sameEntries(held, sessionEntries(t, service.storeRoot, session)) {
			t.Fatalf("%s: the refusal changed what the store holds", tc.name)
		}
	}
	// a session this process minted into is its own whatever the store
	// holds: it is continued and sealed
	if _, err := service.acquire("minted", "screening", vString("y"), nil); err != nil {
		t.Fatalf("a session this process holds: %v", err)
	}
	if _, err := service.sealSession("minted"); err != nil {
		t.Fatalf("sealing a session this process holds: %v", err)
	}
}

// A seal an earlier process wrote is named for what it is, before the store
// is looked at: a sealed session holds receipts too, and is never said to
// be left open.
func TestASessionSealedBeforeARestartIsNotSaidToBeLeftOpen(t *testing.T) {
	earlier, _ := testService(t)
	if _, err := earlier.acquire("done", "screening", vString("x"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := earlier.sealSession("done"); err != nil {
		t.Fatal(err)
	}
	restarted, err := newGatewayService(earlier.storeRoot, testSeed, "gateway:test", earlier.regPath, earlier.sources)
	if err != nil {
		t.Fatal(err)
	}
	registry := readFile(t, earlier.regPath)
	if _, err := restarted.sealSession("done"); err == nil || err.Error() != "session is sealed in the registry: done" || !errors.As(err, new(badRequest)) {
		t.Fatalf("sealing a session sealed before the restart: %v", err)
	}
	if readFile(t, earlier.regPath) != registry {
		t.Fatal("a refused seal changed the registry")
	}
}

// The engine's delegated form (SPEC.md §11): a call under a delegation into
// a session an earlier process on the same store left open is refused as
// the operator's own is, before anything the delegation admits -- no
// custody asked, the issuing host neither read nor counted, no program
// run -- and the same call into a new session is served.
func TestADelegatedAcquisitionIntoASessionLeftOpenIsRefusedFirst(t *testing.T) {
	h := newDelegationHarness(t, false)
	reads := h.countReads(t)
	cred := h.credential(t, statement(t, nil))
	earlier := actionKeysService(t, h.root, h.g.sources)
	if _, err := earlier.acquire("before", "screening", newObject(), actionKeysWho); err != nil {
		t.Fatal(err)
	}
	held := sessionEntries(t, h.g.storeRoot, "before")
	hostReads, counted, custody := h.host.readCount(), h.host.counted(), len(grantCalls(t, h.root))
	status, raw := h.presentRaw(t, "/acquire", h.acquireBody("before", "query"), cred)
	const want = `{"error":"session before was left open by an earlier process: the store holds receipts in it that this process did not mint, and no seal closes it; its chain is not continued from an empty memory, nor is it sealed from a count on disk, so acquire into a new session (gateway verify reports this one unregistered-session, and observes it session-open while its receipts are whole)"}`
	if status != http.StatusBadRequest || raw != want {
		t.Fatalf("a delegated acquisition into a session left open: %d %s", status, raw)
	}
	if reads() != 0 || h.host.readCount() != hostReads || h.host.counted() != counted || len(grantCalls(t, h.root)) != custody {
		t.Fatalf("refused, and still: reads %d, host reads %d->%d, counted %d->%d, custody %d->%d", reads(), hostReads, h.host.readCount(), counted, h.host.counted(), custody, len(grantCalls(t, h.root)))
	}
	if !sameEntries(held, sessionEntries(t, h.g.storeRoot, "before")) {
		t.Fatal("the refusal changed what the store holds in the session")
	}
	if status, raw := h.presentRaw(t, "/acquire", h.acquireBody("after", "query"), cred); status != http.StatusOK || reads() != 1 || h.host.counted() != counted+1 {
		t.Fatalf("a delegated acquisition into a new session: %d %s, reads %d, counted %d", status, raw, reads(), h.host.counted())
	}
}
