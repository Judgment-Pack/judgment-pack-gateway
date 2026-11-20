package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stoppedPastTheAppend is what sealAppendedHook panics with to stand in for
// a process that ends just past a seal's append.
type stoppedPastTheAppend struct{}

// stopPastTheAppend runs run with the process stopped once a seal is
// appended, and holds that it was.
func stopPastTheAppend(t *testing.T, run func()) {
	t.Helper()
	saved := sealAppendedHook
	t.Cleanup(func() { sealAppendedHook = saved })
	sealAppendedHook = func(string) { panic(stoppedPastTheAppend{}) }
	stopped := func() (stopped bool) {
		defer func() {
			if r := recover(); r != nil {
				if _, ours := r.(stoppedPastTheAppend); !ours {
					panic(r)
				}
				stopped = true
			}
		}()
		run()
		return false
	}()
	sealAppendedHook = saved
	if !stopped {
		t.Fatal("the process was not stopped past a seal's append")
	}
}

// startDelivers holds that the next start delivers the session's seal
// alone, and that no marker outlives the acknowledgment.
func startDelivers(t *testing.T, sink *standInSink, service *gatewayService, sinkURL, session string) {
	t.Helper()
	if !strings.Contains(readFile(t, service.regPath), `"sessionId":"`+session+`"`) {
		t.Fatalf("the seal of %s is not in the registry", session)
	}
	before, _ := sink.snapshot()
	var stderr bytes.Buffer
	if err := sealsAtStart(restartForwarding(t, service, sinkURL), &stderr, fixedStamp("2026-11-19T00:00:01Z"), false); err != nil || stderr.Len() != 0 {
		t.Fatalf("the start: %v\n%s", err, stderr.String())
	}
	seals, n := sealsSince(t, sink, len(before))
	if n != 1 || len(seals) != 1 || seals[0] != registrySealDigest(t, readFile(t, service.regPath), session) {
		t.Fatalf("the start sent %d deliveries, seals %v; want the seal of %s, which its marker names", n, seals, session)
	}
	if pending := markedPending(t, fsSealForwarding{service.storeRoot}); len(pending) != 0 {
		t.Fatalf("the marker outlived the acknowledgment: %v", pending)
	}
}

// The seal's marker is in the store before the seal is appended: a /seal
// whose process ends just past the append leaves the marker, and the next
// start delivers the seal (#558).
func TestASealStoppedPastItsAppendIsDeliveredByTheNextStart(t *testing.T) {
	sink, service, server, sinkURL := sealSinkService(t)
	acquireOK(t, server, "sl-p", "p0")
	stopPastTheAppend(t, func() { _, _ = service.sealSession("sl-p") })
	server.Close()
	startDelivers(t, sink, service, sinkURL, "sl-p")
}

// So too for gateway seal-open --config: a seal it appends and does not
// get to deliver, its process ended past the append, is delivered by the
// next start (#558).
func TestASealOpenStoppedPastItsAppendIsDeliveredByTheNextStart(t *testing.T) {
	sink, service, server, sinkURL := sealSinkService(t)
	acquireOK(t, server, "sl-q", "q0")
	server.Close()
	dir := t.TempDir()
	config := filepath.Join(dir, "engine.json")
	text := fmt.Sprintf(`{"engineVersion":%q,"authority":"gateway:test","seed":%q,"store":%q,"registry":%q,"decisionRecords":%q,"listen":"127.0.0.1:8787","catalog":%q,"receiptSink":{"url":%q,"seals":true},"platforms":{}}`,
		sealSinkVersion, writeSeedFile(t, dir, testSeed), service.storeRoot, service.regPath, filepath.Join(dir, "decisions"), filepath.Join(dir, "catalog"), sinkURL)
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	stopPastTheAppend(t, func() {
		var stdout, stderr bytes.Buffer
		cmdSealOpenAt([]string{"--config", config, "--session", "sl-q"}, &stdout, &stderr, nowStamp)
	})
	startDelivers(t, sink, service, sinkURL, "sl-q")
}
