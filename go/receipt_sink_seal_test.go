package main

// A receipt the sink has not acknowledged is held beyond the process that
// minted it (ADR-0049): a session left open is not sealed, at the start or by
// gateway seal-open, until each receipt the store holds of it is delivered
// and acknowledged; /act does not run past a receipt a session holds; and a
// delivery in flight is waited for only so long.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// refuseAcknowledgments is the sink answering another digest: a receipt
// kept, and not acknowledged.
func refuseAcknowledgments(_ int, _ string, w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, `{"acknowledged":"sha256:`+strings.Repeat("0", 64)+`"}`)
}

// A session an earlier process left open, one of whose receipts the sink
// never acknowledged, is not sealed by the start, and is named; the
// session whose receipts it all acknowledged is not either while the sink
// is down, for it is not asked after the first refusal. Once the sink
// acknowledges, the start delivers each stored receipt, oldest first, the
// payload carried where it is configured, and seals both.
func TestTheStartDeliversTheStoredReceiptsBeforeItSealsASession(t *testing.T) {
	sink, sinkServer := newStandInSink(t)
	service, server, root := sinkService(t, sinkServer.URL, true)
	for _, body := range []string{
		`{"session":"fw-a","source":"kept","arguments":{"q":"a0"}}`,
		`{"session":"fw-z","source":"kept","arguments":{"q":"z0"}}`,
	} {
		if code, got := post(t, server, "/acquire", body); code != http.StatusOK {
			t.Fatalf("%s: %d %v", body, code, got)
		}
	}
	sink.setAnswer(refuseAcknowledgments)
	code, body := post(t, server, "/acquire", `{"session":"fw-a","source":"kept","arguments":{"q":"a1"}}`)
	refusedUnforwarded(t, "the held receipt", code, body)
	// the process that held it is gone: a new one on the same store
	server.Close()
	restart := func() *gatewayService {
		t.Helper()
		again, err := newGatewayService(service.storeRoot, testSeed, "gateway:test", service.regPath, service.sources)
		if err != nil {
			t.Fatal(err)
		}
		again.forwarder = newReceiptForwarder(&receiptSinkSpec{url: sinkServer.URL, payload: true})
		again.forwarder.attemptTimeout = 300 * time.Millisecond
		again.forwarder.backoff = []time.Duration{time.Millisecond, time.Millisecond}
		return again
	}
	registryBefore := readFile(t, service.regPath)
	var stderr bytes.Buffer
	if err := sealOpenAtStart(restart(), &stderr, fixedStamp("2026-11-10T00:00:01Z")); err != nil {
		t.Fatalf("the start: %v", err)
	}
	if readFile(t, service.regPath) != registryBefore || strings.Contains(stderr.String(), "sealed after an interruption") {
		t.Fatalf("the start sealed past an unacknowledged receipt:\n%s", stderr.String())
	}
	want := "start: session fw-a is not sealed: " + (receiptNotForwarded{}).Error() + "; it is left open\n"
	if !strings.Contains(stderr.String(), want) {
		t.Fatalf("the session is not named with the fixed sentence:\n%s", stderr.String())
	}
	if n := receiptsHeld(t, root, "fw-a"); n != 2 {
		t.Fatalf("the store holds %d receipts of fw-a", n)
	}

	sink.setAnswer(nil)
	before, _ := sink.snapshot()
	stderr.Reset()
	if err := sealOpenAtStart(restart(), &stderr, fixedStamp("2026-11-10T00:00:02Z")); err != nil {
		t.Fatalf("the start: %v", err)
	}
	if strings.Count(stderr.String(), "start: sealed after an interruption: ") != 2 {
		t.Fatalf("the start did not seal both sessions:\n%s", stderr.String())
	}
	got, order := sink.snapshot()
	if len(order) != 3 {
		t.Fatalf("the sink kept %d receipts; want 3", len(order))
	}
	// fw-a's two receipts in index order, the payload carried, then fw-z's
	// one, which the sink had acknowledged and acknowledges again
	var indexes []float64
	for _, each := range got[len(before):] {
		d, members := readDelivery(t, each)
		if _, present := members["payload"]; !present {
			t.Fatalf("a stored receipt was delivered without its payload: %s", each)
		}
		indexes = append(indexes, d.Receipt["callIndex"].(float64))
	}
	if len(indexes) != 3 || indexes[0] != 0 || indexes[1] != 1 || indexes[2] != 0 {
		t.Fatalf("the stored receipts were delivered in the order %v", indexes)
	}
}

// A delivery already in flight for a session is waited for under the
// context and for at most one attempt's deadline: a request behind it is
// refused with the fixed sentence at that deadline, or when its context
// ends, and does not wait out the delivery's own retries.
func TestARequestBehindADeliveryInFlightIsRefusedAtTheDeadline(t *testing.T) {
	f := &receiptForwarder{attemptTimeout: 100 * time.Millisecond}
	q := newForwardQueue()
	q.add(heldReceipt{index: 0, body: []byte("{}"), digest: "sha256:" + strings.Repeat("0", 64)})
	q.send <- struct{}{} // a delivery in flight
	start := time.Now()
	if err := f.deliver(context.Background(), q, 0); err != (receiptNotForwarded{}) {
		t.Fatalf("behind a delivery in flight: %v", err)
	}
	if waited := time.Since(start); waited < 90*time.Millisecond || waited > 2*time.Second {
		t.Fatalf("waited %s for a delivery in flight; the bound is one attempt's deadline", waited)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	if err := f.deliver(ctx, q, 0); err != (receiptNotForwarded{}) || time.Since(start) > 50*time.Millisecond {
		t.Fatalf("with its context ended: %v after %s", err, time.Since(start))
	}
	if !q.unacknowledged() {
		t.Fatal("a refused wait dropped the held receipt")
	}
}

// /act does not run past a receipt its session holds: it delivers again
// first, and while the sink does not acknowledge, it is refused with the
// fixed sentence and the executor is not started; once the sink
// acknowledges, the action runs.
func TestActDeliversWhatTheSessionHoldsBeforeItRuns(t *testing.T) {
	sink, sinkServer := newStandInSink(t)
	service, server := testService(t)
	service.forwarder = newReceiptForwarder(&receiptSinkSpec{url: sinkServer.URL})
	service.forwarder.attemptTimeout = 300 * time.Millisecond
	service.forwarder.backoff = []time.Duration{time.Millisecond, time.Millisecond}
	started := filepath.Join(t.TempDir(), "argv")
	t.Setenv(envSourceArgv, started)
	env, _ := goodEnvelope()
	t.Setenv(envSourceEnvelope, envelopeText(t, env))
	image := "--image=x@sha256:" + strings.Repeat("0", 64)
	remote := sourceSpec{argv: []string{os.Args[0], image, "--tools=wit_work_item_comment_write", "--endpoint=h"}, env: helperEnv,
		tools: []string{"wit_work_item_comment_write"}, shape: "mcp", endpoint: "h"}
	service.sources["boards/write"] = remote
	service.decisionRecords = t.TempDir()
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	code, first := authed(t, server, "/acquire", `{"session":"act-h","source":"screening","arguments":{"q":"example"}}`, token)
	if code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, first)
	}
	sink.setAnswer(refuseAcknowledgments)
	code, held := authed(t, server, "/acquire", `{"session":"act-h","source":"screening","arguments":{"q":"second"}}`, token)
	refusedUnforwarded(t, "the receipt held", code, held)
	signature := first["receipt"].(map[string]any)["signature"].(string)
	line := `{"kind":"evaluation","cites":[{"sessionId":"act-h","callIndex":0,"signature":"` + signature + `"}]}`
	if err := os.WriteFile(filepath.Join(service.decisionRecords, "evaluations.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	act := `{"session":"act-h","platform":"boards","tool":"wit_work_item_comment_write","arguments":{"action":"add","workItemId":42,"text":"approved"},` +
		`"decision":{"recordDigest":"sha256:` + hexOf([]byte(line)) + `","packDigest":"sha256:` + strings.Repeat("b", 64) + `"},` +
		`"cites":[{"sessionId":"act-h","callIndex":0,"signature":"` + signature + `"}]}`
	// the acquisitions' own sources wrote the file too: only the executor's
	// start counts from here
	_ = os.Remove(started)
	code, body := authed(t, server, "/act", act, token)
	refusedUnforwarded(t, "/act past a held receipt", code, body)
	if _, err := os.Stat(started); err == nil {
		t.Fatal("the executor was started past a held receipt")
	}
	sink.setAnswer(nil)
	if code, body := authed(t, server, "/act", act, token); code != http.StatusOK {
		t.Fatalf("/act once the sink acknowledges: %d %v", code, body)
	}
}

// On the PostgreSQL kind, the command first delivers each receipt the kind
// holds of a session an instance left open, and seals it only once they are
// all acknowledged.
func TestThePostgresSealOpenDeliversTheStoredReceiptsBeforeSealing(t *testing.T) {
	sink, sinkServer := newStandInSink(t)
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, _ := sealOpenPgConfig(t, db, dir, "engine.json", false, "")
	text := strings.Replace(readFile(t, config), `"engineVersion":"24"`, `"engineVersion":"35","receiptSink":{"url":"`+sinkServer.URL+`"}`, 1)
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseEngineConfig([]byte(text))
	if err != nil || cfg.receiptSink == nil {
		t.Fatalf("the configuration: %v", err)
	}
	var said bytes.Buffer
	first, err := startEngineOnKind(cfg, testSeed, sealOpenPgSources(t), nil, &said)
	if err != nil {
		t.Fatalf("the start: %v", err)
	}
	server := httptest.NewServer(first.service.handler())
	if code, got := post(t, server, "/acquire", `{"session":"pg-s","source":"plain","arguments":{"q":"a"}}`); code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, got)
	}
	sink.setAnswer(refuseAcknowledgments)
	code, held := post(t, server, "/acquire", `{"session":"pg-s","source":"plain","arguments":{"q":"b"}}`)
	refusedUnforwarded(t, "the receipt held", code, held)
	server.Close()
	first.stop(&said)

	registry := func() string {
		data, err := db.open(t, nil).registry().readLog(0)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	before := registry()
	var stdout, stderr bytes.Buffer
	if code := cmdSealOpenAt([]string{"--config", config, "--all"}, &stdout, &stderr, nowStamp); code != 1 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), "seal-open: session pg-s is not sealed: "+(receiptNotForwarded{}).Error()+"; it is left open\n") {
		t.Fatalf("seal-open with the sink refusing: %d %q %q", code, stdout.String(), stderr.String())
	}
	if registry() != before {
		t.Fatal("seal-open sealed past an unacknowledged receipt")
	}
	sink.setAnswer(nil)
	stdout.Reset()
	stderr.Reset()
	if code := cmdSealOpenAt([]string{"--config", config, "--all"}, &stdout, &stderr, nowStamp); code != 0 || stderr.Len() != 0 ||
		!strings.Contains(stdout.String(), `"sessionId":"pg-s"`) {
		t.Fatalf("seal-open with the sink acknowledging: %d %q %q", code, stdout.String(), stderr.String())
	}
	got, order := sink.snapshot()
	if len(order) != 2 {
		t.Fatalf("the sink kept %d receipts; want 2", len(order))
	}
	if d, _ := readDelivery(t, got[len(got)-1]); d.ReceiptDigest != order[1] {
		t.Fatalf("the last delivery is not receipt 1's")
	}
}

// actionLeftOpen is a session an earlier process left open holding an
// acquisition receipt, index 0, which the sink acknowledged, and the action
// receipt /act stored after it in the same chain, index 1; with the gateway,
// the sink, and the sink's address.
func actionLeftOpen(t *testing.T) (*gatewayService, *standInSink, string) {
	t.Helper()
	sink, sinkServer := newStandInSink(t)
	service, server := testService(t)
	service.forwarder = newReceiptForwarder(&receiptSinkSpec{url: sinkServer.URL})
	service.forwarder.attemptTimeout = 300 * time.Millisecond
	service.forwarder.backoff = []time.Duration{time.Millisecond, time.Millisecond}
	t.Setenv(envSourceArgv, filepath.Join(t.TempDir(), "argv"))
	env, _ := goodEnvelope()
	t.Setenv(envSourceEnvelope, envelopeText(t, env))
	image := "--image=x@sha256:" + strings.Repeat("0", 64)
	service.sources["boards/write"] = sourceSpec{argv: []string{os.Args[0], image, "--tools=wit_work_item_comment_write", "--endpoint=h"}, env: helperEnv,
		tools: []string{"wit_work_item_comment_write"}, shape: "mcp", endpoint: "h"}
	service.decisionRecords = t.TempDir()
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	code, first := authed(t, server, "/acquire", `{"session":"act-k","source":"screening","arguments":{"q":"example"}}`, token)
	if code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, first)
	}
	signature := first["receipt"].(map[string]any)["signature"].(string)
	line := `{"kind":"evaluation","cites":[{"sessionId":"act-k","callIndex":0,"signature":"` + signature + `"}]}`
	if err := os.WriteFile(filepath.Join(service.decisionRecords, "evaluations.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	act := `{"session":"act-k","platform":"boards","tool":"wit_work_item_comment_write","arguments":{"action":"add","workItemId":42,"text":"approved"},` +
		`"decision":{"recordDigest":"sha256:` + hexOf([]byte(line)) + `","packDigest":"sha256:` + strings.Repeat("b", 64) + `"},` +
		`"cites":[{"sessionId":"act-k","callIndex":0,"signature":"` + signature + `"}]}`
	if code, body := authed(t, server, "/act", act, token); code != http.StatusOK {
		t.Fatalf("/act: %d %v", code, body)
	}
	server.Close()
	if n := receiptsHeld(t, filepath.Dir(service.storeRoot), "act-k"); n != 2 {
		t.Fatalf("the store holds %d receipts of act-k; want the acquisition and the action", n)
	}
	// from here the sink refuses an action receipt, as a sink taking
	// deliveryVersion 1 may: it takes acquisition receipts alone
	sink.setAnswer(func(n int, digest string, w http.ResponseWriter, r *http.Request) {
		got, _ := sink.snapshot()
		if d, _ := readDelivery(t, got[n]); d.Receipt["kind"] != "acquisition" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		_, _ = io.WriteString(w, `{"acknowledged":"`+digest+`"}`)
	})
	return service, sink, sinkServer.URL
}

// deliveredSince is the kind of each delivery the sink was sent after the
// first n.
func deliveredSince(t *testing.T, sink *standInSink, n int) []string {
	t.Helper()
	got, _ := sink.snapshot()
	var kinds []string
	for _, each := range got[n:] {
		d, _ := readDelivery(t, each)
		kind, _ := d.Receipt["kind"].(string)
		kinds = append(kinds, kind)
	}
	return kinds
}

// The start delivers again the acquisition receipts of a session left open,
// and not the action receipt /act stored in the same chain: a sink that
// refuses that kind does not hold the session open, and the start seals it.
func TestTheStartRedeliversAcquisitionReceiptsAloneAndSeals(t *testing.T) {
	service, sink, sinkURL := actionLeftOpen(t)
	again, err := newGatewayService(service.storeRoot, testSeed, "gateway:test", service.regPath, service.sources)
	if err != nil {
		t.Fatal(err)
	}
	again.forwarder = newReceiptForwarder(&receiptSinkSpec{url: sinkURL})
	again.forwarder.attemptTimeout = 300 * time.Millisecond
	again.forwarder.backoff = []time.Duration{time.Millisecond, time.Millisecond}
	before, _ := sink.snapshot()
	var stderr bytes.Buffer
	if err := sealOpenAtStart(again, &stderr, fixedStamp("2026-11-10T00:00:01Z")); err != nil {
		t.Fatalf("the start: %v", err)
	}
	if kinds := deliveredSince(t, sink, len(before)); len(kinds) != 1 || kinds[0] != "acquisition" {
		t.Fatalf("the start delivered %v; want the acquisition alone", kinds)
	}
	if strings.Count(stderr.String(), "start: sealed after an interruption: ") != 1 || strings.Contains(stderr.String(), "is not sealed") {
		t.Fatalf("the start did not seal the session:\n%s", stderr.String())
	}
}

// gateway seal-open --config does as the start does: the acquisition
// receipts alone are delivered again, and the session is sealed.
func TestSealOpenByTheConfigurationRedeliversAcquisitionReceiptsAlone(t *testing.T) {
	service, sink, sinkURL := actionLeftOpen(t)
	dir := t.TempDir()
	seedPath := writeSeedFile(t, dir, testSeed)
	config := filepath.Join(dir, "engine.json")
	body := fmt.Sprintf(`{"engineVersion":"35","authority":"gateway:test","seed":%q,"store":%q,"registry":%q,"decisionRecords":%q,"listen":"127.0.0.1:8787","catalog":%q,"receiptSink":{"url":%q},"platforms":{}}`,
		seedPath, service.storeRoot, service.regPath, filepath.Join(dir, "decisions"), filepath.Join(dir, "catalog"), sinkURL)
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := sink.snapshot()
	var stdout, stderr bytes.Buffer
	if code := cmdSealOpenAt([]string{"--config", config, "--all"}, &stdout, &stderr, nowStamp); code != 0 ||
		!strings.Contains(stdout.String(), `"sessionId":"act-k"`) || strings.Contains(stderr.String(), "is not sealed") {
		t.Fatalf("seal-open: %d %q %q", code, stdout.String(), stderr.String())
	}
	if kinds := deliveredSince(t, sink, len(before)); len(kinds) != 1 || kinds[0] != "acquisition" {
		t.Fatalf("seal-open delivered %v; want the acquisition alone", kinds)
	}
}
