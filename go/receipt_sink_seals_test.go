package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sealSinkService is sinkService with seals forwarded (receiptSink.seals),
// with the sink and its address.
func sealSinkService(t *testing.T) (*standInSink, *gatewayService, *httptest.Server, string) {
	t.Helper()
	sink, sinkServer := newStandInSink(t)
	service, server, _ := sinkService(t, sinkServer.URL, false)
	service.forwarder.seals = true
	return sink, service, server, sinkServer.URL
}

// refusedSealUnforwarded holds an answer to the seal's fixed refusal: 503,
// the code receipts are refused with, the seal's sentence, and nothing of
// the seal.
func refusedSealUnforwarded(t *testing.T, what string, code int, body map[string]any) {
	t.Helper()
	if code != http.StatusServiceUnavailable || len(body) != 2 ||
		body["error"] != (sealNotForwarded{}).Error() || body["code"] != receiptNotForwardedCode {
		t.Fatalf("%s: not the seal's fixed refusal: %d %v", what, code, body)
	}
}

// acquireOK is an acquisition the sink acknowledged.
func acquireOK(t *testing.T, server *httptest.Server, session, q string) {
	t.Helper()
	body := fmt.Sprintf(`{"session":%q,"source":"kept","arguments":{"q":%q}}`, session, q)
	if code, got := post(t, server, "/acquire", body); code != http.StatusOK {
		t.Fatalf("%s: %d %v", body, code, got)
	}
}

// markedPending is the sessions the store marks as holding a seal pending
// forwarding.
func markedPending(t *testing.T, marks sealForwarding) []string {
	t.Helper()
	pending, err := marks.pending()
	if err != nil {
		t.Fatal(err)
	}
	return pending
}

// registrySealDigest is the digest of the session's line in the registry:
// SHA-256 over the line without its line feed.
func registrySealDigest(t *testing.T, registry, session string) string {
	t.Helper()
	for _, line := range strings.Split(registry, "\n") {
		if strings.Contains(line, `"sessionId":"`+session+`"`) {
			sum := sha256.Sum256([]byte(line))
			return "sha256:" + hex.EncodeToString(sum[:])
		}
	}
	t.Fatalf("the registry holds no seal of %s", session)
	return ""
}

// sealsSince is the seal deliveries the sink was sent from the n-th on, by
// their digests, and how many deliveries there were.
func sealsSince(t *testing.T, sink *standInSink, n int) ([]string, int) {
	t.Helper()
	got, _ := sink.snapshot()
	var seals []string
	for _, each := range got[n:] {
		if d, members := readDelivery(t, each); d.DeliveryVersion == sealDeliveryVersion {
			if len(members) != 3 || d.Seal == nil || d.ReceiptDigest != "" {
				t.Fatalf("a seal's delivery is not {deliveryVersion, seal, sealDigest}: %s", each)
			}
			seals = append(seals, d.SealDigest)
		}
	}
	return seals, len(got) - n
}

// A seal the sink does not acknowledge is refused with the seal's sentence
// and held: it is in the registry, and marked in the store, and /seal asked
// again delivers it again. Once the sink acknowledges it, /seal answers it,
// once, the marker is removed, and the store verifies as it did with the
// marker there: no verifier reads it.
func TestASealIsHeldUntilTheSinkAcknowledgesIt(t *testing.T) {
	sink, service, server, _ := sealSinkService(t)
	acquireOK(t, server, "sl-a", "a0")
	acquireOK(t, server, "sl-a", "a1")
	sink.setAnswer(refuseAcknowledgments)
	code, body := post(t, server, "/seal", `{"session":"sl-a"}`)
	refusedSealUnforwarded(t, "the seal held", code, body)
	if !strings.Contains(readFile(t, service.regPath), `"sessionId":"sl-a"`) {
		t.Fatal("the seal is not in the registry")
	}
	marks := fsSealForwarding{service.storeRoot}
	if pending := markedPending(t, marks); len(pending) != 1 || pending[0] != "sl-a" {
		t.Fatalf("the seal is not marked pending: %v", pending)
	}
	verdict := func() string {
		t.Helper()
		rep, err := service.verifyReport()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := rep.marshal()
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	withMarker := verdict()
	code, body = post(t, server, "/seal", `{"session":"sl-a"}`)
	refusedSealUnforwarded(t, "the seal asked again", code, body)

	sink.setAnswer(nil)
	code, sealed := post(t, server, "/seal", `{"session":"sl-a"}`)
	if code != http.StatusOK || sealed["sessionId"] != "sl-a" || sealed["finalCount"] != float64(2) {
		t.Fatalf("the seal once acknowledged: %d %v", code, sealed)
	}
	_, order := sink.snapshot()
	if len(order) != 3 || order[2] != digestOfAnswered(t, sealed) || order[2] != registrySealDigest(t, readFile(t, service.regPath), "sl-a") {
		t.Fatalf("the sink kept %v; want the two receipts, then the seal answered", order)
	}
	if pending := markedPending(t, marks); len(pending) != 0 {
		t.Fatalf("the marker outlived the acknowledgment: %v", pending)
	}
	if verdict() != withMarker {
		t.Fatal("the marker changed the store's verdict")
	}
	if code, again := post(t, server, "/seal", `{"session":"sl-a"}`); code != http.StatusBadRequest {
		t.Fatalf("a seal answered, asked again: %d %v", code, again)
	}
	if pending := markedPending(t, marks); len(pending) != 0 {
		t.Fatalf("a seal of a sealed session left a marker: %v", pending)
	}
}

// The sink is sent a session's held receipts first, then its seal: while a
// receipt is held the seal is refused with the receipt's sentence, and
// nothing is sealed or marked; once the sink acknowledges, the held receipt
// is delivered by the seal before the seal is appended, and the seal after
// it, in its own form.
func TestTheSinkIsSentTheSessionsReceiptsBeforeItsSeal(t *testing.T) {
	sink, service, server, _ := sealSinkService(t)
	acquireOK(t, server, "sl-b", "b0")
	sink.setAnswer(refuseAcknowledgments)
	code, body := post(t, server, "/acquire", `{"session":"sl-b","source":"kept","arguments":{"q":"b1"}}`)
	refusedUnforwarded(t, "the receipt held", code, body)
	code, body = post(t, server, "/seal", `{"session":"sl-b"}`)
	refusedUnforwarded(t, "the seal behind a held receipt", code, body)
	if strings.Contains(readFile(t, service.regPath), `"sessionId":"sl-b"`) || len(markedPending(t, fsSealForwarding{service.storeRoot})) != 0 {
		t.Fatal("a seal was appended, or marked, behind a held receipt")
	}
	sink.setAnswer(nil)
	before, _ := sink.snapshot()
	code, sealed := post(t, server, "/seal", `{"session":"sl-b"}`)
	if code != http.StatusOK {
		t.Fatalf("the seal: %d %v", code, sealed)
	}
	got, _ := sink.snapshot()
	since := got[len(before):]
	if len(since) != 2 {
		t.Fatalf("the seal sent %d deliveries; want the held receipt, then the seal", len(since))
	}
	first, _ := readDelivery(t, since[0])
	second, _ := readDelivery(t, since[1])
	if first.DeliveryVersion != receiptDeliveryVersion || first.Receipt["callIndex"] != float64(1) {
		t.Fatalf("the first delivery is not the held receipt: %s", since[0])
	}
	if second.DeliveryVersion != sealDeliveryVersion || second.SealDigest != digestOfAnswered(t, sealed) || second.Seal["finalCount"] != float64(2) {
		t.Fatalf("the second delivery is not the seal answered: %s", since[1])
	}
}

// Without receiptSink.seals -- every sink of engine version 35 -- no seal is
// sent and no marker is made. seals is a member of sealSinkVersion, refused
// by name under an earlier version, off unless it is true.
func TestAVersion35SinkIsNeverSentASeal(t *testing.T) {
	sink, sinkServer := newStandInSink(t)
	service, server, _ := sinkService(t, sinkServer.URL, false)
	acquireOK(t, server, "sl-v", "v0")
	if code, sealed := post(t, server, "/seal", `{"session":"sl-v"}`); code != http.StatusOK {
		t.Fatalf("the seal: %d %v", code, sealed)
	}
	if seals, n := sealsSince(t, sink, 0); len(seals) != 0 || n != 1 {
		t.Fatalf("a sink without seals was sent %d deliveries, %d seals", n, len(seals))
	}
	if _, err := os.Lstat(filepath.Join(service.storeRoot, sealForwardingDir)); !os.IsNotExist(err) {
		t.Fatalf("a marker's directory was made: %v", err)
	}

	if !engineVersions[sealSinkVersion] || !versionAtLeast(sealSinkVersion, "36") || versionAtLeast(receiptSinkVersion, sealSinkVersion) {
		t.Fatalf("seals is a member of a version after receiptSink's: %q", sealSinkVersion)
	}
	catalog := t.TempDir()
	with := func(version, member string) string {
		return atVersion(t, version, catalog, `,"receiptSink":`+member, ``)
	}
	_, err := parseEngineConfig([]byte(with(receiptSinkVersion, `{"url":"https://sink.example/r","seals":true}`)))
	if want := fmt.Sprintf("receiptSink: seals is a version-%s member; engineVersion %s has no seals", sealSinkVersion, receiptSinkVersion); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("seals under version %s: %v", receiptSinkVersion, err)
	}
	for member, want := range map[string]bool{
		`{"url":"https://sink.example/r","seals":true}`:  true,
		`{"url":"https://sink.example/r","seals":false}`: false,
		`{"url":"https://sink.example/r"}`:               false,
	} {
		cfg, err := parseEngineConfig([]byte(with(sealSinkVersion, member)))
		if err != nil || cfg.receiptSink.seals != want || newReceiptForwarder(cfg.receiptSink).seals != want {
			t.Fatalf("%s: %v", member, err)
		}
	}
	if _, err := parseEngineConfig([]byte(with(sealSinkVersion, `{"url":"https://sink.example/r","seals":"yes"}`))); err == nil {
		t.Fatal("seals that is not true or false was read")
	}
}

// restartForwarding is a new process on service's store, forwarding seals
// to sinkURL: the one that held a seal is gone, past the seal's append and
// before its acknowledgment.
func restartForwarding(t *testing.T, service *gatewayService, sinkURL string) *gatewayService {
	t.Helper()
	again, err := newGatewayService(service.storeRoot, testSeed, "gateway:test", service.regPath, service.sources)
	if err != nil {
		t.Fatal(err)
	}
	again.forwarder = newReceiptForwarder(&receiptSinkSpec{url: sinkURL, seals: true})
	again.forwarder.attemptTimeout = 300 * time.Millisecond
	again.forwarder.backoff = []time.Duration{time.Millisecond, time.Millisecond}
	return again
}

// A seal appended and not acknowledged when its process ends is delivered
// by the next start before it serves, with the seal-open switch off. While
// the sink refuses, the start names it and the marker stays; once the sink
// acknowledges, the marker is removed, and the start after sends nothing.
func TestTheStartDeliversASealPendingForwarding(t *testing.T) {
	sink, service, server, sinkURL := sealSinkService(t)
	acquireOK(t, server, "sl-c", "c0")
	sink.setAnswer(refuseAcknowledgments)
	code, body := post(t, server, "/seal", `{"session":"sl-c"}`)
	refusedSealUnforwarded(t, "the seal held", code, body)
	server.Close()
	marks := fsSealForwarding{service.storeRoot}

	var stderr bytes.Buffer
	if err := sealsAtStart(restartForwarding(t, service, sinkURL), &stderr, fixedStamp("2026-11-19T00:00:01Z"), false); err != nil {
		t.Fatalf("the start: %v", err)
	}
	if stderr.String() != "start: "+sealHeldRefusal("sl-c")+"\n" {
		t.Fatalf("the start did not name the seal held:\n%s", stderr.String())
	}
	if pending := markedPending(t, marks); len(pending) != 1 {
		t.Fatalf("the marker did not stay: %v", pending)
	}

	sink.setAnswer(nil)
	before, _ := sink.snapshot()
	stderr.Reset()
	if err := sealsAtStart(restartForwarding(t, service, sinkURL), &stderr, fixedStamp("2026-11-19T00:00:02Z"), false); err != nil || stderr.Len() != 0 {
		t.Fatalf("the start: %v\n%s", err, stderr.String())
	}
	seals, n := sealsSince(t, sink, len(before))
	if n != 1 || len(seals) != 1 || seals[0] != registrySealDigest(t, readFile(t, service.regPath), "sl-c") {
		t.Fatalf("the start sent %d deliveries, seals %v; want the seal alone", n, seals)
	}
	if pending := markedPending(t, marks); len(pending) != 0 {
		t.Fatalf("the marker outlived the acknowledgment: %v", pending)
	}
	after, _ := sink.snapshot()
	if err := sealsAtStart(restartForwarding(t, service, sinkURL), &stderr, fixedStamp("2026-11-19T00:00:03Z"), false); err != nil {
		t.Fatal(err)
	}
	if _, n := sealsSince(t, sink, len(after)); n != 0 {
		t.Fatalf("a start with nothing pending sent %d deliveries", n)
	}
}

// gateway seal-open --config delivers a seal pending forwarding before it
// seals, and holds the seal it makes after an interruption as /seal holds
// its own: appended, named while the sink does not acknowledge it, and
// delivered by the next seal-open.
func TestSealOpenByTheConfigurationDeliversASealPendingForwarding(t *testing.T) {
	sink, service, server, sinkURL := sealSinkService(t)
	acquireOK(t, server, "sl-d", "d0")
	acquireOK(t, server, "sl-e", "e0")
	_, receipts := sink.snapshot()
	sink.setAnswer(refuseAcknowledgments)
	code, body := post(t, server, "/seal", `{"session":"sl-d"}`)
	refusedSealUnforwarded(t, "the seal held", code, body)
	server.Close()
	dir := t.TempDir()
	config := filepath.Join(dir, "engine.json")
	text := fmt.Sprintf(`{"engineVersion":%q,"authority":"gateway:test","seed":%q,"store":%q,"registry":%q,"decisionRecords":%q,"listen":"127.0.0.1:8787","catalog":%q,"receiptSink":{"url":%q,"seals":true},"platforms":{}}`,
		sealSinkVersion, writeSeedFile(t, dir, testSeed), service.storeRoot, service.regPath, filepath.Join(dir, "decisions"), filepath.Join(dir, "catalog"), sinkURL)
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	// the receipts and sl-d's seal acknowledged, and no other seal: sl-d's
	// pending seal is delivered first, and sl-e, left open, is sealed and
	// its seal held
	acknowledged := map[string]bool{registrySealDigest(t, readFile(t, service.regPath), "sl-d"): true}
	for _, digest := range receipts {
		acknowledged[digest] = true
	}
	start, _ := sink.snapshot()
	sink.setAnswer(func(n int, digest string, w http.ResponseWriter, r *http.Request) {
		if acknowledged[digest] {
			fmt.Fprintf(w, `{"acknowledged":%q}`, digest)
			return
		}
		refuseAcknowledgments(n, digest, w, r)
	})
	var stdout, stderr bytes.Buffer
	if code := cmdSealOpenAt([]string{"--config", config, "--all"}, &stdout, &stderr, nowStamp); code != 1 ||
		!strings.Contains(stdout.String(), `"sessionId":"sl-e"`) ||
		stderr.String() != "seal-open: "+sealHeldRefusal("sl-e")+"\n" {
		t.Fatalf("seal-open with sl-e's seal refused: %d %q %q", code, stdout.String(), stderr.String())
	}
	if seals, _ := sealsSince(t, sink, len(start)); len(seals) < 2 || seals[0] != registrySealDigest(t, readFile(t, service.regPath), "sl-d") {
		t.Fatalf("the pending seal was not delivered first: %v", seals)
	}
	marks := fsSealForwarding{service.storeRoot}
	if pending := markedPending(t, marks); len(pending) != 1 || pending[0] != "sl-e" {
		t.Fatalf("sl-e's seal alone is not marked: %v", pending)
	}

	sink.setAnswer(nil)
	before, _ := sink.snapshot()
	stdout.Reset()
	stderr.Reset()
	if code := cmdSealOpenAt([]string{"--config", config, "--all"}, &stdout, &stderr, nowStamp); code != 0 || stdout.Len() != 0 {
		t.Fatalf("seal-open with the sink acknowledging: %d %q %q", code, stdout.String(), stderr.String())
	}
	seals, n := sealsSince(t, sink, len(before))
	if n != 1 || len(seals) != 1 || seals[0] != registrySealDigest(t, readFile(t, service.regPath), "sl-e") {
		t.Fatalf("seal-open sent %d deliveries, seals %v; want sl-e's held seal alone", n, seals)
	}
	if pending := markedPending(t, marks); len(pending) != 0 {
		t.Fatalf("the markers outlived the acknowledgments: %v", pending)
	}
}

// On the PostgreSQL kind a seal held is marked among the documents of no
// scope, and the next start delivers it before it serves, and removes the
// marker.
func TestAPostgresSealHeldIsDeliveredByTheNextStart(t *testing.T) {
	sink, sinkServer := newStandInSink(t)
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, _ := sealOpenPgConfig(t, db, dir, "engine.json", false, "")
	text := strings.Replace(readFile(t, config), `"engineVersion":"24"`, `"engineVersion":"`+sealSinkVersion+`","receiptSink":{"url":"`+sinkServer.URL+`","seals":true}`, 1)
	cfg, err := parseEngineConfig([]byte(text))
	if err != nil || cfg.receiptSink == nil || !cfg.receiptSink.seals {
		t.Fatalf("the configuration: %v", err)
	}
	var said bytes.Buffer
	first, err := startEngineOnKind(cfg, testSeed, sealOpenPgSources(t), nil, &said)
	if err != nil {
		t.Fatalf("the start: %v", err)
	}
	server := httptest.NewServer(first.service.handler())
	if code, got := post(t, server, "/acquire", `{"session":"pg-f","source":"plain","arguments":{"q":"a"}}`); code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, got)
	}
	sink.setAnswer(refuseAcknowledgments)
	code, body := post(t, server, "/seal", `{"session":"pg-f"}`)
	refusedSealUnforwarded(t, "the seal held", code, body)
	server.Close()
	first.stop(&said)
	marks := pgSealForwarding{db.open(t, nil).ofNoScope().documents()}
	if pending := markedPending(t, marks); len(pending) != 1 || pending[0] != "pg-f" {
		t.Fatalf("the seal is not marked pending: %v", pending)
	}

	sink.setAnswer(nil)
	before, _ := sink.snapshot()
	again, err := startEngineOnKind(cfg, testSeed, sealOpenPgSources(t), nil, &said)
	if err != nil {
		t.Fatalf("the start: %v\n%s", err, said.String())
	}
	defer again.stop(&said)
	data, err := db.open(t, nil).registry().readLog(0)
	if err != nil {
		t.Fatal(err)
	}
	seals, n := sealsSince(t, sink, len(before))
	if n != 1 || len(seals) != 1 || seals[0] != registrySealDigest(t, string(data), "pg-f") {
		t.Fatalf("the start sent %d deliveries, seals %v; want the seal alone", n, seals)
	}
	if pending := markedPending(t, marks); len(pending) != 0 {
		t.Fatalf("the marker outlived the acknowledgment: %v", pending)
	}
}
