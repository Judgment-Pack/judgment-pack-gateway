package main

// Delivery version "3" (ADR-0059 section 9; sink_delivery_v3.go): each
// kind's envelope and digest, today's bytes for a sink without the member, a
// sink of "1" given "3", /act acknowledged before its answer, an /act not
// acknowledged answered once acknowledged without its write repeated, a seal
// refused while an action receipt is held, and the start delivering action
// receipts before it seals.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// v3Forwarder is the forwarder a configuration with deliveryVersion "3"
// makes, with short deadlines.
func v3Forwarder(t *testing.T, url, more string) *receiptForwarder {
	t.Helper()
	spec, err := parseSinkMember(t, `{"url":"`+url+`","deliveryVersion":"3"`+more+`}`, sinkDeliveryV3Version)
	if err != nil {
		t.Fatal(err)
	}
	f := newReceiptForwarder(spec)
	f.attemptTimeout = 300 * time.Millisecond
	f.backoff = []time.Duration{time.Millisecond, time.Millisecond}
	return f
}

// v3Delivery is a "3" delivery as a sink that reads "3" reads it.
type v3Delivery struct {
	DeliveryVersion string         `json:"deliveryVersion"`
	Kind            string         `json:"kind"`
	Digest          string         `json:"digest"`
	Receipt         map[string]any `json:"receipt"`
	ActionReceipt   map[string]any `json:"actionReceipt"`
	Seal            map[string]any `json:"seal"`
}

func readV3(t *testing.T, body []byte) v3Delivery {
	t.Helper()
	var d v3Delivery
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("a delivery that is not JSON: %v", err)
	}
	return d
}

// ackV3 answers as a sink that reads "3": the acknowledgment of the
// delivery's digest, or a 503 for a kind refuse names.
func ackV3(t *testing.T, sink *standInSink, refuse func(kind string) bool) func(int, string, http.ResponseWriter, *http.Request) {
	return func(n int, _ string, w http.ResponseWriter, _ *http.Request) {
		got, _ := sink.snapshot()
		d := readV3(t, got[n])
		if refuse != nil && refuse(d.Kind) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"acknowledged":"`+d.Digest+`"}`)
	}
}

// v3KindsSince is the kind of each delivery after the first n.
func v3KindsSince(t *testing.T, sink *standInSink, n int) []string {
	t.Helper()
	got, _ := sink.snapshot()
	var kinds []string
	for _, each := range got[n:] {
		kinds = append(kinds, readV3(t, each).Kind)
	}
	return kinds
}

// lineOf is the canonical line of a record as answered.
func lineOf(t *testing.T, record any) []byte {
	t.Helper()
	text, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	v, err := parseJSON(text)
	if err != nil {
		t.Fatal(err)
	}
	return canon(v)
}

func wantV3Digest(kind string, line []byte) string {
	sum := sha256.Sum256(append([]byte("judgment-pack-gateway/sink-delivery/3:"+kind+"\n"), line...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func v3Object(t *testing.T, text string) *vObject {
	t.Helper()
	v, err := parseJSON([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return v.(*vObject)
}

func TestDeliveryVersion3EnvelopeAndDigestOfEachKind(t *testing.T) {
	f := v3Forwarder(t, "https://sink.example/r", `,"payload":true`)
	receipt := v3Object(t, `{"callIndex":0,"kind":"acquisition","sessionId":"s-1"}`)
	action := v3Object(t, `{"callIndex":1,"kind":"action","sessionId":"s-1"}`)
	sealRecord := v3Object(t, `{"finalCount":1,"sessionId":"s-1"}`)
	entryLine := []byte(`{"body":{"kind":"tally"},"ordinal":0}`)
	entry, err := f.heldRefusalEntry("refusal-abcdefghijklmnopqrstuvwx", entryLine)
	if err != nil {
		t.Fatal(err)
	}
	payload := v3Object(t, `{"x":1}`)
	for _, c := range []struct {
		kind    string
		held    heldReceipt
		line    []byte
		members map[string]string
	}{
		{sinkKindAcquisitionReceipt, f.held(0, receipt, "PD", payload, false), canon(receipt),
			map[string]string{"receipt": string(canon(receipt)), "payloadDigest": `"PD"`, "payload": `{"x":1}`}},
		{sinkKindAcquisitionReceipt, f.held(0, receipt, "PD", payload, true), canon(receipt),
			map[string]string{"receipt": string(canon(receipt)), "payloadDigest": `"PD"`}},
		{sinkKindActionReceipt, f.heldAction(1, action), canon(action),
			map[string]string{"actionReceipt": string(canon(action))}},
		{sinkKindSeal, f.heldSeal(sealRecord), canon(sealRecord),
			map[string]string{"seal": string(canon(sealRecord))}},
		{sinkKindRefusalEntry, entry, entryLine,
			map[string]string{"journal": `"refusal-abcdefghijklmnopqrstuvwx"`, "entry": string(entryLine)}},
	} {
		var members map[string]json.RawMessage
		if err := json.Unmarshal(c.held.body, &members); err != nil {
			t.Fatalf("%s: %v", c.kind, err)
		}
		if again, err := canonText(c.held.body); err != nil || !bytes.Equal(again, c.held.body) {
			t.Errorf("%s: the body is not canonical: %s", c.kind, c.held.body)
		}
		want := wantV3Digest(c.kind, c.line)
		if c.held.digest != want || string(members["digest"]) != `"`+want+`"` {
			t.Errorf("%s: digest %s, member %s; want %s", c.kind, c.held.digest, members["digest"], want)
		}
		// condition C4: never the digest of the older forms
		if c.held.digest == receiptDigestOf(v3Object(t, string(c.line))) {
			t.Errorf("%s: the digest is the line's own, the older form's", c.kind)
		}
		if string(members["deliveryVersion"]) != `"3"` || string(members["kind"]) != `"`+c.kind+`"` {
			t.Errorf("%s: %s %s", c.kind, members["deliveryVersion"], members["kind"])
		}
		if len(members) != 3+len(c.members) {
			t.Errorf("%s: members %v", c.kind, members)
		}
		for name, value := range c.members {
			if string(members[name]) != value {
				t.Errorf("%s: %s is %s; want %s", c.kind, name, members[name], value)
			}
		}
		for _, older := range []string{"receiptDigest", "sealDigest"} {
			if _, present := members[older]; present {
				t.Errorf("%s: carries %s", c.kind, older)
			}
		}
	}
	if f.heldAction(1, action).index != 1 || f.heldSeal(sealRecord).index != sealIndex || !f.heldSeal(sealRecord).seal {
		t.Fatal("the held items stand in the wrong place in their session")
	}
}

// A configuration without the member sends v0.39.0's bodies, byte for byte.
func TestAnOlderSinkIsSentTheBytesOfThePreviousRelease(t *testing.T) {
	receipt := v3Object(t, `{"callIndex":0,"kind":"acquisition","sessionId":"s-1"}`)
	sealRecord := v3Object(t, `{"finalCount":1,"sessionId":"s-1"}`)
	payload := v3Object(t, `{"x":1}`)
	pd := "sha256:" + strings.Repeat("a", 64)
	forwarder := func(text string) *receiptForwarder {
		spec, err := parseSinkMember(t, text, sinkDeliveryV3Version)
		if err != nil {
			t.Fatal(err)
		}
		return newReceiptForwarder(spec)
	}
	plain := forwarder(`{"url":"https://sink.example/r"}`)
	withPayload := forwarder(`{"url":"https://sink.example/r","payload":true}`)
	seals := forwarder(`{"url":"https://sink.example/r","seals":true}`)
	for _, c := range []struct {
		name string
		got  []byte
		want string
	}{
		{"an acquisition receipt", plain.held(0, receipt, pd, payload, false).body, `{"deliveryVersion":"1","payloadDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","receipt":{"callIndex":0,"kind":"acquisition","sessionId":"s-1"},"receiptDigest":"sha256:8db17f1170a3bcfe70569d0317580a02dab3b6c740c479f1f877e007b3b603f4"}`},
		{"an acquisition receipt, the payload not configured", seals.held(0, receipt, pd, payload, false).body, `{"deliveryVersion":"1","payloadDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","receipt":{"callIndex":0,"kind":"acquisition","sessionId":"s-1"},"receiptDigest":"sha256:8db17f1170a3bcfe70569d0317580a02dab3b6c740c479f1f877e007b3b603f4"}`},
		{"an acquisition receipt with its payload", withPayload.held(0, receipt, pd, payload, false).body, `{"deliveryVersion":"1","payload":{"x":1},"payloadDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","receipt":{"callIndex":0,"kind":"acquisition","sessionId":"s-1"},"receiptDigest":"sha256:8db17f1170a3bcfe70569d0317580a02dab3b6c740c479f1f877e007b3b603f4"}`},
		{"an acquisition receipt whose payload is not kept", withPayload.held(0, receipt, pd, payload, true).body, `{"deliveryVersion":"1","payloadDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","receipt":{"callIndex":0,"kind":"acquisition","sessionId":"s-1"},"receiptDigest":"sha256:8db17f1170a3bcfe70569d0317580a02dab3b6c740c479f1f877e007b3b603f4"}`},
		{"a seal", seals.heldSeal(sealRecord).body, `{"deliveryVersion":"2","seal":{"finalCount":1,"sessionId":"s-1"},"sealDigest":"sha256:975571ff00a2047d449175617ae0652a075574ae6acf66ae565ce773f304b986"}`},
	} {
		if string(c.got) != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, c.got, c.want)
		}
	}
	if plain.v3 || seals.v3 || withPayload.v3 {
		t.Fatal("a configuration without the member forwards action receipts")
	}
}

// A sink that reads "1" acknowledges nothing it is sent under "3": neither
// the receiptDigest member it looks for, which "3" does not carry, nor the
// "1" digest of the receipt names the digest the gateway sent, so the
// acquisition is refused, never acknowledged silently (condition C4).
func TestASinkOfVersion1GivenVersion3AcknowledgesNothing(t *testing.T) {
	sink, sinkServer := newStandInSink(t)
	service, server, _ := sinkService(t, sinkServer.URL, false)
	service.forwarder = v3Forwarder(t, sinkServer.URL, "")
	code, body := post(t, server, "/acquire", `{"session":"v3-a","source":"kept","arguments":{"q":"a"}}`)
	refusedUnforwarded(t, "the receiptDigest member echoed", code, body)
	sink.setAnswer(func(n int, _ string, w http.ResponseWriter, _ *http.Request) {
		got, _ := sink.snapshot()
		d := readV3(t, got[n])
		_, _ = io.WriteString(w, `{"acknowledged":"`+digestOfAnswered(t, d.Receipt)+`"}`)
	})
	code, body = post(t, server, "/acquire", `{"session":"v3-a","source":"kept","arguments":{"q":"a"}}`)
	refusedUnforwarded(t, "the 1 digest of the receipt", code, body)
	sink.setAnswer(ackV3(t, sink, nil))
	if code, body := post(t, server, "/acquire", `{"session":"v3-a","source":"kept","arguments":{"q":"b"}}`); code != http.StatusOK {
		t.Fatalf("acknowledged as 3: %d %v", code, body)
	}
}

// actV3Service is a gateway forwarding under "3", with a write platform, a
// decision record citing the session's first acquisition, and the /act body.
func actV3Service(t *testing.T, session string) (*standInSink, *gatewayService, func(path, body string) (int, map[string]any), string) {
	t.Helper()
	sink, sinkServer := newStandInSink(t)
	sink.setAnswer(ackV3(t, sink, nil))
	service, server := testService(t)
	service.forwarder = v3Forwarder(t, sinkServer.URL, "")
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
	call := func(path, body string) (int, map[string]any) { return authed(t, server, path, body, token) }
	code, first := call("/acquire", `{"session":"`+session+`","source":"screening","arguments":{"q":"example"}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, first)
	}
	signature := first["receipt"].(map[string]any)["signature"].(string)
	line := `{"kind":"evaluation","cites":[{"sessionId":"` + session + `","callIndex":0,"signature":"` + signature + `"}]}`
	if err := os.WriteFile(filepath.Join(service.decisionRecords, "evaluations.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	act := `{"session":"` + session + `","platform":"boards","tool":"wit_work_item_comment_write","arguments":{"action":"add","workItemId":42,"text":"approved"},` +
		`"decision":{"recordDigest":"sha256:` + hexOf([]byte(line)) + `","packDigest":"sha256:` + strings.Repeat("b", 64) + `"},` +
		`"cites":[{"sessionId":"` + session + `","callIndex":0,"signature":"` + signature + `"}]}`
	return sink, service, call, act
}

// /act answers only once the sink acknowledged its receipt; one not
// acknowledged is refused with the action's sentence, and the session's seal
// is refused, and appends nothing, while that receipt is held.
func TestDeliveryVersion3ActIsAcknowledgedBeforeItsAnswerAndHoldsTheSeal(t *testing.T) {
	sink, service, call, act := actV3Service(t, "act-v3")
	before, _ := sink.snapshot()
	code, answered := call("/act", act)
	if code != http.StatusOK {
		t.Fatalf("/act: %d %v", code, answered)
	}
	got, _ := sink.snapshot()
	if kinds := v3KindsSince(t, sink, len(before)); len(kinds) != 1 || kinds[0] != sinkKindActionReceipt {
		t.Fatalf("/act delivered %v; want its action receipt", kinds)
	}
	d := readV3(t, got[len(got)-1])
	if d.Receipt != nil || d.Digest != wantV3Digest(sinkKindActionReceipt, lineOf(t, answered["receipt"])) {
		t.Fatalf("the action receipt delivered is not the one answered: %+v", d)
	}

	sink.setAnswer(ackV3(t, sink, func(kind string) bool { return kind == sinkKindActionReceipt }))
	code, body := call("/act", act)
	if code != http.StatusServiceUnavailable || len(body) != 2 || body["error"] != (actionReceiptNotForwarded{}).Error() || body["code"] != receiptNotForwardedCode {
		t.Fatalf("/act not acknowledged: %d %v", code, body)
	}
	if !strings.Contains(body["error"].(string), "the action was carried out and its receipt is in the store") {
		t.Fatalf("the sentence: %v", body["error"])
	}
	code, body = call("/seal", `{"session":"act-v3"}`)
	refusedUnforwarded(t, "the seal past a held action receipt", code, body)
	if registry, _ := os.ReadFile(service.regPath); bytes.Contains(registry, []byte(`"act-v3"`)) {
		t.Fatal("a seal was appended while an action receipt of its session was held")
	}
	if pending := markedPending(t, service.sealForwarding()); len(pending) != 0 {
		t.Fatalf("a seal was marked while an action receipt was held: %v", pending)
	}
	sink.setAnswer(ackV3(t, sink, nil))
	before, _ = sink.snapshot()
	if code, body := call("/seal", `{"session":"act-v3"}`); code != http.StatusOK {
		t.Fatalf("/seal once acknowledged: %d %v", code, body)
	}
	if kinds := v3KindsSince(t, sink, len(before)); len(kinds) != 2 || kinds[0] != sinkKindActionReceipt || kinds[1] != sinkKindSeal {
		t.Fatalf("the seal delivered %v; want the action receipt, then the seal", kinds)
	}
}

// An /act under an action key whose receipt the sink did not acknowledge: the
// write ran once, a retry under the same key is refused while the receipt is
// held and never sends again, and is answered from the key's evidence once
// the receipt is acknowledged.
func TestDeliveryVersion3KeyedActIsAnsweredOnceAcknowledgedWithoutARepeatedWrite(t *testing.T) {
	root, g, c := actionKeysSetup(t)
	sink, sinkServer := newStandInSink(t)
	g.forwarder = v3Forwarder(t, sinkServer.URL, "")
	sink.setAnswer(ackV3(t, sink, func(kind string) bool { return kind == sinkKindActionReceipt }))
	key := strings.Repeat("e", 64)
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := actionKeysAct(g, c, "act-key", key); !errors.As(err, new(actionReceiptNotForwarded)) {
			t.Fatalf("attempt %d not acknowledged: %v", attempt, err)
		}
		if sent := actionKeysSent(root, key); sent != 1 {
			t.Fatalf("attempt %d: the write was sent %d times", attempt, sent)
		}
	}
	sink.setAnswer(ackV3(t, sink, nil))
	out, err := actionKeysAct(g, c, "act-key", key)
	if err != nil {
		t.Fatalf("the retry once acknowledged: %v", err)
	}
	if sent := actionKeysSent(root, key); sent != 1 {
		t.Fatalf("the write was sent %d times", sent)
	}
	got, _ := sink.snapshot()
	if d := readV3(t, got[len(got)-1]); d.Kind != sinkKindActionReceipt || d.Digest != wantV3Digest(sinkKindActionReceipt, lineOf(t, out["receipt"])) {
		t.Fatalf("the receipt acknowledged is not the one answered: %+v", d)
	}
}

// After an interruption the start delivers the session's stored action
// receipts under "3" too, and leaves the session open while one is not
// acknowledged.
func TestDeliveryVersion3StartDeliversActionReceiptsBeforeItSeals(t *testing.T) {
	service, sink, sinkURL := actionLeftOpen(t)
	start := func() string {
		again, err := newGatewayService(service.storeRoot, testSeed, "gateway:test", service.regPath, service.sources)
		if err != nil {
			t.Fatal(err)
		}
		again.forwarder = v3Forwarder(t, sinkURL, "")
		var stderr bytes.Buffer
		if err := sealOpenAtStart(again, &stderr, fixedStamp("2026-11-10T00:00:01Z")); err != nil {
			t.Fatalf("the start: %v", err)
		}
		return stderr.String()
	}
	sink.setAnswer(ackV3(t, sink, func(kind string) bool { return kind == sinkKindActionReceipt }))
	if said := start(); !strings.Contains(said, "is not sealed") || strings.Contains(said, "sealed after an interruption: ") {
		t.Fatalf("the start sealed past an action receipt not acknowledged:\n%s", said)
	}
	sink.setAnswer(ackV3(t, sink, nil))
	before, _ := sink.snapshot()
	if said := start(); strings.Count(said, "start: sealed after an interruption: ") != 1 {
		t.Fatalf("the start did not seal the session:\n%s", said)
	}
	kinds := v3KindsSince(t, sink, len(before))
	if strings.Join(kinds, " ") != "acquisition-receipt action-receipt seal" {
		t.Fatalf("the start delivered %v", kinds)
	}
}
