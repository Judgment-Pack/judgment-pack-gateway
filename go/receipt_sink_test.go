package main

// The receipt sink (engineVersion 35; ADR-0049; SPEC.md §6a), against an
// in-process stand-in sink: delivery before the answer and in order within
// a session, a receipt held and delivered again after a failed
// acknowledgment, each way the sink can fail refused with the one sentence,
// the url's rule and the version gate at load, and the payload carried only
// where the configuration asks for it.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// standInSink keeps each delivery it is sent by its receipt digest, once,
// and answers by answer, the acknowledgment where answer is nil.
type standInSink struct {
	mu     sync.Mutex
	got    [][]byte          // every request body, in arrival order
	kept   map[string][]byte // by receipt digest, the first body
	order  []string          // digests, in the order first kept
	answer func(n int, digest string, w http.ResponseWriter, r *http.Request)
}

func (s *standInSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var request struct {
		ReceiptDigest string `json:"receiptDigest"`
	}
	_ = json.Unmarshal(body, &request)
	digest := request.ReceiptDigest
	s.mu.Lock()
	n := len(s.got)
	s.got = append(s.got, body)
	if _, seen := s.kept[digest]; !seen {
		s.kept[digest] = body
		s.order = append(s.order, digest)
	}
	answer := s.answer
	s.mu.Unlock()
	if answer != nil {
		answer(n, digest, w, r)
		return
	}
	_, _ = io.WriteString(w, `{"acknowledged":"`+digest+`"}`)
}

func (s *standInSink) setAnswer(answer func(n int, digest string, w http.ResponseWriter, r *http.Request)) {
	s.mu.Lock()
	s.answer = answer
	s.mu.Unlock()
}

func (s *standInSink) snapshot() (got [][]byte, order []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.got...), append([]string(nil), s.order...)
}

// sinkService is a gateway forwarding to sinkURL, with a source that keeps
// its payload and one that keeps none, each answering its arguments, and
// the store's root.
func sinkService(t *testing.T, sinkURL string, payload bool) (*gatewayService, *httptest.Server, string) {
	t.Helper()
	t.Setenv(envSourceHelper, "1")
	t.Setenv(envSourceEchoStdin, "1")
	root := t.TempDir()
	service, err := newGatewayService(
		filepath.Join(root, "store"), testSeed, "gateway:test",
		filepath.Join(root, "registry.jsonl"),
		map[string]sourceSpec{
			"kept":   {argv: []string{os.Args[0]}, env: helperEnv},
			"unkept": {argv: []string{os.Args[0]}, env: helperEnv, notRetained: true},
		})
	if err != nil {
		t.Fatal(err)
	}
	service.forwarder = newReceiptForwarder(&receiptSinkSpec{url: sinkURL, payload: payload})
	service.forwarder.attemptTimeout = 300 * time.Millisecond
	service.forwarder.backoff = []time.Duration{time.Millisecond, time.Millisecond}
	server := httptest.NewServer(service.handler())
	t.Cleanup(server.Close)
	return service, server, root
}

func newStandInSink(t *testing.T) (*standInSink, *httptest.Server) {
	t.Helper()
	sink := &standInSink{kept: map[string][]byte{}}
	server := httptest.NewServer(sink)
	t.Cleanup(server.Close)
	return sink, server
}

// deliveryOf is a delivery request as the sink read it.
type deliveryOf struct {
	DeliveryVersion string          `json:"deliveryVersion"`
	Payload         json.RawMessage `json:"payload"`
	PayloadDigest   string          `json:"payloadDigest"`
	Receipt         map[string]any  `json:"receipt"`
	ReceiptDigest   string          `json:"receiptDigest"`
}

func readDelivery(t *testing.T, body []byte) (deliveryOf, map[string]json.RawMessage) {
	t.Helper()
	var d deliveryOf
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("a delivery that is not JSON: %v", err)
	}
	_ = json.Unmarshal(body, &members)
	return d, members
}

// digestOfAnswered is the digest of a receipt as /acquire answered it: the
// SHA-256 of its canonical bytes.
func digestOfAnswered(t *testing.T, receipt any) string {
	t.Helper()
	text, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	v, err := parseJSON(text)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canon(v))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func receiptsHeld(t *testing.T, root, session string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "store", "receipts", session))
	if err != nil {
		return 0
	}
	return len(entries)
}

// refusedUnforwarded holds an answer to the fixed refusal: 503, the
// sentence and the code, and nothing of a receipt or a result.
func refusedUnforwarded(t *testing.T, what string, code int, body map[string]any) {
	t.Helper()
	if code != http.StatusServiceUnavailable || len(body) != 2 ||
		body["error"] != (receiptNotForwarded{}).Error() || body["code"] != receiptNotForwardedCode {
		t.Fatalf("%s: not the fixed refusal: %d %v", what, code, body)
	}
}

// Each receipt reaches the sink, and is acknowledged, before /acquire
// answers: while the sink holds the delivery, no answer is written. The
// sink is sent the receipt as answered, its digest, and the payload's,
// with no payload; a session's receipts arrive in the order of their
// indexes.
func TestAReceiptIsAcknowledgedByTheSinkBeforeTheAnswer(t *testing.T) {
	sink, sinkServer := newStandInSink(t)
	arrived, release := make(chan struct{}), make(chan struct{})
	var released sync.Once
	let := func() { released.Do(func() { close(release) }) }
	// before the sink's server closes, which waits for its handlers
	t.Cleanup(let)
	sink.setAnswer(func(n int, digest string, w http.ResponseWriter, r *http.Request) {
		if n == 0 {
			close(arrived)
			<-release
		}
		_, _ = io.WriteString(w, `{"acknowledged":"`+digest+`"}`)
	})
	service, server, _ := sinkService(t, sinkServer.URL, false)
	// one send outlasts the hold below, so the answer waits on this send
	service.forwarder.attemptTimeout = 10 * time.Second

	type answer struct {
		code int
		body map[string]any
	}
	done := make(chan answer, 1)
	go func() {
		code, body := post(t, server, "/acquire", `{"session":"fw-1","source":"kept","arguments":{"q":0}}`)
		done <- answer{code, body}
	}()
	select {
	case <-arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("the receipt never reached the sink")
	}
	select {
	case a := <-done:
		t.Fatalf("/acquire answered while the sink held the delivery: %d %v", a.code, a.body)
	case <-time.After(300 * time.Millisecond):
	}
	let()
	first := <-done
	if first.code != http.StatusOK {
		t.Fatalf("the acquisition: %d %v", first.code, first.body)
	}
	answered := []map[string]any{first.body}
	for i := 1; i < 3; i++ {
		code, body := post(t, server, "/acquire", `{"session":"fw-1","source":"kept","arguments":{"q":`+string(rune('0'+i))+`}}`)
		if code != http.StatusOK {
			t.Fatalf("acquisition %d: %d %v", i, code, body)
		}
		answered = append(answered, body)
	}
	got, order := sink.snapshot()
	if len(got) != 3 || len(order) != 3 {
		t.Fatalf("the sink was sent %d deliveries, %d receipts; want 3 of 3", len(got), len(order))
	}
	for i, body := range got {
		d, members := readDelivery(t, body)
		receipt := answered[i]["receipt"].(map[string]any)
		if d.DeliveryVersion != "1" || d.ReceiptDigest != digestOfAnswered(t, receipt) || order[i] != d.ReceiptDigest {
			t.Fatalf("delivery %d does not name the answered receipt: %s", i, body)
		}
		if int(d.Receipt["callIndex"].(float64)) != i || d.Receipt["signature"] != receipt["signature"] {
			t.Fatalf("delivery %d is not receipt %d as answered: %v", i, i, d.Receipt)
		}
		if d.PayloadDigest != receipt["resultDigest"] {
			t.Fatalf("delivery %d's payload digest is not the receipt's: %q", i, d.PayloadDigest)
		}
		if _, present := members["payload"]; present {
			t.Fatalf("delivery %d carries the payload, which the configuration did not ask for", i)
		}
	}
}

// Several acquisitions of one session in flight at once are delivered in
// the order of their indexes, each once.
func TestASessionsReceiptsReachTheSinkInOrder(t *testing.T) {
	sink, sinkServer := newStandInSink(t)
	_, server, _ := sinkService(t, sinkServer.URL, false)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if code, body := post(t, server, "/acquire", `{"session":"fw-order","source":"kept","arguments":{"q":`+string(rune('0'+i))+`}}`); code != http.StatusOK {
				t.Errorf("acquisition %d: %d %v", i, code, body)
			}
		}(i)
	}
	wg.Wait()
	got, order := sink.snapshot()
	if len(got) != 4 || len(order) != 4 {
		t.Fatalf("the sink was sent %d deliveries, %d receipts; want 4 of 4", len(got), len(order))
	}
	for i, body := range got {
		d, _ := readDelivery(t, body)
		if int(d.Receipt["callIndex"].(float64)) != i {
			t.Fatalf("delivery %d is of receipt %v", i, d.Receipt["callIndex"])
		}
	}
}

// A receipt the sink took but did not acknowledge is held and sent again,
// the same bytes under the same digest, which the sink keeps once. While it
// is not acknowledged the session's next acquisition is refused before its
// source runs, mints nothing, and the session is not sealed; once the sink
// acknowledges it, the next acquisition delivers it first, then its own,
// and the seal counts both.
func TestAnUnacknowledgedReceiptIsHeldAndDeliveredAgain(t *testing.T) {
	sink, sinkServer := newStandInSink(t)
	sink.setAnswer(func(n int, digest string, w http.ResponseWriter, r *http.Request) {
		// kept, and the acknowledgment lost
		_, _ = io.WriteString(w, `{"acknowledged":"sha256:`+strings.Repeat("0", 64)+`"}`)
	})
	service, server, root := sinkService(t, sinkServer.URL, false)

	code, body := post(t, server, "/acquire", `{"session":"fw-2","source":"kept","arguments":{"q":"a"}}`)
	refusedUnforwarded(t, "a lost acknowledgment", code, body)
	if receiptsHeld(t, root, "fw-2") != 1 {
		t.Fatalf("the receipt minted is not held in the store")
	}
	// the sink still answers no acknowledgment: nothing else proceeds
	code, body = post(t, server, "/acquire", `{"session":"fw-2","source":"kept","arguments":{"q":"b"}}`)
	refusedUnforwarded(t, "the next acquisition", code, body)
	if n := receiptsHeld(t, root, "fw-2"); n != 1 {
		t.Fatalf("the next acquisition minted while a receipt was held: %d receipts", n)
	}
	code, body = post(t, server, "/seal", `{"session":"fw-2"}`)
	refusedUnforwarded(t, "the seal", code, body)
	// the seal holds the session's queue under its own hold too, apart from
	// the delivery before it: a receipt minted since that delivery, and not
	// acknowledged, refuses it all the same
	forwarder := service.forwarder
	service.forwarder = nil
	code, body = post(t, server, "/seal", `{"session":"fw-2"}`)
	service.forwarder = forwarder
	refusedUnforwarded(t, "the seal with no delivery before it", code, body)

	sink.setAnswer(nil)
	code, body = post(t, server, "/acquire", `{"session":"fw-2","source":"kept","arguments":{"q":"c"}}`)
	if code != http.StatusOK || int(body["receipt"].(map[string]any)["callIndex"].(float64)) != 1 {
		t.Fatalf("the acquisition once the sink acknowledges: %d %v", code, body)
	}
	got, order := sink.snapshot()
	if len(order) != 2 {
		t.Fatalf("the sink kept %d receipts; want 2", len(order))
	}
	first := sink.kept[order[0]]
	sent := 0
	for _, each := range got {
		if d, _ := readDelivery(t, each); d.ReceiptDigest == order[0] {
			sent++
			if string(each) != string(first) {
				t.Fatalf("receipt 0 was sent again in other bytes")
			}
		}
	}
	// three sends for each of the two refused acquisitions and the refused
	// seal, and one before the third acquisition's source ran
	if sent != 3*receiptSinkAttempts+1 {
		t.Fatalf("receipt 0 was sent %d times; want %d", sent, 3*receiptSinkAttempts+1)
	}
	if d, _ := readDelivery(t, got[len(got)-1]); d.ReceiptDigest != order[1] || d.ReceiptDigest != digestOfAnswered(t, body["receipt"]) {
		t.Fatalf("the last delivery is not of the answered receipt")
	}
	code, sealed := post(t, server, "/seal", `{"session":"fw-2"}`)
	if code != http.StatusOK || sealed["finalCount"] != float64(2) {
		t.Fatalf("the seal once every receipt is acknowledged: %d %v", code, sealed)
	}
}

// A sink that is unreachable, past its deadline, or answering anything but
// the acknowledgment of the receipt -- another digest, another status, a
// body past its bound, a redirect -- refuses the acquisition with the one
// sentence, and nothing of the receipt or the result is answered.
func TestASinkThatDoesNotAcknowledgeRefusesWithTheFixedSentence(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	unreachable := closed.URL
	closed.Close()
	answers := map[string]func(n int, digest string, w http.ResponseWriter, r *http.Request){
		"past its deadline": func(n int, digest string, w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		},
		"another digest": func(n int, digest string, w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"acknowledged":"sha256:`+strings.Repeat("f", 64)+`"}`)
		},
		"another status": func(n int, digest string, w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"acknowledged":"`+digest+`"}`)
		},
		"a body past its bound": func(n int, digest string, w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"acknowledged":"`+digest+`"}`+strings.Repeat(" ", maxReceiptSinkAcknowledgment))
		},
		"another member beside it": func(n int, digest string, w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"acknowledged":"`+digest+`","more":1}`)
		},
		"a redirect": func(n int, digest string, w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
		},
	}
	t.Run("unreachable", func(t *testing.T) {
		_, server, root := sinkService(t, unreachable, false)
		code, body := post(t, server, "/acquire", `{"session":"fw-3","source":"kept","arguments":{"q":"a"}}`)
		refusedUnforwarded(t, "unreachable", code, body)
		if receiptsHeld(t, root, "fw-3") != 1 {
			t.Fatal("the receipt minted is not held in the store")
		}
	})
	for name, answer := range answers {
		t.Run(name, func(t *testing.T) {
			sink, sinkServer := newStandInSink(t)
			sink.setAnswer(answer)
			_, server, _ := sinkService(t, sinkServer.URL, false)
			code, body := post(t, server, "/acquire", `{"session":"fw-3","source":"kept","arguments":{"q":"a"}}`)
			refusedUnforwarded(t, name, code, body)
			if got, _ := sink.snapshot(); len(got) != receiptSinkAttempts {
				t.Fatalf("%s: the receipt was sent %d times; want %d", name, len(got), receiptSinkAttempts)
			}
		})
	}
}

// The payload is carried only where the configuration asks for it, and
// never for a source that keeps no payload.
func TestThePayloadIsCarriedOnlyWhereConfigured(t *testing.T) {
	sink, sinkServer := newStandInSink(t)
	_, server, _ := sinkService(t, sinkServer.URL, true)
	if code, body := post(t, server, "/acquire", `{"session":"fw-4","source":"kept","arguments":{"q":"carried"}}`); code != http.StatusOK {
		t.Fatalf("kept: %d %v", code, body)
	}
	if code, body := post(t, server, "/acquire", `{"session":"fw-5","source":"unkept","arguments":{"q":"not carried"}}`); code != http.StatusOK {
		t.Fatalf("unkept: %d %v", code, body)
	}
	got, _ := sink.snapshot()
	if len(got) != 2 {
		t.Fatalf("the sink was sent %d deliveries; want 2", len(got))
	}
	d, members := readDelivery(t, got[0])
	if _, present := members["payload"]; !present || !strings.Contains(string(d.Payload), "carried") {
		t.Fatalf("the payload the configuration asks for is not carried: %s", got[0])
	}
	payload, _ := parseJSON(d.Payload)
	if "sha256:"+digestOfBytes(canon(payload)) != d.PayloadDigest {
		t.Fatalf("the payload carried is not the one its digest names")
	}
	if _, members := readDelivery(t, got[1]); members["payload"] != nil {
		t.Fatalf("a payload the gateway does not keep was carried: %s", got[1])
	}
}

// receiptSink is a version-35 member: an earlier version refuses it by
// name, and it is held to its form. Its url is https, or plain http to a
// loopback address written as one; a name, even localhost, is not one, and
// the refusal repeats no value.
func TestReceiptSinkIsAVersion35MemberHeldToItsURLRule(t *testing.T) {
	if receiptSinkVersion != "35" || !versionAtLeast(engineVersion, receiptSinkVersion) || !engineVersions[receiptSinkVersion] {
		t.Fatalf("receiptSink is version 35's member, read by this engine: %q, engine %q", receiptSinkVersion, engineVersion)
	}
	catalog := t.TempDir()
	with := func(version, member string) string {
		return atVersion(t, version, catalog, `,"receiptSink":`+member, ``)
	}
	cfg, err := parseEngineConfig([]byte(with("35", `{"url":"https://sink.example/receipts"}`)))
	if err != nil || cfg.receiptSink == nil || cfg.receiptSink.url != "https://sink.example/receipts" || cfg.receiptSink.payload {
		t.Fatalf("an https sink: %v %+v", err, cfg.receiptSink)
	}
	if opts := engineServeOptions(cfg, nil, nil); opts.receiptSink != cfg.receiptSink {
		t.Fatal("serve is not given the configuration's sink")
	}
	if cfg, err := parseEngineConfig([]byte(atVersion(t, "35", catalog, ``, ``))); err != nil || cfg.receiptSink != nil {
		t.Fatalf("version 35 without the member: %v %+v", err, cfg.receiptSink)
	}
	accepted := []string{
		`{"url":"http://127.0.0.1:9900/receipts","payload":true}`,
		`{"url":"http://127.8.0.1/receipts","payload":false}`,
		`{"url":"http://[::1]:9900/"}`,
	}
	for _, member := range accepted {
		if _, err := parseEngineConfig([]byte(with("35", member))); err != nil {
			t.Fatalf("%s: %v", member, err)
		}
	}
	refused := []struct{ version, member, want string }{
		{"34", `{"url":"https://sink.example/receipts"}`, "engine configuration: receiptSink is a version-35 member; engineVersion 34 has no receiptSink"},
		{"35", `{"url":"http://sink.example/receipts"}`, "plain http to a host that is not a loopback address"},
		{"35", `{"url":"http://localhost:9900/receipts"}`, "plain http to a host that is not a loopback address"},
		{"35", `{"url":"http://10.0.0.5:9900/receipts"}`, "plain http to a host that is not a loopback address"},
		{"35", `{"url":"http://0.0.0.0:9900/receipts"}`, "plain http to a host that is not a loopback address"},
		{"35", `{"url":"ftp://sink.example/receipts"}`, "url is not an absolute http or https URL"},
		{"35", `{"url":"/receipts"}`, "url is not an absolute http or https URL"},
		{"35", `{"url":"https://user@sink.example/receipts"}`, "url carries a user"},
		{"35", `{"url":"https://sink.example/receipts?to=sink.example"}`, "url carries a query or a fragment"},
		{"35", `{"url":""}`, "url is a string of 1 to 2048 bytes"},
		{"35", `{"payload":true}`, `missing member "url"`},
		{"35", `{"url":"https://sink.example/","payload":"yes"}`, "payload, when present, is true or false"},
		{"35", `{"url":"https://sink.example/","timeout":5}`, `unknown member "timeout"`},
		{"35", `"https://sink.example/"`, "receiptSink is an object"},
	}
	for _, c := range refused {
		_, err := parseEngineConfig([]byte(with(c.version, c.member)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s at %s: %v; want %q", c.member, c.version, err, c.want)
		}
		if strings.Contains(err.Error(), "sink.example") || strings.Contains(err.Error(), "10.0.0.5") {
			t.Fatalf("the refusal repeats the value it was given: %v", err)
		}
	}
}
