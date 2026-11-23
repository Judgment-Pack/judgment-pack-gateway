package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The routes under the request limits (ADR-0057, decisions 2, 3 and 5, as
// the maintainer ruled them; gateway #507). The scope identifiers and
// subjects are the synthetic ones of caller_scopes_test.go.

const (
	subjectOfNone = "caller-of-none"
	subjectOfAll  = "caller-of-all"
	subjectOfAB   = "caller-of-a-and-b"
	limitsScopeC  = "équipe-c"
)

// a caller of each scope identifier, one of the sources of none alone, one
// of A and B and not none, and the installation's caller, which reaches
// every source
var limitsTestCallers = callerScopes{entries: map[string]callerEntry{
	subjectA:      {grants: map[string]bool{callerScopeA: true}},
	subjectB:      {grants: map[string]bool{callerScopeB: true}},
	subjectOfNone: unscopedEntry,
	subjectOfAB:   {grants: map[string]bool{callerScopeA: true, callerScopeB: true}},
	subjectOfAll:  {installation: true},
}}

// The sentences of ADR-0057 decision 3, as the record writes them.
var recordLimitSentences = map[string]string{
	limitScopeRate:       "limit: the request rate of this request's scope is reached; send it again after Retry-After",
	limitScopeInFlight:   "limit: this request's scope has as many requests in flight as it is allowed; send it again after Retry-After",
	limitGatewayInFlight: "limit: the gateway has as many requests in flight that are not yet tied to a scope as it is allowed; send it again after Retry-After",
}

type limitsHarness struct {
	g      *gatewayService
	server *httptest.Server
	root   string
	issuer *testIssuer
	tokens map[string]string
}

func limitsSetup(t *testing.T, cfg *limitsConfig) *limitsHarness {
	t.Helper()
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	g, err := newGatewayService(filepath.Join(root, "store"), testSeed, "gateway:test", filepath.Join(root, "registry.jsonl"),
		map[string]sourceSpec{
			"scoped-a": {argv: []string{os.Args[0]}, env: helperEnv, scope: callerScopeA},
			"scoped-b": {argv: []string{os.Args[0]}, env: helperEnv, scope: callerScopeB},
			"scoped-c": {argv: []string{os.Args[0]}, env: helperEnv, scope: limitsScopeC},
			"plain":    {argv: []string{os.Args[0]}, env: helperEnv},
		})
	if err != nil {
		t.Fatal(err)
	}
	g.receiptVersion = receiptVersion3
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	id.callers = limitsTestCallers
	g.identity = &id
	g.limits = cfg
	if cfg != nil {
		// a clock that does not move, so no bucket refills while a test
		// runs, however slowly: every Retry-After is the refusing state's
		// whole wait
		if g.limiter, err = newRequestLimiter((&fakeLimitClock{}).clock(), cfg.beforeScope, cfg.entries(limitScopeKeys(g.sources))); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(g.handler())
	t.Cleanup(server.Close)
	return &limitsHarness{g: g, server: server, root: root, issuer: issuer, tokens: map[string]string{
		"a":    tokenFor(t, issuer, subjectA, []any{callerScopeA}),
		"b":    tokenFor(t, issuer, subjectB, []any{callerScopeB}),
		"none": tokenFor(t, issuer, subjectOfNone, nil),
		"ab":   tokenFor(t, issuer, subjectOfAB, []any{callerScopeA, callerScopeB}),
		"all":  tokenFor(t, issuer, subjectOfAll, nil),
		"bad":  "not-a-token",
	}}
}

func (h *limitsHarness) post(t *testing.T, path, body, who string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if who != "" {
		req.Header.Set("Authorization", "Bearer "+h.tokens[who])
	}
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(raw)
}

// stored is every byte under the harness's root: the store, its journal,
// its labels and the registry.
func (h *limitsHarness) stored(t *testing.T) string {
	t.Helper()
	return storedUnder(t, h.root)
}

// storedUnder is every byte under root, each file's path beside it.
func storedUnder(t *testing.T, root string) string {
	t.Helper()
	var sb strings.Builder
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		fmt.Fprintf(&sb, "%s\x00%s\x00", path, data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return sb.String()
}

// want429 is a limiter's refusal: 429, the Retry-After given, and the body
// of the fixed sentence, byte for byte, with refusedAt on /act.
func want429(t *testing.T, code int, header http.Header, body, limit string, retryAfter int, refusedAt string) {
	t.Helper()
	want := map[string]any{"error": recordLimitSentences[limit], "code": "limit_reached", "limit": limit}
	if refusedAt != "" {
		want["refusedAt"] = refusedAt
	}
	wantBody, _ := json.Marshal(want)
	if code != http.StatusTooManyRequests || header.Get("Retry-After") != fmt.Sprint(retryAfter) || body != string(wantBody) {
		t.Fatalf("answer %d, Retry-After %q, %s; want 429, %d, %s", code, header.Get("Retry-After"), body, retryAfter, wantBody)
	}
}

func wantStatus(t *testing.T, what string, code int, body string, want int) {
	t.Helper()
	if code != want {
		t.Fatalf("%s: %d %s, want %d", what, code, body, want)
	}
}

// holdBody sends a request's headers, with Expect: 100-continue, and holds
// its body: the server answers 100 Continue only when the handler first
// reads the body, so once holdBody returns the request has passed its
// token and every step before its body. The function returned sends the
// body and returns the answer's status.
func holdBody(t *testing.T, server *httptest.Server, path, token, body string) func() int {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: gateway\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nExpect: 100-continue\r\n\r\n", path, token, len(body))
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 100") {
		t.Fatalf("the held request was answered before its body: %q %v", line, err)
	}
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	return func() int {
		if _, err := io.WriteString(conn, body); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
}

func rateOf(rpm, burst int) limitEntry {
	return limitEntry{scope: limitValues{requestsPerMinute: rpm, burst: burst}}
}

// /acquire: a caller of one scope is charged before the body, one of
// several once the source's scope check holds; a 429 receipts, stores and
// admits nothing; a request whose scope is not established is charged to
// none.
func TestLimitsAcquireIsCountedAndRefusedWithNothingReceipted(t *testing.T) {
	h := limitsSetup(t, &limitsConfig{beforeScope: 64, scopes: map[string]limitEntry{callerScopeA: rateOf(60, 1)}})
	code, _, body := h.post(t, "/acquire", acquireBodyFor("s-1", "scoped-a", callerScopeA), "a")
	wantStatus(t, "A's first", code, body, http.StatusOK)
	before, started := h.stored(t), h.g.started.Load()
	code, header, body := h.post(t, "/acquire", acquireBodyFor("s-2", "scoped-a", callerScopeA), "a")
	want429(t, code, header, body, limitScopeRate, 1, "")
	// a caller of several scopes, charged to A after the body
	code, header, body = h.post(t, "/acquire", acquireBodyFor("s-3", "scoped-a", callerScopeA), "all")
	want429(t, code, header, body, limitScopeRate, 1, "")
	if h.stored(t) != before || h.g.started.Load() != started || sessionHeld(h.g, "s-2") || sessionHeld(h.g, "s-3") {
		t.Fatal("a refused acquisition stored, ran or admitted something")
	}
	// a scope the request does not establish is charged to none: the
	// source's scope check answers, as before
	code, _, body = h.post(t, "/acquire", acquireBodyFor("s-4", "scoped-a", callerScopeB), "all")
	if code != http.StatusBadRequest || !strings.Contains(body, scopeRefusal) {
		t.Fatalf("a scope not the source's: %d %s", code, body)
	}
	// B is not limited, and is answered
	code, _, body = h.post(t, "/acquire", acquireBodyFor("s-b", "scoped-b", callerScopeB), "all")
	wantStatus(t, "B", code, body, http.StatusOK)
	assertLimitNothingHeld(t, h.g.limiter)
}

// /seal: counted before the body for a caller of one scope; for one of
// several, at the scope it names or at the session it holds; the refused
// seal signs nothing and the session stays open.
func TestLimitsSealIsCountedAndRefused(t *testing.T) {
	h := limitsSetup(t, &limitsConfig{beforeScope: 64, scopes: map[string]limitEntry{callerScopeA: rateOf(60, 2)}})
	code, _, body := h.post(t, "/acquire", acquireBodyFor("s-1", "scoped-a", callerScopeA), "a")
	wantStatus(t, "acquire", code, body, http.StatusOK)
	// refused after the limit step, and counted
	code, _, body = h.post(t, "/seal", `{"session":"s-none"}`, "a")
	wantStatus(t, "a seal of no session", code, body, http.StatusBadRequest)
	before := h.stored(t)
	code, header, body := h.post(t, "/seal", `{"session":"s-1"}`, "a")
	want429(t, code, header, body, limitScopeRate, 1, "")
	code, header, body = h.post(t, "/seal", `{"session":"s-1"}`, "all")
	want429(t, code, header, body, limitScopeRate, 1, "")
	code, header, body = h.post(t, "/seal", `{"session":"s-1","scope":"`+callerScopeA+`"}`, "all")
	want429(t, code, header, body, limitScopeRate, 1, "")
	if h.stored(t) != before || !sessionHeld(h.g, "s-1") {
		t.Fatal("a refused seal sealed or stored something")
	}
	assertLimitNothingHeld(t, h.g.limiter)
}

// /act: a caller of one scope is counted at step 3a, before the body; one
// of several at step 8a, after the scope step and before the session is
// looked up; a request carrying dryRun is counted as any other (ADR-0054,
// decision 6). The 429 names refusedAt "limit" and journals nothing.
func TestLimitsActIsCountedBeforeTheSession(t *testing.T) {
	for _, tc := range []struct{ name, who, first, wantFirstAt string }{
		{"step 3a", "none", `{"session":"s-unknown","dryRun":true}`, ""},
		// refused at the session step itself: counted only where the count
		// comes before the session is read and looked up
		{"step 8a", "all", `{"platform":"warehouse"}`, "session"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := limitsSetup(t, &limitsConfig{beforeScope: 64, scopes: map[string]limitEntry{unscopedMarker: rateOf(60, 1)}})
			code, _, body := h.post(t, "/act", tc.first, tc.who)
			var first map[string]any
			_ = json.Unmarshal([]byte(body), &first)
			if code == http.StatusTooManyRequests || tc.wantFirstAt != "" && first["refusedAt"] != tc.wantFirstAt {
				t.Fatalf("the first /act: %d %s", code, body)
			}
			before := h.stored(t)
			code, header, body := h.post(t, "/act", `{"session":"s-unknown"}`, tc.who)
			want429(t, code, header, body, limitScopeRate, 1, "limit")
			if h.stored(t) != before {
				t.Fatal("a refused action journaled or stored something")
			}
			assertLimitNothingHeld(t, h.g.limiter)
		})
	}
}

// /verify from the installation's caller is charged to every scope it
// reaches, all or nothing: one scope's refusal leaves the others whole.
func TestLimitsVerifyIsChargedToEveryScopeAllOrNothing(t *testing.T) {
	h := limitsSetup(t, &limitsConfig{beforeScope: 64, scopes: map[string]limitEntry{
		callerScopeA: rateOf(60, 1), callerScopeB: rateOf(60, 1), unscopedMarker: rateOf(60, 1),
	}})
	code, _, body := h.post(t, "/acquire", acquireBodyFor("s-b", "scoped-b", callerScopeB), "b")
	wantStatus(t, "B's acquisition", code, body, http.StatusOK)
	code, header, body := h.post(t, "/verify", ``, "all")
	want429(t, code, header, body, limitScopeRate, 1, "")
	// A's and none's one request each are still there
	code, _, body = h.post(t, "/acquire", acquireBodyFor("s-a", "scoped-a", callerScopeA), "a")
	wantStatus(t, "A after the refused /verify", code, body, http.StatusOK)
	code, _, body = h.post(t, "/acquire", acquireBodyFor("s-n", "plain", ""), "none")
	wantStatus(t, "none after the refused /verify", code, body, http.StatusOK)
	assertLimitNothingHeld(t, h.g.limiter)
}

// Isolation end to end: scope A at its in-flight cap, with a request held
// inside it, refuses A's next; B's /acquire is answered while A's is held,
// which asserts order, not timing; A's held request is then answered.
func TestLimitsOneScopeAtItsLimitLeavesAnotherAnswered(t *testing.T) {
	h := limitsSetup(t, &limitsConfig{beforeScope: 64, scopes: map[string]limitEntry{callerScopeA: {scope: limitValues{inFlight: 1}}}})
	finish := holdBody(t, h.server, "/acquire", h.tokens["a"], acquireBodyFor("s-1", "scoped-a", callerScopeA))
	code, header, body := h.post(t, "/acquire", acquireBodyFor("s-2", "scoped-a", callerScopeA), "a")
	want429(t, code, header, body, limitScopeInFlight, 1, "")
	code, _, body = h.post(t, "/acquire", acquireBodyFor("s-b", "scoped-b", callerScopeB), "b")
	wantStatus(t, "B while A is held", code, body, http.StatusOK)
	if status := finish(); status != http.StatusOK {
		t.Fatalf("A's held request: %d", status)
	}
	assertLimitNothingHeld(t, h.g.limiter)
}

// The gateway-wide slot is held for the token's check alone (the
// maintainer's ruling; #594): a request of a caller of several scopes,
// held in its body after authentication, holds no slot, so with a cap of
// one a request with a bad token is answered 401, not 429, and counted.
func TestLimitsGatewayWideSlotIsHeldForTheTokenAlone(t *testing.T) {
	h := limitsSetup(t, &limitsConfig{beforeScope: 1})
	finish := holdBody(t, h.server, "/acquire", h.tokens["all"], acquireBodyFor("s-1", "plain", ""))
	code, _, body := h.post(t, "/posture", ``, "bad")
	wantStatus(t, "a bad token while a body is held", code, body, http.StatusUnauthorized)
	code, _, body = h.post(t, "/posture", ``, "none")
	if code != http.StatusOK || !strings.Contains(body, `"unauthenticatedRefusals":1`) {
		t.Fatalf("posture while a body is held: %d %s", code, body)
	}
	if status := finish(); status != http.StatusOK {
		t.Fatalf("the held request: %d", status)
	}
	assertLimitNothingHeld(t, h.g.limiter)
}

// With the gateway-wide cap full, the public key and its history answer;
// /registry and every other route are refused before any token is read,
// and each refusal is counted.
func TestLimitsExemptRoutesAnswerUnderAFullCap(t *testing.T) {
	h := limitsSetup(t, &limitsConfig{beforeScope: 1})
	held, refused := h.g.limiter.enter()
	if refused != nil {
		t.Fatal(refused)
	}
	for _, path := range []string{"/publickey", keyHistoryRoute} {
		if code, _, body := h.post(t, path, ``, ""); code == http.StatusTooManyRequests {
			t.Fatalf("%s under a full cap: %s", path, body)
		}
	}
	refusedRoutes := []struct{ path, who string }{{"/registry", ""}, {"/posture", "all"}, {"/acquire", "a"}, {"/verify", "all"}, {"/seal", "bad"}, {"/act", "none"}, {"/no-such-route", ""}}
	for _, tc := range refusedRoutes {
		code, header, body := h.post(t, tc.path, `{}`, tc.who)
		want429(t, code, header, body, limitGatewayInFlight, 1, "")
	}
	held.release()
	code, _, body := h.post(t, "/posture", ``, "all")
	if code != http.StatusOK || !strings.Contains(body, fmt.Sprintf(`"unauthenticatedRefusals":%d`, len(refusedRoutes))) {
		t.Fatalf("posture after the full cap: %d %s", code, body)
	}
	assertLimitNothingHeld(t, h.g.limiter)
}

// A client that sends its headers slowly holds no gateway-wide slot: the
// handler, and the slot, start only once the headers are read, and the
// listener cuts the headers at its read-header timeout.
func TestLimitsSlowHeadersHoldNoSlotAndAreCut(t *testing.T) {
	h := limitsSetup(t, &limitsConfig{beforeScope: 1})
	h.g.readHeaderTimeout = 200 * time.Millisecond
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := h.g.httpServer(ln.Addr())
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	slow, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	if _, err := io.WriteString(slow, "POST /posture HTTP/1.1\r\nHost: gateway\r\n"); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "http://"+ln.Addr().String()+"/posture", nil)
	req.Header.Set("Authorization", "Bearer "+h.tokens["all"])
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a request beside stalled headers: %d", resp.StatusCode)
	}
	// the stalled headers are cut well before the read timeout
	_ = slow.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = slow.Read(make([]byte, 512))
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatal("the stalled headers were not cut at the read-header timeout")
	}
}

// /posture: the line and the member are judged over the caller's own
// scopes, byte for byte the same whatever another scope's entry; the count
// of 401s is given to every caller and names no scope.
func TestLimitsPostureIsTheCallersOwnScopes(t *testing.T) {
	var reports []string
	for _, b := range []*limitEntry{nil, {scope: limitValues{inFlight: 2}}, {scope: limitValues{requestsPerMinute: 120, burst: 5, inFlight: 9}}} {
		cfg := &limitsConfig{beforeScope: 64, scopes: map[string]limitEntry{callerScopeA: {scope: limitValues{requestsPerMinute: 60, burst: 6, inFlight: 3}}}}
		if b != nil {
			cfg.scopes[callerScopeB] = *b
		}
		h := limitsSetup(t, cfg)
		code, _, body := h.post(t, "/posture", ``, "bad")
		wantStatus(t, "a bad token", code, body, http.StatusUnauthorized)
		_, _, report := h.post(t, "/posture", ``, "a")
		reports = append(reports, report)
		_, _, all := h.post(t, "/posture", ``, "all")
		if b != nil && !strings.Contains(all, callerScopeB) {
			t.Fatalf("the installation's caller does not read B: %s", all)
		}
	}
	if reports[0] != reports[1] || reports[1] != reports[2] {
		t.Fatalf("A's report changes with B's entry:\n%s\n%s\n%s", reports[0], reports[1], reports[2])
	}
	for _, want := range []string{`"name":"request-limits"`, `"state":"enforced"`, `"limits":[{"burst":6,"inFlight":3,"requestsPerMinute":60,"scope":"` + callerScopeA + `"}]`, `"unauthenticatedRefusals":1`, "counted by this instance alone"} {
		if !strings.Contains(reports[0], want) {
			t.Fatalf("A's report lacks %s: %s", want, reports[0])
		}
	}
	if strings.Contains(reports[0], callerScopeB) {
		t.Fatalf("A's report names B: %s", reports[0])
	}
}

// Without the member nothing changes: no wrapper, no count, no line, no
// member, no start line.
func TestLimitsAbsentChangesNothing(t *testing.T) {
	_, server, issuer := callerScopesService(t, limitsTestCallers)
	code, raw := postRawWith(t, server, "/posture", ``, "not-a-token")
	if code != http.StatusUnauthorized {
		t.Fatalf("a bad token: %d %s", code, raw)
	}
	_, raw = postRawWith(t, server, "/posture", ``, tokenFor(t, issuer, subjectOfAll, nil))
	for _, absent := range []string{"request-limits", `"limits"`, "unauthenticatedRefusals"} {
		if strings.Contains(string(raw), absent) {
			t.Fatalf("a report without limits holds %s: %s", absent, raw)
		}
	}
	if line := requestLimitsStartLine(nil, nil); line != "" {
		t.Fatalf("start line without limits: %q", line)
	}
	if l, err := limiterFor(nil, nil); l != nil || err != nil {
		t.Fatal("a limiter made without limits")
	}
}

// The member's form and every load-time refusal (decision 1).
func TestLimitsMemberIsHeldToItsForm(t *testing.T) {
	scopes := map[string]bool{"east-ledger": true, unscopedMarker: true}
	parse := func(text string, identity bool) (*limitsConfig, error) {
		v, err := parseJSON([]byte(text))
		if err != nil {
			return nil, err
		}
		return parseLimitsConfig(v, scopes, identity)
	}
	good, err := parse(`{"default":{"requestsPerMinute":600,"burst":60,"inFlight":16,"perCaller":{"requestsPerMinute":120,"burst":20,"inFlight":4}},"scopes":{"east-ledger":{"inFlight":32},"unscoped":{"requestsPerMinute":60,"burst":10}}}`, true)
	if err != nil {
		t.Fatal(err)
	}
	if good.beforeScope != defaultBeforeScope || good.scopes["east-ledger"].perCaller != nil || good.scopes["east-ledger"].scope.requestsPerMinute != 0 {
		t.Fatalf("parsed: %+v", good)
	}
	if line := requestLimitsStartLine(good, map[string]sourceSpec{"x": {scope: "east-ledger"}, "y": {}, "z": {scope: "west-ledger"}}); line != "request limits: 3 of 3 scopes are limited, counted by this instance alone" {
		t.Fatalf("start line: %q", line)
	}
	for _, tc := range []struct {
		name, text string
		identity   bool
		want       string
	}{
		{"empty", `{}`, true, "limits is an object of beforeScope"},
		{"another member", `{"beforeScope":{"inFlight":4},"global":{}}`, true, "limits is an object of beforeScope"},
		{"not an object", `[]`, true, "limits is an object of beforeScope"},
		{"beforeScope zero", `{"beforeScope":{"inFlight":0}}`, true, "limits.beforeScope"},
		{"beforeScope too high", `{"beforeScope":{"inFlight":65537}}`, true, "limits.beforeScope"},
		{"beforeScope another member", `{"beforeScope":{"inFlight":4,"burst":1}}`, true, "limits.beforeScope"},
		{"an empty entry", `{"default":{}}`, true, "an entry is an object"},
		{"an entry's other member", `{"default":{"inFlight":1,"rate":1}}`, true, "an entry is an object"},
		{"an empty perCaller", `{"default":{"perCaller":{}}}`, true, "an entry is an object"},
		{"perCaller in perCaller", `{"default":{"perCaller":{"inFlight":1,"perCaller":{"inFlight":1}}}}`, true, "an entry is an object"},
		{"rate out of range", `{"default":{"requestsPerMinute":600001,"burst":1}}`, true, "requestsPerMinute is an integer from 1 to 600000"},
		{"rate zero", `{"default":{"requestsPerMinute":0,"burst":1}}`, true, "requestsPerMinute is an integer from 1 to 600000"},
		{"burst out of range", `{"default":{"requestsPerMinute":60,"burst":10001}}`, true, "burst is an integer from 1 to 10000"},
		{"inFlight out of range", `{"default":{"inFlight":4097}}`, true, "inFlight is an integer from 1 to 4096"},
		{"a string", `{"default":{"inFlight":"4"}}`, true, "inFlight is an integer from 1 to 4096"},
		{"rate without burst", `{"default":{"requestsPerMinute":60}}`, true, "requestsPerMinute and burst are given together"},
		{"burst without rate", `{"default":{"burst":6}}`, true, "requestsPerMinute and burst are given together"},
		{"an unknown scope", `{"scopes":{"east-ledgr":{"inFlight":1}}}`, true, "a key is a scope identifier some platform is fixed to"},
		{"perCaller without identity", `{"default":{"perCaller":{"inFlight":1}}}`, false, "perCaller counts each caller"},
		{"perCaller above its scope", `{"scopes":{"east-ledger":{"inFlight":2,"perCaller":{"inFlight":3}}}}`, true, "a perCaller value is above its scope's value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parse(tc.text, tc.identity); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := parse(`{"default":{"inFlight":1.5}}`, true); err == nil {
		t.Fatal("a fraction was read")
	}
	if _, err := parseLimitsConfig(mustParseJSON(t, `{"scopes":{"unscoped":{"inFlight":1}}}`), map[string]bool{"east-ledger": true}, true); err == nil {
		t.Fatal(`"unscoped" taken where no platform is of none`)
	}
	// the version gates the member, by name; without it, nothing is read
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	config := func(version, limits string) string {
		text := engineJSON(t, catalog, limits, platformJSON(t, "warehouse", ref, "engine-warehouse", ""))
		return strings.Replace(text, `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
	}
	if _, err := parseEngineConfig([]byte(config(actScopeVersion, `,"limits":{"beforeScope":{"inFlight":4}}`))); err == nil || err.Error() != "engine configuration: limits is a version-44 member; engineVersion 43 has no limits" {
		t.Fatalf("below the version: %v", err)
	}
	cfg, err := parseEngineConfig([]byte(config(requestLimitsVersion, `,"limits":{"scopes":{"unscoped":{"inFlight":4}}}`)))
	if err != nil || cfg.limits == nil || cfg.limits.scopes[unscopedMarker].scope.inFlight != 4 {
		t.Fatalf("at the version: %+v %v", cfg.limits, err)
	}
	cfg, err = parseEngineConfig([]byte(config(requestLimitsVersion, ``)))
	if err != nil || cfg.limits != nil || engineServeOptions(cfg, nil, nil).limits != nil {
		t.Fatalf("without the member: %+v %v", cfg.limits, err)
	}
}

func mustParseJSON(t *testing.T, text string) value {
	t.Helper()
	v, err := parseJSON([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A /seal whose scope is not established -- from a caller of several scopes
// naming none, of a session this process does not hold, or naming a scope
// its caller does not reach -- is charged to no scope, and still looks for
// the session in the registry and the store before it is answered, since
// one another process or instance sealed or holds is answered so (#595).
// It takes a gateway-wide slot again once its body is read and holds it
// until its answer is written: with the cap full it is refused, and the
// refusal is not counted as unauthenticated; with a slot free it is
// answered as before, the slot held through the lookup.
func TestLimitsSealNotEstablishedHoldsAGatewayWideSlot(t *testing.T) {
	for _, tc := range []struct{ name, who, body string }{
		{"naming no scope", "all", `{"session":"s-elsewhere"}`},
		{"naming a scope not reached", "ab", `{"session":"s-elsewhere","scope":"` + limitsScopeC + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := limitsSetup(t, &limitsConfig{beforeScope: 1, scopes: map[string]limitEntry{callerScopeA: rateOf(60, 1)}})
			finish := holdBody(t, h.server, "/seal", h.tokens[tc.who], tc.body)
			held, refused := h.g.limiter.enter()
			if refused != nil {
				t.Fatal("the held request kept its gateway-wide slot past its token")
			}
			unauthenticated := h.g.limiter.unauthenticatedRefusals()
			if status := finish(); status != http.StatusTooManyRequests {
				t.Fatalf("a seal not established under a full cap: %d, want 429", status)
			}
			held.release()
			if n := h.g.limiter.unauthenticatedRefusals(); n != unauthenticated {
				t.Fatalf("the refusal of an authenticated request was counted as unauthenticated: %d -> %d", unauthenticated, n)
			}
			during := int64(-1)
			saved := sealDeliveredHook
			t.Cleanup(func() { sealDeliveredHook = saved })
			sealDeliveredHook = func(string) { during = h.g.limiter.beforeHeld.Load() }
			code, _, body := h.post(t, "/seal", tc.body, tc.who)
			sealDeliveredHook = saved
			if code != http.StatusBadRequest || !strings.Contains(body, "no such session") || during != 1 {
				t.Fatalf("with a slot free: %d %s, slots held during the lookup %d, want 400, no such session, 1", code, body, during)
			}
			assertLimitNothingHeld(t, h.g.limiter)
		})
	}
}

// limitsActBody is an /act request of the actScopeSetup harness; scope is
// raw JSON or "", extra raw members each led by a comma.
func limitsActBody(h *actScopeHarness, session, platform, scope, key, decision, cites, extra string) string {
	b := `{"session":"` + session + `","platform":"` + platform + `","tool":"query","arguments":{"ticket":"T-1"},"decision":` + decision + `,"cites":` + cites + `,"actionKey":"` + key + `"`
	if scope != "" {
		b += `,"scope":` + scope
	}
	return b + extra + "}"
}

// limitsOn gives the harness's gateway the limits and a limiter whose clock
// does not move, and a server of its handler under them.
func limitsOn(t *testing.T, g *gatewayService, cfg *limitsConfig) *httptest.Server {
	t.Helper()
	g.limits = cfg
	var err error
	if g.limiter, err = newRequestLimiter((&fakeLimitClock{}).clock(), cfg.beforeScope, cfg.entries(limitScopeKeys(g.sources))); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(g.handler())
	t.Cleanup(server.Close)
	return server
}

// Turning the limits on never changes who may write (#595): step 8a charges
// the scope the write touches -- "unscoped" for a request naming none -- and
// refuses nothing the ladder would admit.
func TestLimitsActChargeRefusesNothingTheLadderAdmits(t *testing.T) {
	h := limitsSetup(t, &limitsConfig{beforeScope: 64, scopes: map[string]limitEntry{unscopedMarker: rateOf(60, 1)}})
	who, err := engineCaller(h.g.identity, nil, "Bearer "+h.tokens["ab"], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	step := func() error {
		pass, refused := h.g.limiter.enter()
		if refused != nil {
			t.Fatal(refused)
		}
		defer pass.release()
		r := httptest.NewRequest(http.MethodPost, "/act", nil)
		r = r.WithContext(context.WithValue(r.Context(), limitPassKey{}, pass))
		return h.g.actScopeCharge(r)(requestedScope{}, who)
	}
	if err := step(); err != nil {
		t.Fatalf("step 8a of a write naming no scope: %v, want it charged to unscoped", err)
	}
	var refused *limitRefusal
	if err := step(); !errors.As(err, &refused) || refused.limit != limitScopeRate {
		t.Fatalf("the second: %v, want unscoped's rate refusal", err)
	}
	assertLimitNothingHeld(t, h.g.limiter)
}

// The same /act, limits on or off, is admitted or refused alike: a caller
// of A and B that does not reach none, writing to the platform of none
// with no scope named, with and without a write fixed to a scope
// identifier; and a caller of B and none, whose dry-run there is admitted.
func TestLimitsOnOrOffActAnswersAlike(t *testing.T) {
	for _, scopedWrite := range []bool{false, true} {
		t.Run(fmt.Sprintf("scoped write %v", scopedWrite), func(t *testing.T) {
			h := actScopeSetup(t)
			h.g.dryRunApprovals = true
			if !scopedWrite {
				delete(h.g.sources, "tickets-b/write")
				delete(h.g.sources, "tickets-b/live")
			}
			h.g.identity.callers.entries[subjectOfAB] = callerEntry{grants: map[string]bool{callerScopeA: true, callerScopeB: true}}
			ab := tokenFor(t, h.issuer, subjectOfAB, []any{callerScopeA, callerScopeB})
			off := httptest.NewServer(h.g.handler())
			t.Cleanup(off.Close)
			on := limitsOn(t, h.g, &limitsConfig{beforeScope: 64, scopes: map[string]limitEntry{
				unscopedMarker: rateOf(60, 10), callerScopeA: rateOf(60, 10), callerScopeB: rateOf(60, 10),
			}})
			for _, c := range []struct{ name, body, token string }{
				{"A and B, a write", limitsActBody(h, "w-ab", "tickets", "", strings.Repeat("c", 64), h.decisionU, h.cite("u-read", h.unscopedSig), ""), ab},
				{"A and B, a dry-run", limitsActBody(h, "d-ab", "tickets", "", strings.Repeat("d", 64), h.decisionU, h.cite("u-read", h.unscopedSig), `,"dryRun":true`), ab},
				{"B and none, a dry-run", limitsActBody(h, "d-both", "tickets", "", strings.Repeat("d", 64), h.decisionU, h.cite("u-read", h.unscopedSig), `,"dryRun":true`), h.tokenBoth},
			} {
				codeOff, outOff := authed(t, off, "/act", c.body, c.token)
				codeOn, outOn := authed(t, on, "/act", c.body, c.token)
				if codeOff != codeOn || outOff["refusedAt"] != outOn["refusedAt"] || outOff["error"] != outOn["error"] {
					t.Fatalf("%s: off %d %v, on %d %v", c.name, codeOff, outOff, codeOn, outOn)
				}
				if strings.HasPrefix(c.name, "A and B") == (codeOn == http.StatusOK) {
					t.Fatalf("%s: %d %v", c.name, codeOn, outOn)
				}
			}
			assertLimitNothingHeld(t, h.g.limiter)
		})
	}
}
